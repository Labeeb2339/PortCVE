using System.Reflection;
using System.Text;
using PortCVE.Analysis;
using PortCVE.Collection;
using PortCVE.Domain;
using PortCVE.Output;
using PortCVE.Snapshots;
using PortCVE.Vulnerabilities;

namespace PortCVE.Cli;

public sealed class CliApplication
{
    private readonly ISnapshotBuilder snapshotBuilder;
    private readonly LockfileService lockfileService;
    private readonly IVulnerabilityScanner vulnerabilityScanner;

    public CliApplication()
        : this(new SnapshotBuilder(), new LockfileService(), new TrivyVulnerabilityScanner())
    {
    }

    internal CliApplication(ISnapshotBuilder snapshotBuilder, LockfileService lockfileService)
        : this(snapshotBuilder, lockfileService, new TrivyVulnerabilityScanner())
    {
    }

    internal CliApplication(
        ISnapshotBuilder snapshotBuilder,
        LockfileService lockfileService,
        IVulnerabilityScanner vulnerabilityScanner)
    {
        this.snapshotBuilder = snapshotBuilder;
        this.lockfileService = lockfileService;
        this.vulnerabilityScanner = vulnerabilityScanner;
    }

    public async Task<int> RunAsync(
        CliOptions options,
        TextWriter output,
        TextWriter error,
        CancellationToken cancellationToken)
    {
        return options.Command switch
        {
            CommandKind.Help => WriteHelp(output),
            CommandKind.Version => WriteVersion(output),
            CommandKind.List or CommandKind.Inspect => await RunListAsync(options, output, error, cancellationToken),
            CommandKind.Scan => await RunScanAsync(options, output, error, cancellationToken),
            CommandKind.Lock => await RunLockAsync(options, output, error, cancellationToken),
            CommandKind.Snapshot => await RunSnapshotAsync(options, output, error, cancellationToken),
            CommandKind.Diff or CommandKind.Check => await RunDiffAsync(options, output, error, cancellationToken),
            CommandKind.Watch => await RunWatchAsync(options, output, error, cancellationToken),
            CommandKind.Doctor => await RunDoctorAsync(options, output, error, cancellationToken),
            _ => throw new CliUsageException("Unsupported command."),
        };
    }

    private async Task<int> RunScanAsync(
        CliOptions options,
        TextWriter output,
        TextWriter error,
        CancellationToken cancellationToken)
    {
        string? sbomPath = null;
        if (options.SbomPath is not null)
        {
            try
            {
                sbomPath = Path.GetFullPath(options.SbomPath);
            }
            catch (Exception exception) when (exception is ArgumentException or NotSupportedException)
            {
                error.WriteLine($"error: invalid SBOM path: {exception.Message}");
                return ExitCodes.UsageOrSchema;
            }

            if (!File.Exists(sbomPath))
            {
                error.WriteLine($"error: SBOM file not found: '{sbomPath}'.");
                return ExitCodes.UsageOrSchema;
            }
        }

        var snapshot = await snapshotBuilder.CollectAsync(
            new(IncludeFirewall: false, IncludeProfiles: false),
            cancellationToken);
        if (!SocketsAvailable(snapshot))
        {
            TextRenderer.RenderDiagnostics(snapshot.Diagnostics, error);
            return ExitCodes.RuntimeFailure;
        }

        var selected = snapshot.Listeners
            .Where(static listener => listener.Protocol == TransportProtocol.Tcp)
            .Where(listener => options.All || listener.LocalPort == options.Port)
            .OrderBy(static listener => listener.Key, StringComparer.Ordinal)
            .ToArray();
        var selector = options.All ? "all_tcp_listeners" : $"tcp:{options.Port}";
        var service = new VulnerabilityAssessmentService(vulnerabilityScanner);
        VulnerabilityReport report;
        try
        {
            report = await service.AssessAsync(
                Version,
                selector,
                selected,
                selected.Length == 0 ? null : sbomPath,
                cancellationToken);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            error.WriteLine($"error: could not read the SBOM: {exception.Message}");
            return ExitCodes.RuntimeFailure;
        }

        if (options.Json)
        {
            var jsonReport = options.IncludePrivate
                ? report
                : VulnerabilityReportRedactor.Redact(report);
            await output.WriteLineAsync(JsonOutput.Serialize(jsonReport));
        }
        else
        {
            VulnerabilityTextRenderer.Render(report, output, error);
        }

        if (selected.Length == 0)
        {
            if (!options.Json)
            {
                error.WriteLine($"error: no TCP listeners matched {selector}.");
            }

            return ExitCodes.NegativeResult;
        }

        if (!report.HasSuccessfulScan)
        {
            return ExitCodes.IncompleteEvidence;
        }

        if (options.Strict && !report.Summary.IsComplete)
        {
            return ExitCodes.IncompleteEvidence;
        }

        if (options.FailOn is not null && report.Findings.Any(finding =>
            MeetsThreshold(finding.Severity, options.FailOn.Value)))
        {
            return ExitCodes.NegativeResult;
        }

        return ExitCodes.Success;
    }

    private async Task<int> RunListAsync(
        CliOptions options,
        TextWriter output,
        TextWriter error,
        CancellationToken cancellationToken)
    {
        var snapshot = await snapshotBuilder.CollectAsync(
            new(options.IncludeFirewall, options.IncludeFirewall, ResolveAccounts: options.ResolveAccounts),
            cancellationToken);
        var listeners = ApplyFilters(snapshot.Listeners, options);
        var filteredSnapshot = snapshot with { Listeners = listeners };

        if (options.Json)
        {
            var jsonSnapshot = options.IncludePrivate ? filteredSnapshot : SnapshotRedactor.Redact(filteredSnapshot);
            await output.WriteLineAsync(JsonOutput.Serialize(jsonSnapshot));
        }
        else if (options.Command == CommandKind.Inspect)
        {
            TextRenderer.RenderDetails(listeners, options.ShowEvidence, output);
            TextRenderer.RenderDiagnostics(snapshot.Diagnostics, error);
        }
        else
        {
            TextRenderer.RenderList(listeners, output);
            TextRenderer.RenderDiagnostics(snapshot.Diagnostics, error);
        }

        if (!SocketsAvailable(snapshot))
        {
            return ExitCodes.RuntimeFailure;
        }

        if (options.Strict && !CoreEvidenceComplete(snapshot))
        {
            return ExitCodes.IncompleteEvidence;
        }

        return options.Command == CommandKind.Inspect && listeners.Count == 0
            ? ExitCodes.NegativeResult
            : ExitCodes.Success;
    }

    private async Task<int> RunLockAsync(
        CliOptions options,
        TextWriter output,
        TextWriter error,
        CancellationToken cancellationToken)
    {
        var path = options.OutputPath ?? "listeners.lock.json";
        var snapshot = await snapshotBuilder.CollectAsync(
            new(
                options.IncludeFirewall,
                options.IncludeFirewall,
                HashBinaries: true,
                ResolveAccounts: options.ResolveAccounts),
            cancellationToken);
        if (!SocketsAvailable(snapshot))
        {
            TextRenderer.RenderDiagnostics(snapshot.Diagnostics, error);
            return ExitCodes.RuntimeFailure;
        }

        if (options.Strict && !CoreEvidenceComplete(snapshot))
        {
            TextRenderer.RenderDiagnostics(snapshot.Diagnostics, error);
            return ExitCodes.IncompleteEvidence;
        }

        var lockListeners = ApplyFilters(snapshot.Listeners, options);
        if (!options.IncludeUdp && options.Protocol != TransportProtocol.Udp)
        {
            lockListeners = lockListeners.Where(static item => item.Protocol == TransportProtocol.Tcp).ToArray();
        }

        var lockSnapshot = snapshot with { Listeners = lockListeners };
        var includesUdp = options.IncludeUdp || options.Protocol == TransportProtocol.Udp;
        var selector = new LockfileSelector(options.Port, options.Protocol, options.ProcessFilter, options.ScopeFilter);
        var dockerReport = snapshot.Collectors.FirstOrDefault(static report => report.Name == "docker");
        var includesContainerEvidence = dockerReport?.Status == CollectorStatus.Complete
            || dockerReport?.Status is CollectorStatus.Partial or CollectorStatus.Failed
            || (dockerReport?.Diagnostics.Any(static diagnostic =>
                diagnostic.Code is "docker_access_denied" or "docker_timeout") ?? false)
            || lockListeners.Any(static listener => (listener.ContainerExposures?.Count ?? 0) > 0);
        var lockfile = lockfileService.Create(
            lockSnapshot,
            includesUdp,
            options.IncludeFirewall,
            selector,
            includesContainerEvidence);
        if (!lockfile.IsComplete && !options.AllowIncomplete)
        {
            error.WriteLine("error: refusing to write a baseline with incomplete owner, bind-scope, or requested host-policy evidence.");
            error.WriteLine(
                $"evidence: ownership={lockfile.Evidence.Ownership}, bind_scope={lockfile.Evidence.BindScope}, "
                + $"host_policy={lockfile.Evidence.HostPolicy}, containers={lockfile.Evidence.Containers}");
            error.WriteLine("Run elevated for stronger owner evidence, narrow the filters, or pass --allow-incomplete for a diff-only baseline.");
            return ExitCodes.IncompleteEvidence;
        }
        try
        {
            await lockfileService.WriteAsync(path, lockfile, options.Force, cancellationToken);
        }
        catch (IOException) when (!options.Force && File.Exists(Path.GetFullPath(path)))
        {
            error.WriteLine($"error: '{Path.GetFullPath(path)}' already exists; pass --force to replace it.");
            return ExitCodes.UsageOrSchema;
        }

        if (options.Json)
        {
            await output.WriteLineAsync(JsonOutput.Serialize(new
            {
                path = options.IncludePrivate ? Path.GetFullPath(path) : Path.GetFileName(path),
                listener_count = lockfile.Listeners.Count,
                schema_version = lockfile.SchemaVersion,
                evidence = lockfile.Evidence,
            }));
        }
        else
        {
            output.WriteLine($"Wrote {lockfile.Listeners.Count} normalized endpoints to {Path.GetFullPath(path)}.");
        }

        TextRenderer.RenderDiagnostics(snapshot.Diagnostics, error);
        return ExitCodes.Success;
    }

    private async Task<int> RunSnapshotAsync(
        CliOptions options,
        TextWriter output,
        TextWriter error,
        CancellationToken cancellationToken)
    {
        var snapshot = await snapshotBuilder.CollectAsync(
            new(options.IncludeFirewall, options.IncludeFirewall, ResolveAccounts: options.ResolveAccounts),
            cancellationToken);
        if (!SocketsAvailable(snapshot))
        {
            TextRenderer.RenderDiagnostics(snapshot.Diagnostics, error);
            return ExitCodes.RuntimeFailure;
        }

        var jsonSnapshot = options.IncludePrivate ? snapshot : SnapshotRedactor.Redact(snapshot);
        var json = JsonOutput.Serialize(jsonSnapshot);
        if (string.IsNullOrWhiteSpace(options.OutputPath))
        {
            await output.WriteLineAsync(json);
        }
        else
        {
            var fullPath = Path.GetFullPath(options.OutputPath);
            if (File.Exists(fullPath) && !options.Force)
            {
                error.WriteLine($"error: '{fullPath}' already exists; pass --force to replace it.");
                return ExitCodes.UsageOrSchema;
            }

            var directory = Path.GetDirectoryName(fullPath);
            if (!string.IsNullOrEmpty(directory))
            {
                Directory.CreateDirectory(directory);
            }

            await File.WriteAllTextAsync(fullPath, json + Environment.NewLine, new UTF8Encoding(false), cancellationToken);
            if (!options.Json)
            {
                output.WriteLine($"Wrote snapshot with {snapshot.Listeners.Count} endpoints to {fullPath}.");
            }
        }

        TextRenderer.RenderDiagnostics(snapshot.Diagnostics, error);
        return options.Strict && !CoreEvidenceComplete(snapshot)
            ? ExitCodes.IncompleteEvidence
            : ExitCodes.Success;
    }

    private async Task<int> RunDiffAsync(
        CliOptions options,
        TextWriter output,
        TextWriter error,
        CancellationToken cancellationToken)
    {
        ListenerLockfile baseline;
        try
        {
            baseline = await lockfileService.ReadAsync(options.InputPath!, cancellationToken);
        }
        catch (Exception exception) when (exception is IOException or System.Text.Json.JsonException or InvalidDataException)
        {
            error.WriteLine($"error: invalid lockfile: {exception.Message}");
            return ExitCodes.UsageOrSchema;
        }

        var baselineUsedFirewall = baseline.Evidence.HostPolicy != EvidenceCompleteness.NotCollected;
        var baselineUsedContainers = baseline.Evidence.Containers != EvidenceCompleteness.NotCollected;
        var baselineNeedsHashes = baseline.Listeners.Any(static item =>
            item.OwnerIdentityStrength is OwnerIdentityStrength.Sha256 or OwnerIdentityStrength.ContainerImage);
        var snapshot = await snapshotBuilder.CollectAsync(
            new(
                options.IncludeFirewall || baselineUsedFirewall,
                options.IncludeFirewall || baselineUsedFirewall,
                baselineNeedsHashes,
                options.ResolveAccounts),
            cancellationToken);
        if (!SocketsAvailable(snapshot))
        {
            TextRenderer.RenderDiagnostics(snapshot.Diagnostics, error);
            return ExitCodes.RuntimeFailure;
        }

        var currentListeners = ApplyLockSelector(snapshot.Listeners, baseline);
        var currentSnapshot = snapshot with { Listeners = currentListeners };
        var currentLockfile = lockfileService.Create(
            currentSnapshot,
            baseline.IncludesUdp,
            baselineUsedFirewall,
            baseline.Selector,
            baselineUsedContainers);
        var current = currentLockfile.Listeners;
        var changes = ListenerDiffEngine.Compare(baseline.Listeners, current)
            .Concat(ListenerDiffEngine.CompareEvidence(baseline.Evidence, currentLockfile.Evidence))
            .OrderBy(static change => change.Key, StringComparer.Ordinal)
            .ThenBy(static change => change.Kind)
            .ToArray();
        if (options.Json)
        {
            var jsonDiagnostics = options.IncludePrivate
                ? snapshot.Diagnostics
                : SnapshotRedactor.RedactDiagnostics(snapshot.Diagnostics);
            await output.WriteLineAsync(JsonOutput.Serialize(new
            {
                schema_version = 1,
                baseline = options.IncludePrivate
                    ? Path.GetFullPath(options.InputPath!)
                    : Path.GetFileName(options.InputPath!),
                changed = changes.Length > 0,
                changes,
                diagnostics = jsonDiagnostics,
            }));
        }
        else
        {
            TextRenderer.RenderChanges(changes, output);
            TextRenderer.RenderDiagnostics(snapshot.Diagnostics, error);
        }

        if (options.Command == CommandKind.Check)
        {
            if (!baseline.IsComplete || !currentLockfile.IsComplete
                || changes.Any(static change => change.Kind == ListenerChangeKind.EvidenceRegressed)
                || (options.Strict && !CoreEvidenceComplete(snapshot)))
            {
                if (!options.Json)
                {
                    output.WriteLine();
                    output.WriteLine("INCOMPLETE: the baseline or current evidence cannot support a pass/fail decision.");
                }

                return ExitCodes.IncompleteEvidence;
            }

            var securityFindings = changes.Where(IsCheckFailure).ToArray();
            if (securityFindings.Length > 0)
            {
                if (!options.Json)
                {
                    output.WriteLine();
                    output.WriteLine($"FAIL: {securityFindings.Length} security-relevant listener change(s).");
                }

                return ExitCodes.NegativeResult;
            }

            if (!options.Json)
            {
                output.WriteLine();
                output.WriteLine("PASS: no new, widened, or owner-changed listeners.");
            }
        }

        return options.Command == CommandKind.Diff
            && options.Strict
            && (!baseline.IsComplete
                || !currentLockfile.IsComplete
                || changes.Any(static change => change.Kind == ListenerChangeKind.EvidenceRegressed)
                || !CoreEvidenceComplete(snapshot))
                ? ExitCodes.IncompleteEvidence
                : ExitCodes.Success;
    }

    private async Task<int> RunWatchAsync(
        CliOptions options,
        TextWriter output,
        TextWriter error,
        CancellationToken cancellationToken)
    {
        var interval = options.Interval ?? TimeSpan.FromSeconds(1);
        var firstSnapshot = await snapshotBuilder.CollectAsync(
            new(options.IncludeFirewall, options.IncludeFirewall, ResolveAccounts: options.ResolveAccounts),
            cancellationToken);
        if (!SocketsAvailable(firstSnapshot))
        {
            TextRenderer.RenderDiagnostics(firstSnapshot.Diagnostics, error);
            return ExitCodes.RuntimeFailure;
        }

        if (options.Strict && !CoreEvidenceComplete(firstSnapshot))
        {
            TextRenderer.RenderDiagnostics(firstSnapshot.Diagnostics, error);
            return ExitCodes.IncompleteEvidence;
        }

        var firstListeners = WatchListeners(firstSnapshot.Listeners, options);
        var previous = firstListeners.Select(LockfileService.ToLockedListener).ToArray();
        var previousSnapshot = firstSnapshot;
        var sequence = 0L;
        var completedIterations = 0;
        if (options.Json)
        {
            await output.WriteLineAsync(JsonOutput.Serialize(new
            {
                schema_version = 1,
                sequence,
                observed_at = firstSnapshot.GeneratedAt,
                kind = "watch_started",
                listener_count = previous.Length,
            }, indented: false));
        }
        else
        {
            output.WriteLine($"Watching {previous.Length} endpoints every {interval.TotalSeconds:0.###}s. Press Ctrl+C to stop.");
        }

        while (options.Iterations is null || completedIterations < options.Iterations.Value)
        {
            await Task.Delay(interval, cancellationToken);
            var snapshot = await snapshotBuilder.CollectAsync(
                new(options.IncludeFirewall, options.IncludeFirewall, ResolveAccounts: options.ResolveAccounts),
                cancellationToken);
            completedIterations++;
            if (!SocketsAvailable(snapshot))
            {
                if (options.Json)
                {
                    await output.WriteLineAsync(JsonOutput.Serialize(new
                    {
                        schema_version = 1,
                        sequence = ++sequence,
                        observed_at = snapshot.GeneratedAt,
                        kind = "collector_degraded",
                        diagnostics = options.IncludePrivate
                            ? snapshot.Diagnostics
                            : SnapshotRedactor.RedactDiagnostics(snapshot.Diagnostics),
                    }, indented: false));
                }
                else
                {
                    TextRenderer.RenderDiagnostics(snapshot.Diagnostics, error);
                }

                if (options.Strict)
                {
                    return ExitCodes.IncompleteEvidence;
                }

                continue;
            }

            var currentListeners = WatchListeners(snapshot.Listeners, options);
            var current = currentListeners.Select(LockfileService.ToLockedListener).ToArray();
            var changes = ListenerDiffEngine.Compare(previous, current);
            if (CollectorEvidenceDegraded(previousSnapshot, snapshot, options.IncludeFirewall)
                || changes.Any(static change => change.Kind == ListenerChangeKind.EvidenceRegressed))
            {
                if (options.Json)
                {
                    await output.WriteLineAsync(JsonOutput.Serialize(new
                    {
                        schema_version = 1,
                        sequence = ++sequence,
                        observed_at = snapshot.GeneratedAt,
                        kind = "collector_degraded",
                        diagnostics = options.IncludePrivate
                            ? snapshot.Diagnostics
                            : SnapshotRedactor.RedactDiagnostics(snapshot.Diagnostics),
                    }, indented: false));
                }
                else
                {
                    error.WriteLine("warning: evidence degraded; the watch baseline was not advanced.");
                    TextRenderer.RenderDiagnostics(snapshot.Diagnostics, error);
                }

                if (options.Strict)
                {
                    return ExitCodes.IncompleteEvidence;
                }

                continue;
            }

            foreach (var change in changes)
            {
                if (options.Json)
                {
                    await output.WriteLineAsync(JsonOutput.Serialize(new
                    {
                        schema_version = 1,
                        sequence = ++sequence,
                        observed_at = snapshot.GeneratedAt,
                        kind = change.Kind,
                        change,
                    }, indented: false));
                }
                else
                {
                    output.WriteLine($"{snapshot.GeneratedAt:O}  {change.Kind.ToString().ToLowerInvariant()}  {change.Key}");
                    output.WriteLine($"  {change.Summary}");
                }
            }

            previous = current;
            previousSnapshot = snapshot;
        }

        return ExitCodes.Success;
    }

    private async Task<int> RunDoctorAsync(
        CliOptions options,
        TextWriter output,
        TextWriter error,
        CancellationToken cancellationToken)
    {
        var snapshot = await snapshotBuilder.CollectAsync(
            new(options.IncludeFirewall, options.IncludeFirewall, ResolveAccounts: options.ResolveAccounts),
            cancellationToken);
        if (options.Json)
        {
            var jsonCollectors = options.IncludePrivate
                ? snapshot.Collectors
                : SnapshotRedactor.RedactCollectorReports(snapshot.Collectors);
            await output.WriteLineAsync(JsonOutput.Serialize(new
            {
                schema_version = 1,
                tool = "portcve",
                version = Version,
                platform = snapshot.Platform,
                privileged = Environment.IsPrivilegedProcess,
                collectors = jsonCollectors,
                endpoint_count = snapshot.Listeners.Count,
                privacy = new
                {
                    local_only = !options.ResolveAccounts,
                    telemetry = false,
                    process_environment_read = false,
                    command_lines_collected = false,
                    external_probe_run = false,
                    account_name_resolution = options.ResolveAccounts,
                    domain_lookup_possible = options.ResolveAccounts,
                },
            }));
        }
        else
        {
            output.WriteLine($"PortCVE {Version}");
            output.WriteLine($"Platform        {snapshot.Platform}");
            output.WriteLine($"Elevated        {(Environment.IsPrivilegedProcess ? "yes" : "no")}");
            output.WriteLine($"Endpoints       {snapshot.Listeners.Count}");
            output.WriteLine();
            output.WriteLine("COLLECTORS");
            foreach (var report in snapshot.Collectors)
            {
                output.WriteLine($"  {report.Name,-20} {report.Status.ToString().ToLowerInvariant(),-11} {report.DurationMs,6} ms");
            }

            output.WriteLine();
            output.WriteLine("PRIVACY");
            if (options.ResolveAccounts)
            {
                output.WriteLine("  Account-name resolution is enabled; Windows may query trusted domains or the global catalog.");
                output.WriteLine("  No telemetry, reputation request, or external reachability probe is performed.");
            }
            else
            {
                output.WriteLine("  Local/offline; no telemetry, account lookup, reputation request, or external probe.");
            }

            output.WriteLine("  Process environment variables and command lines are not collected.");
            TextRenderer.RenderDiagnostics(snapshot.Diagnostics, error);
        }

        if (!SocketsAvailable(snapshot))
        {
            return ExitCodes.RuntimeFailure;
        }

        return options.Strict && !CoreEvidenceComplete(snapshot)
            ? ExitCodes.IncompleteEvidence
            : ExitCodes.Success;
    }

    private static IReadOnlyList<ListenerEvidence> ApplyFilters(
        IReadOnlyList<ListenerEvidence> listeners,
        CliOptions options)
    {
        IEnumerable<ListenerEvidence> query = listeners;
        if (options.Port is not null)
        {
            query = query.Where(item => item.LocalPort == options.Port);
        }

        if (options.Protocol is not null)
        {
            query = query.Where(item => item.Protocol == options.Protocol);
        }

        if (!string.IsNullOrWhiteSpace(options.ProcessFilter))
        {
            query = query.Where(item =>
                item.Owner.ImageName.Contains(options.ProcessFilter, StringComparison.OrdinalIgnoreCase)
                || item.Owner.Services.Any(service => service.Contains(options.ProcessFilter, StringComparison.OrdinalIgnoreCase)));
        }

        query = options.ScopeFilter switch
        {
            "loopback" => query.Where(static item => item.BindScope == BindScope.Loopback),
            "interface" => query.Where(static item => item.BindScope == BindScope.Interface),
            "wildcard" => query.Where(static item => item.BindScope == BindScope.Wildcard),
            "non-loopback" => query.Where(static item => item.BindScope != BindScope.Loopback),
            _ => query,
        };

        return query.ToArray();
    }

    private static IReadOnlyList<ListenerEvidence> ApplyLockSelector(
        IReadOnlyList<ListenerEvidence> listeners,
        ListenerLockfile baseline)
    {
        var options = new CliOptions(
            CommandKind.List,
            Port: baseline.Selector.Port,
            Protocol: baseline.Selector.Protocol,
            ProcessFilter: baseline.Selector.Process,
            ScopeFilter: baseline.Selector.Scope);
        var filtered = ApplyFilters(listeners, options);
        return baseline.IncludesUdp
            ? filtered
            : filtered.Where(static item => item.Protocol == TransportProtocol.Tcp).ToArray();
    }

    private static bool SocketsAvailable(SystemSnapshot snapshot) =>
        snapshot.Collectors.Any(static report => report.Name == "sockets" && report.Status == CollectorStatus.Complete);

    private static bool CoreEvidenceComplete(SystemSnapshot snapshot)
    {
        return snapshot.Collectors
            .Where(static report => report.Name != "docker")
            .All(static report => report.Status == CollectorStatus.Complete);
    }

    private static IReadOnlyList<ListenerEvidence> WatchListeners(
        IReadOnlyList<ListenerEvidence> listeners,
        CliOptions options)
    {
        var filtered = ApplyFilters(listeners, options);
        return options.IncludeUdp || options.Protocol == TransportProtocol.Udp
            ? filtered
            : filtered.Where(static item => item.Protocol == TransportProtocol.Tcp).ToArray();
    }

    private static bool CollectorEvidenceDegraded(
        SystemSnapshot previous,
        SystemSnapshot current,
        bool includeFirewall)
    {
        var required = includeFirewall
            ? new List<string> { "sockets", "process_owners", "interfaces", "windows_firewall" }
            : ["sockets", "process_owners", "interfaces"];
        if (previous.Listeners.Any(static listener => (listener.ContainerExposures?.Count ?? 0) > 0))
        {
            required.Add("docker");
        }
        foreach (var name in required)
        {
            var oldStatus = previous.Collectors.FirstOrDefault(item => item.Name == name)?.Status ?? CollectorStatus.Unavailable;
            var newStatus = current.Collectors.FirstOrDefault(item => item.Name == name)?.Status ?? CollectorStatus.Unavailable;
            if (CollectorRank(newStatus) < CollectorRank(oldStatus))
            {
                return true;
            }
        }

        return false;
    }

    private static int CollectorRank(CollectorStatus status) => status switch
    {
        CollectorStatus.Complete => 3,
        CollectorStatus.Partial => 2,
        CollectorStatus.Unavailable => 1,
        CollectorStatus.Failed => 0,
        _ => 0,
    };

    private static bool MeetsThreshold(
        VulnerabilitySeverity actual,
        VulnerabilitySeverity threshold) => actual switch
        {
            VulnerabilitySeverity.Critical => true,
            VulnerabilitySeverity.High => threshold == VulnerabilitySeverity.High,
            _ => false,
        };

    private static bool IsCheckFailure(ListenerChange change) => change.Kind switch
    {
        ListenerChangeKind.Added => true,
        ListenerChangeKind.OwnerChanged => true,
        ListenerChangeKind.ExposureExpanded => true,
        ListenerChangeKind.EvidenceRegressed => false,
        ListenerChangeKind.PolicyChanged when change.Before is not null && change.After is not null =>
            PolicyRank(change.After.HostPolicy) > PolicyRank(change.Before.HostPolicy),
        _ => false,
    };

    private static int PolicyRank(FirewallVerdict verdict) => verdict switch
    {
        FirewallVerdict.Block => 0,
        FirewallVerdict.NotEvaluated or FirewallVerdict.Unknown => 1,
        FirewallVerdict.Mixed => 2,
        FirewallVerdict.Allow or FirewallVerdict.Disabled => 3,
        _ => 1,
    };

    private static int WriteVersion(TextWriter output)
    {
        output.WriteLine($"portcve {Version}");
        return ExitCodes.Success;
    }

    private static int WriteHelp(TextWriter output)
    {
        output.WriteLine("PortCVE explains local ports and locks the ones you expect.");
        output.WriteLine();
        output.WriteLine("USAGE");
        output.WriteLine("  portcve                         List local TCP listeners and UDP binds");
        output.WriteLine("  portcve 8080                    Explain every local endpoint on port 8080");
        output.WriteLine("  portcve tcp:8080 --evidence     Explain one protocol with firewall evidence");
        output.WriteLine("  portcve lock -o listeners.lock  Save a normalized, privacy-reduced baseline");
        output.WriteLine("  portcve diff listeners.lock     Show drift from the live machine");
        output.WriteLine("  portcve check listeners.lock    Fail on new, wider, or owner-changed binds");
        output.WriteLine("  portcve scan tcp:8080           Check an exact listener's Docker image offline");
        output.WriteLine("  portcve scan --all              Check exact Docker images for all TCP listeners");
        output.WriteLine("  portcve watch --json             Stream endpoint changes as JSONL");
        output.WriteLine("  portcve doctor                  Check collection coverage and privacy mode");
        output.WriteLine();
        output.WriteLine("OPTIONS");
        output.WriteLine("  -p, --port <1-65535>                Filter by local port");
        output.WriteLine("  --proto <tcp|udp>                   Filter by transport protocol");
        output.WriteLine("  --scope <scope>                     loopback, interface, wildcard, non-loopback");
        output.WriteLine("  --process <name>                    Filter by process or service name");
        output.WriteLine("  --firewall / --no-firewall          Enable or disable host-policy collection");
        output.WriteLine("  --evidence                          Show rule and collector evidence");
        output.WriteLine("  --json                              Emit versioned machine-readable output");
        output.WriteLine("  --include-private                   Keep paths, account IDs, and exact IPs in JSON");
        output.WriteLine("  --resolve-accounts                  Resolve SIDs; Windows may query domain services");
        output.WriteLine("  --include-udp                       Include UDP binds in lock/watch workflows");
        output.WriteLine("  --allow-incomplete                  Permit a diff-only baseline with weak evidence");
        output.WriteLine("  --strict                            Exit 3 when core evidence is incomplete");
        output.WriteLine("  --all                               Select every TCP listener for scan");
        output.WriteLine("  --sbom <path>                       Scan an explicitly supplied local SBOM");
        output.WriteLine("  --fail-on <high|critical>           Exit 1 when that severity threshold is met");
        output.WriteLine("  -o, --output <path>                 Write lock or snapshot output to a file");
        output.WriteLine("  --force                             Replace an existing output file");
        output.WriteLine("  --interval <duration>               Watch interval, for example 500ms or 2s");
        output.WriteLine();
        output.WriteLine("EXIT CODES");
        output.WriteLine("  0 success/pass; 1 no match or policy fail; 2 usage/schema;");
        output.WriteLine("  3 incomplete evidence; 4 collection/runtime failure; 130 interrupted.");
        output.WriteLine();
        output.WriteLine("PortCVE is read-only and does not prove reachability or exploitability.");
        output.WriteLine("Vulnerability scans use a preinstalled Trivy database in offline mode; no update is automatic.");
        return ExitCodes.Success;
    }

    private static string Version =>
        Assembly.GetExecutingAssembly().GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
        ?? Assembly.GetExecutingAssembly().GetName().Version?.ToString()
        ?? "unknown";
}

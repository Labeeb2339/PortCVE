using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Reflection;
using BindWitness.Analysis;
using BindWitness.Domain;
using BindWitness.Platforms.Windows;

namespace BindWitness.Collection;

public sealed record SnapshotOptions(
    bool IncludeFirewall = false,
    bool IncludeProfiles = false,
    bool HashBinaries = false,
    bool ResolveAccounts = false);

public interface ISnapshotBuilder
{
    Task<SystemSnapshot> CollectAsync(SnapshotOptions options, CancellationToken cancellationToken);
}

public sealed class SnapshotBuilder : ISnapshotBuilder
{
    private const string EndpointOwnerChurnLimitation =
        "Owner metadata was withheld because this endpoint occurrence appeared during process-owner collection.";

    private readonly WindowsEndpointCollector endpointCollector;
    private readonly NetworkInterfaceCollector interfaceCollector;
    private readonly WindowsFirewallCollector firewallCollector;
    private readonly WindowsDockerEngineCollector dockerCollector;

    public SnapshotBuilder()
        : this(
            new WindowsEndpointCollector(),
            new NetworkInterfaceCollector(),
            new WindowsFirewallCollector(),
            new WindowsDockerEngineCollector())
    {
    }

    internal SnapshotBuilder(
        WindowsEndpointCollector endpointCollector,
        NetworkInterfaceCollector interfaceCollector,
        WindowsFirewallCollector firewallCollector,
        WindowsDockerEngineCollector dockerCollector)
    {
        this.endpointCollector = endpointCollector;
        this.interfaceCollector = interfaceCollector;
        this.firewallCollector = firewallCollector;
        this.dockerCollector = dockerCollector;
    }

    public async Task<SystemSnapshot> CollectAsync(
        SnapshotOptions options,
        CancellationToken cancellationToken)
    {
        var startedAt = DateTimeOffset.UtcNow;
        var totalStopwatch = Stopwatch.StartNew();
        var diagnostics = new List<CollectorDiagnostic>();
        var reports = new List<CollectorReport>();

        if (!OperatingSystem.IsWindows())
        {
            var diagnostic = new CollectorDiagnostic(
                "sockets",
                CollectorStatus.Unavailable,
                "platform_unsupported",
                "BindWitness 0.1 supports Windows only.");
            return new(
                SystemSnapshot.CurrentSchemaVersion,
                ToolVersion,
                startedAt,
                totalStopwatch.ElapsedMilliseconds,
                Environment.OSVersion.VersionString,
                [new("sockets", CollectorStatus.Unavailable, startedAt, 0, [diagnostic])],
                [],
                [],
                [diagnostic]);
        }

        var includeProfiles = options.IncludeProfiles || options.IncludeFirewall;
        var interfaceTask = interfaceCollector.CollectAsync(includeProfiles, cancellationToken);
        var firewallTask = options.IncludeFirewall
            ? firewallCollector.CollectAsync(cancellationToken)
            : null;
        var dockerTask = dockerCollector.CollectAsync(cancellationToken);

        var ownerGuardDiagnostics = new List<CollectorDiagnostic>();
        IReadOnlyList<WindowsRawEndpoint> beforeOwnerEndpoints;
        try
        {
            beforeOwnerEndpoints = endpointCollector.Collect();
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            beforeOwnerEndpoints = [];
            ownerGuardDiagnostics.Add(new(
                "process_owners",
                CollectorStatus.Partial,
                "endpoint_stability_baseline_failed",
                $"The pre-owner endpoint snapshot failed: {exception.Message} " +
                "Owner metadata cannot be safely attached to endpoints observed only afterward."));
        }

        CollectionResult<IReadOnlyDictionary<int, OwnerEvidence>> ownerResult;
        try
        {
            var processIds = beforeOwnerEndpoints
                .Where(static endpoint => endpoint.ProcessId <= int.MaxValue)
                .Select(static endpoint => (int)endpoint.ProcessId);
            ownerResult = new WindowsOwnerCollector().Collect(
                processIds,
                options.HashBinaries,
                options.ResolveAccounts);
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            var diagnostic = new CollectorDiagnostic(
                "process_owners",
                CollectorStatus.Failed,
                "owner_collection_failed",
                exception.Message);
            ownerResult = new(
                new Dictionary<int, OwnerEvidence>(),
                new("process_owners", CollectorStatus.Failed, DateTimeOffset.UtcNow, 0, [diagnostic]));
        }

        IReadOnlyList<WindowsRawEndpoint> authoritativeEndpoints;
        var socketStartedAt = DateTimeOffset.UtcNow;
        var socketStopwatch = Stopwatch.StartNew();
        try
        {
            authoritativeEndpoints = endpointCollector.Collect();
            socketStopwatch.Stop();
            reports.Add(new("sockets", CollectorStatus.Complete, socketStartedAt, socketStopwatch.ElapsedMilliseconds, []));
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            socketStopwatch.Stop();
            var diagnostic = new CollectorDiagnostic(
                "sockets",
                CollectorStatus.Failed,
                "socket_collection_failed",
                $"The authoritative post-owner endpoint snapshot failed: {exception.Message}");
            diagnostics.Add(diagnostic);
            reports.Add(new("sockets", CollectorStatus.Failed, socketStartedAt, socketStopwatch.ElapsedMilliseconds, [diagnostic]));
            authoritativeEndpoints = [];
        }

        var endpointOccurrences = EndpointSnapshotMatcher.Match(beforeOwnerEndpoints, authoritativeEndpoints);
        var appearedDuringOwnerCollection = endpointOccurrences.Count(static occurrence => !occurrence.IsStable);
        if (appearedDuringOwnerCollection > 0)
        {
            ownerGuardDiagnostics.Add(new(
                "process_owners",
                CollectorStatus.Partial,
                "endpoint_owner_churn",
                $"{appearedDuringOwnerCollection} endpoint occurrence(s) appeared between the pre-owner and " +
                "post-owner socket snapshots. Earlier process metadata was not attached to those rows."));
        }

        if (ownerGuardDiagnostics.Count > 0)
        {
            var ownerDiagnostics = ownerResult.Report.Diagnostics
                .Concat(ownerGuardDiagnostics)
                .ToArray();
            var ownerStatus = ownerResult.Report.Status == CollectorStatus.Failed
                ? CollectorStatus.Failed
                : CollectorStatus.Partial;
            ownerResult = ownerResult with
            {
                Report = ownerResult.Report with
                {
                    Status = ownerStatus,
                    Diagnostics = ownerDiagnostics,
                },
            };
        }

        reports.Add(ownerResult.Report);
        diagnostics.AddRange(ownerResult.Report.Diagnostics);

        var interfaceResult = await interfaceTask;
        reports.Add(interfaceResult.Report);
        diagnostics.AddRange(interfaceResult.Report.Diagnostics);

        var listeners = endpointOccurrences
            .Select(occurrence => CreateListener(
                occurrence.Endpoint,
                occurrence.IsStable,
                ownerResult.Value,
                interfaceResult.Value))
            .OrderBy(static listener => listener.Protocol)
            .ThenBy(static listener => listener.LocalPort)
            .ThenBy(static listener => listener.Family)
            .ThenBy(static listener => listener.LocalAddress, StringComparer.Ordinal)
            .ThenBy(static listener => listener.Owner.ImageName, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        var dockerResult = await dockerTask;
        if (dockerResult.Report.Status == CollectorStatus.Complete)
        {
            var correlation = DockerExposureCorrelator.Correlate(listeners, dockerResult.Value);
            listeners = correlation.Listeners.ToArray();
            if (correlation.UnmatchedPublications.Count > 0)
            {
                var diagnostic = new CollectorDiagnostic(
                    "docker",
                    CollectorStatus.Partial,
                    "docker_publication_unmatched",
                    $"{correlation.UnmatchedPublications.Count} Docker published-port mapping(s) could not be "
                    + "uniquely correlated to a Windows IP Helper endpoint. They were not converted into "
                    + "observed listeners.");
                diagnostics.Add(diagnostic);
                dockerResult = dockerResult with
                {
                    Report = dockerResult.Report with
                    {
                        Status = CollectorStatus.Partial,
                        Diagnostics = dockerResult.Report.Diagnostics.Append(diagnostic).ToArray(),
                    },
                };
            }
        }
        else if (dockerResult.Report.Status is CollectorStatus.Partial or CollectorStatus.Failed)
        {
            diagnostics.AddRange(dockerResult.Report.Diagnostics);
        }

        reports.Add(dockerResult.Report);

        if (firewallTask is not null)
        {
            var firewall = await firewallTask;
            reports.Add(firewall.Report);
            diagnostics.AddRange(firewall.Report.Diagnostics);
            if (firewall.Policy is not null)
            {
                listeners = listeners
                    .Select(listener => listener with
                    {
                        HostPolicy = GuardHostPolicyForInterfaceCollection(
                            listener.BindScope,
                            interfaceResult.Report.Status,
                            firewall.Policy.Assess(listener)),
                    })
                    .ToArray();
            }
            else
            {
                var limitation = firewall.Report.Diagnostics.FirstOrDefault()?.Message
                    ?? "Windows Firewall policy was unavailable.";
                listeners = listeners
                    .Select(listener => listener with
                    {
                        HostPolicy = new(
                            FirewallVerdict.Unknown,
                            Confidence.Low,
                            "Windows Firewall policy could not be evaluated.",
                            [],
                            [limitation, "External reachability was not tested."]),
                    })
                    .ToArray();
            }
        }

        totalStopwatch.Stop();
        return new(
            SystemSnapshot.CurrentSchemaVersion,
            ToolVersion,
            startedAt,
            totalStopwatch.ElapsedMilliseconds,
            Environment.OSVersion.VersionString,
            reports.OrderBy(static report => report.ObservedAt).ToArray(),
            interfaceResult.Value,
            listeners,
            diagnostics);
    }

    private static ListenerEvidence CreateListener(
        WindowsRawEndpoint endpoint,
        bool canAttachOwnerEvidence,
        IReadOnlyDictionary<int, OwnerEvidence> owners,
        IReadOnlyList<NetworkInterfaceEvidence> interfaces)
    {
        var protocol = endpoint.Protocol == WindowsEndpointProtocol.Tcp
            ? TransportProtocol.Tcp
            : TransportProtocol.Udp;
        var family = endpoint.AddressFamily == AddressFamily.InterNetwork
            ? IpFamily.Ipv4
            : IpFamily.Ipv6;
        var owner = ResolveOwnerEvidence(endpoint.ProcessId, canAttachOwnerEvidence, owners);
        var bind = BindScopeClassifier.Classify(endpoint.LocalAddress, family, interfaces);
        var state = protocol == TransportProtocol.Tcp
            ? endpoint.TcpState?.ToString().ToUpperInvariant() ?? "UNKNOWN"
            : "BOUND";
        var address = endpoint.LocalAddress.ToString();
        var key = CreateBindKey(protocol, family, address, endpoint.LocalPort);
        var evidence = new List<string>
        {
            $"Windows IP Helper reported PID {endpoint.ProcessId} for this endpoint.",
            $"The socket is bound to {bind.Summary}.",
        };
        var limitations = bind.Limitations.Concat(owner.Limitations).Distinct(StringComparer.Ordinal).ToArray();

        return new(
            key,
            protocol,
            family,
            address,
            endpoint.LocalPort,
            state,
            bind.Scope,
            bind.Summary,
            owner,
            bind.ActiveOn,
            HostPolicyEvidence.NotEvaluated,
            evidence,
            limitations);
    }

    public static string CreateBindKey(TransportProtocol protocol, IpFamily family, string address, int port) =>
        $"{protocol.ToString().ToLowerInvariant()}/{family.ToString().ToLowerInvariant()}/{address}/{port}";

    internal static HostPolicyEvidence GuardHostPolicyForInterfaceCollection(
        BindScope bindScope,
        CollectorStatus interfaceStatus,
        HostPolicyEvidence assessment)
    {
        ArgumentNullException.ThrowIfNull(assessment);

        if (bindScope == BindScope.Loopback || interfaceStatus == CollectorStatus.Complete)
        {
            return assessment;
        }

        var status = interfaceStatus.ToString().ToLowerInvariant();
        var limitation =
            $"Network interface collection was {status}; one or more bound paths may be missing from the firewall assessment.";
        var verdict = assessment.Verdict == FirewallVerdict.Mixed
            ? FirewallVerdict.Mixed
            : FirewallVerdict.Unknown;

        return assessment with
        {
            Verdict = verdict,
            Confidence = Confidence.Low,
            Summary = "Interface evidence was incomplete, so Windows Firewall policy could not be resolved for every bound path.",
            Limitations = assessment.Limitations
                .Append(limitation)
                .Distinct(StringComparer.Ordinal)
                .ToArray(),
        };
    }

    internal static OwnerEvidence ResolveOwnerEvidence(
        uint processId,
        bool canAttachOwnerEvidence,
        IReadOnlyDictionary<int, OwnerEvidence> owners)
    {
        ArgumentNullException.ThrowIfNull(owners);

        var pid = processId <= int.MaxValue ? (int)processId : -1;
        if (!canAttachOwnerEvidence)
        {
            return UnknownOwner(pid, EndpointOwnerChurnLimitation);
        }

        return owners.TryGetValue(pid, out var owner)
            ? owner
            : UnknownOwner(pid);
    }

    private static OwnerEvidence UnknownOwner(int pid, string? limitation = null) => new(
        pid,
        null,
        pid >= 0 ? $"pid-{pid}" : "unknown",
        null,
        null,
        null,
        null,
        null,
        null,
        [],
        false,
        false,
        [limitation ?? "The endpoint owner could not be attributed."]);

    private static string ToolVersion =>
        Assembly.GetExecutingAssembly().GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
        ?? Assembly.GetExecutingAssembly().GetName().Version?.ToString()
        ?? "unknown";
}

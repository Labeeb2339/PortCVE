using System.Globalization;
using PortCVE.Remote.Advisories;

namespace PortCVE.Remote;

internal sealed record RemoteAuditOptions(
    string ToolVersion,
    RemoteTargetPlan TargetPlan,
    IReadOnlyList<int> Ports,
    ProbeDepth ProbeDepth,
    bool AuthorizationAsserted,
    bool OnlineAdvisories,
    int Concurrency,
    int Rate,
    TimeSpan ConnectTimeout,
    TimeSpan ReadTimeout,
    string? NvdApiKey);

internal sealed class RemoteAuditService
{
    internal const int MaximumPlannedEndpoints = 1_000_000;
    internal const int MaximumUniqueAdvisoryIdentities = 64;
    internal const string ClaimBoundary =
        "Remote fingerprints and CVE correlations are evidence-backed candidates, not proof of vulnerable or exploitable code.";
    internal const string NvdNotice =
        "This product uses data from the NVD API but is not endorsed or certified by the NVD.";

    private readonly IRemoteHostScanner hostScanner;
    private readonly IRemoteAdvisoryClient advisoryClient;
    private readonly RemoteBannerCpeCatalog cpeCatalog;

    internal RemoteAuditService(
        IRemoteHostScanner hostScanner,
        IRemoteAdvisoryClient advisoryClient,
        RemoteBannerCpeCatalog? cpeCatalog = null)
    {
        this.hostScanner = hostScanner ?? throw new ArgumentNullException(nameof(hostScanner));
        this.advisoryClient = advisoryClient ?? throw new ArgumentNullException(nameof(advisoryClient));
        this.cpeCatalog = cpeCatalog ?? new RemoteBannerCpeCatalog();
    }

    internal async Task<RemoteAuditReport> AssessAsync(
        RemoteAuditOptions options,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(options.TargetPlan);
        ArgumentNullException.ThrowIfNull(options.Ports);
        cancellationToken.ThrowIfCancellationRequested();
        if (options.TargetPlan.Targets.Count == 0)
        {
            throw new ArgumentException("At least one planned target is required.", nameof(options));
        }

        if (!options.AuthorizationAsserted)
        {
            throw new ArgumentException("Remote assessment requires an authorization assertion.", nameof(options));
        }

        if (string.IsNullOrWhiteSpace(options.ToolVersion)
            || string.IsNullOrWhiteSpace(options.TargetPlan.Selector))
        {
            throw new ArgumentException("Tool version and target selector are required.", nameof(options));
        }

        var normalizedPorts = options.Ports.Distinct().Order().ToArray();
        if (normalizedPorts.Length == 0
            || normalizedPorts.Any(static port => port is < 1 or > 65_535))
        {
            throw new ArgumentException("At least one valid TCP port from 1 to 65535 is required.", nameof(options));
        }

        options = options with { Ports = normalizedPorts };
        var plannedEndpoints = (long)options.TargetPlan.Targets.Count * options.Ports.Count;
        if (plannedEndpoints > MaximumPlannedEndpoints)
        {
            throw new ArgumentOutOfRangeException(
                nameof(options),
                $"The target/port plan contains {plannedEndpoints.ToString("N0", CultureInfo.InvariantCulture)} TCP endpoints; "
                + $"the in-memory report limit is {MaximumPlannedEndpoints.ToString("N0", CultureInfo.InvariantCulture)}. "
                + "Split the assessment into smaller runs.");
        }

        var hosts = await ScanTargetsAsync(options, cancellationToken).ConfigureAwait(false);
        var advisoryBatch = await AssessProductsAsync(hosts, options, cancellationToken).ConfigureAwait(false);
        var assessments = advisoryBatch.Assessments;
        var advisoryResults = advisoryBatch.Results;
        var advisoryStatus = ComputeAdvisoryStatus(
            hosts,
            assessments,
            advisoryResults,
            options.OnlineAdvisories,
            advisoryBatch.IdentityLimitExceeded);
        var diagnostics = BuildReportDiagnostics(
            hosts,
            assessments,
            options.OnlineAdvisories,
            advisoryStatus,
            advisoryBatch.IdentityLimitExceeded);
        var openPorts = hosts.SelectMany(static host => host.Ports)
            .Count(static port => port.State == RemotePortState.Open);
        var productCandidates = hosts.SelectMany(static host => host.Ports)
            .Sum(static port => port.ProductCandidates.Count);
        var allMatches = advisoryResults.SelectMany(static item => item.Matches)
            .ToArray();
        var matches = allMatches
            .Where(IsCandidateClaim)
            .ToArray();
        var directMatches = matches
            .Where(static match => string.Equals(match.Classification, "candidate", StringComparison.Ordinal))
            .ToArray();
        var complete = IsComplete(
            hosts,
            advisoryStatus,
            options.OnlineAdvisories);

        return new(
            RemoteAuditReport.CurrentSchemaVersion,
            options.ToolVersion,
            DateTimeOffset.UtcNow,
            options.TargetPlan.Selector,
            "tcp",
            options.ProbeDepth == ProbeDepth.Active ? "safe_active" : "discovery",
            options.AuthorizationAsserted,
            options.OnlineAdvisories,
            advisoryStatus,
            MaximumUniqueAdvisoryIdentities,
            options.Ports,
            hosts,
            assessments,
            advisoryResults,
            new(
                options.TargetPlan.Targets.Count,
                hosts.Count(static host => host.ResolvedAddresses.Count > 0),
                hosts.Sum(static host => host.Ports.Count),
                openPorts,
                productCandidates,
                assessments.Count,
                advisoryResults.Count,
                matches.Length,
                matches.Count(static match => string.Equals(
                    match.Classification,
                    "conditional_candidate",
                    StringComparison.Ordinal)),
                allMatches.Count(static match => string.Equals(
                    match.Classification,
                    "inconclusive",
                    StringComparison.Ordinal)),
                directMatches.Count(static match => match.Severity == RemoteAdvisorySeverity.Critical),
                directMatches.Count(static match => match.Severity == RemoteAdvisorySeverity.High),
                complete),
            diagnostics,
            ClaimBoundary,
            options.OnlineAdvisories ? NvdNotice : null);
    }

    private async Task<IReadOnlyList<RemoteHostReport>> ScanTargetsAsync(
        RemoteAuditOptions options,
        CancellationToken cancellationToken)
    {
        var targets = options.TargetPlan.Targets;
        var reports = new RemoteHostReport[targets.Count];
        var hostConcurrency = Math.Min(Math.Min(16, options.Concurrency), targets.Count);
        var portConcurrency = Math.Max(1, options.Concurrency / Math.Max(1, hostConcurrency));
        var parallel = new ParallelOptions
        {
            CancellationToken = cancellationToken,
            MaxDegreeOfParallelism = Math.Max(1, hostConcurrency),
        };

        await Parallel.ForEachAsync(
            Enumerable.Range(0, targets.Count),
            parallel,
            async (index, token) =>
            {
                reports[index] = await hostScanner.ScanAsync(
                    new(
                        targets[index],
                        options.Ports,
                        options.ConnectTimeout,
                        options.ReadTimeout,
                        portConcurrency,
                        options.ProbeDepth,
                        maxConnectionsPerSecond: options.Rate),
                    token).ConfigureAwait(false);
            }).ConfigureAwait(false);

        return reports;
    }

    private async Task<AdvisoryAssessmentBatch> AssessProductsAsync(
        IReadOnlyList<RemoteHostReport> hosts,
        RemoteAuditOptions options,
        CancellationToken cancellationToken)
    {
        var candidates = hosts
            .SelectMany(host => host.Ports
                .Where(static port => port.State == RemotePortState.Open)
                .SelectMany(port => port.ProductCandidates.Select(candidate => new CandidateContext(
                    host.Target,
                    port.Address,
                    port.Port,
                    candidate))))
            .OrderBy(static item => item.Target, StringComparer.Ordinal)
            .ThenBy(static item => item.Address, StringComparer.Ordinal)
            .ThenBy(static item => item.Port)
            .ThenBy(static item => item.Candidate.Product, StringComparer.Ordinal)
            .ThenBy(static item => item.Candidate.Version, StringComparer.Ordinal)
            .ToArray();

        var assessments = new List<RemoteAdvisoryAssessment>(candidates.Length);
        var results = new List<RemoteAdvisoryProviderResult>();
        var resultsByIdentity = new Dictionary<string, RemoteAdvisoryProviderResult>(
            StringComparer.OrdinalIgnoreCase);
        var identityLimitExceeded = false;
        var subjectIndex = 0;
        foreach (var context in candidates)
        {
            cancellationToken.ThrowIfCancellationRequested();
            subjectIndex++;
            var candidate = context.Candidate;
            if (candidate.Confidence != RemoteProductConfidence.BannerPattern)
            {
                assessments.Add(CreateUnresolvedAssessment(
                    subjectIndex,
                    context,
                    RemoteIdentityDisposition.NotEligible,
                    "identity_evidence_insufficient",
                    "A self-reported HTTP header is retained for review but is not strong enough for CVE correlation."));
                continue;
            }

            var resolution = cpeCatalog.Resolve(
                candidate.Product,
                candidate.Version,
                candidate.Evidence,
                RemoteAdvisoryConfidence.Strong);
            if (!resolution.IsResolved)
            {
                assessments.Add(CreateUnresolvedAssessment(
                    subjectIndex,
                    context,
                    RemoteIdentityDisposition.Unresolved,
                    resolution.Diagnostic?.Code ?? "cpe_unresolved",
                    resolution.Diagnostic?.Message ?? "No verified CPE mapping was available."));
                continue;
            }

            if (!options.OnlineAdvisories)
            {
                assessments.Add(CreateResolvedAssessment(
                    subjectIndex,
                    context,
                    resolution,
                    advisoryResultId: null,
                    diagnostics: []));
                continue;
            }

            var key = resolution.Cpe23Uri!;
            if (!resultsByIdentity.TryGetValue(key, out var providerResult))
            {
                if (results.Count >= MaximumUniqueAdvisoryIdentities)
                {
                    identityLimitExceeded = true;
                    assessments.Add(CreateResolvedAssessment(
                        subjectIndex,
                        context,
                        resolution,
                        advisoryResultId: null,
                        diagnostics:
                        [
                            new(
                                "nvd_identity_cap_exceeded",
                                $"The run-wide limit of {MaximumUniqueAdvisoryIdentities.ToString(CultureInfo.InvariantCulture)} "
                                + "unique catalog-backed identities was reached; this identity was not sent to NVD."),
                        ]));
                    continue;
                }

                var result = await advisoryClient.EnrichAsync(
                    new(
                        new(
                            candidate.Product,
                            candidate.Version!,
                            candidate.Evidence,
                            RemoteAdvisoryConfidence.Strong,
                            resolution),
                        ExplicitOnline: true,
                        options.NvdApiKey),
                    cancellationToken).ConfigureAwait(false);
                providerResult = new(
                    $"remote-advisory-result-{results.Count + 1:0000}",
                    candidate.Product,
                    candidate.Version!,
                    resolution.Cpe23Uri!,
                    resolution.MappingSource,
                    result.Status,
                    result.Provider,
                    result.NetworkMode,
                    result.SourceTimestamp,
                    result.Matches,
                    result.Diagnostics);
                results.Add(providerResult);
                resultsByIdentity.Add(key, providerResult);
            }

            assessments.Add(CreateResolvedAssessment(
                subjectIndex,
                context,
                resolution,
                providerResult.ResultId,
                diagnostics: []));
        }

        return new(assessments, results, identityLimitExceeded);
    }

    private static RemoteAdvisoryAssessment CreateResolvedAssessment(
        int subjectIndex,
        CandidateContext context,
        RemoteBannerCpeCatalog.Resolution resolution,
        string? advisoryResultId,
        IReadOnlyList<RemoteAdvisoryDiagnostic> diagnostics) =>
        new(
            $"remote-product-{subjectIndex:0000}",
            context.Target,
            context.Address,
            context.Port,
            context.Candidate.Product,
            context.Candidate.Version,
            context.Candidate.Confidence,
            context.Candidate.Evidence,
            RemoteIdentityDisposition.Resolved,
            resolution.Cpe23Uri,
            resolution.MappingSource,
            advisoryResultId,
            diagnostics);

    private static RemoteAdvisoryAssessment CreateUnresolvedAssessment(
        int subjectIndex,
        CandidateContext context,
        RemoteIdentityDisposition disposition,
        string code,
        string message) =>
        new(
            $"remote-product-{subjectIndex:0000}",
            context.Target,
            context.Address,
            context.Port,
            context.Candidate.Product,
            context.Candidate.Version,
            context.Candidate.Confidence,
            context.Candidate.Evidence,
            disposition,
            null,
            null,
            null,
            [new(code, message)]);

    private static IReadOnlyList<RemoteDiagnostic> BuildReportDiagnostics(
        IReadOnlyList<RemoteHostReport> hosts,
        IReadOnlyList<RemoteAdvisoryAssessment> assessments,
        bool onlineAdvisories,
        RemoteAdvisoryStatus advisoryStatus,
        bool identityLimitExceeded)
    {
        var diagnostics = new List<RemoteDiagnostic>();
        if (hosts.Any(static host => host.Diagnostics.Count > 0))
        {
            diagnostics.Add(new(
                "remote_targets_incomplete",
                "One or more targets could not be resolved or scanned completely."));
        }

        if (hosts.SelectMany(static host => host.Ports)
            .Any(static port => !IsConclusivePortState(port.State)))
        {
            diagnostics.Add(new(
                "remote_endpoints_incomplete",
                "One or more TCP endpoint probes failed before a conclusive state was observed."));
        }

        if (hosts.SelectMany(static host => host.Ports)
            .Any(static port => port.State == RemotePortState.Open && port.Diagnostics.Count > 0))
        {
            diagnostics.Add(new(
                "remote_fingerprint_incomplete",
                "At least one open service could not complete every selected identification or safe-active probe."));
        }

        if (onlineAdvisories && advisoryStatus != RemoteAdvisoryStatus.Complete)
        {
            diagnostics.Add(new(
                "remote_advisories_incomplete",
                "NVD enrichment was incomplete for one or more remote product identities."));
        }

        if (identityLimitExceeded)
        {
            diagnostics.Add(new(
                "remote_advisory_identity_limit_exceeded",
                $"The run contained more than {MaximumUniqueAdvisoryIdentities.ToString(CultureInfo.InvariantCulture)} "
                + "unique strong catalog-backed identities; additional identities were not sent to NVD."));
        }

        if (onlineAdvisories
            && (assessments.Any(static item => item.IdentityDisposition != RemoteIdentityDisposition.Resolved)
                || hosts.SelectMany(static host => host.Ports)
                    .Any(static port => port.State == RemotePortState.Open && port.ProductCandidates.Count == 0)))
        {
            diagnostics.Add(new(
                "remote_identity_unresolved",
                "At least one open service lacked a strong, catalog-backed product/version identity for CVE correlation."));
        }

        return diagnostics;
    }

    private static RemoteAdvisoryStatus ComputeAdvisoryStatus(
        IReadOnlyList<RemoteHostReport> hosts,
        IReadOnlyList<RemoteAdvisoryAssessment> assessments,
        IReadOnlyList<RemoteAdvisoryProviderResult> results,
        bool onlineAdvisories,
        bool identityLimitExceeded)
    {
        if (!onlineAdvisories)
        {
            return RemoteAdvisoryStatus.NotRequested;
        }

        if (results.Any(static result => result.Status == RemoteAdvisoryStatus.Failed))
        {
            return RemoteAdvisoryStatus.Failed;
        }

        if (results.Any(static result => result.Status == RemoteAdvisoryStatus.Unavailable))
        {
            return RemoteAdvisoryStatus.Unavailable;
        }

        var openPortWithoutIdentity = hosts.SelectMany(static host => host.Ports)
            .Any(static port => port.State == RemotePortState.Open && port.ProductCandidates.Count == 0);
        if (identityLimitExceeded ||
            openPortWithoutIdentity ||
            assessments.Any(static assessment =>
                assessment.IdentityDisposition != RemoteIdentityDisposition.Resolved ||
                assessment.AdvisoryResultId is null) ||
            results.Any(static result => result.Status != RemoteAdvisoryStatus.Complete))
        {
            return RemoteAdvisoryStatus.Partial;
        }

        return RemoteAdvisoryStatus.Complete;
    }

    private static bool IsComplete(
        IReadOnlyList<RemoteHostReport> hosts,
        RemoteAdvisoryStatus advisoryStatus,
        bool onlineAdvisories)
    {
        if (hosts.Any(static host => host.Diagnostics.Count > 0)
            || hosts.SelectMany(static host => host.Ports).Any(static port =>
                !IsConclusivePortState(port.State)
                || (port.State == RemotePortState.Open && port.Diagnostics.Count > 0)))
        {
            return false;
        }

        if (!onlineAdvisories)
        {
            return true;
        }

        return advisoryStatus == RemoteAdvisoryStatus.Complete;
    }

    private static bool IsConclusivePortState(RemotePortState state) =>
        state is RemotePortState.Open or RemotePortState.Closed;

    internal static bool IsCandidateClaim(RemoteAdvisoryMatch match) =>
        string.Equals(match.Classification, "candidate", StringComparison.Ordinal)
        || string.Equals(match.Classification, "conditional_candidate", StringComparison.Ordinal);

    private sealed record CandidateContext(
        string Target,
        string Address,
        int Port,
        RemoteProductCandidate Candidate);

    private sealed record AdvisoryAssessmentBatch(
        IReadOnlyList<RemoteAdvisoryAssessment> Assessments,
        IReadOnlyList<RemoteAdvisoryProviderResult> Results,
        bool IdentityLimitExceeded);
}

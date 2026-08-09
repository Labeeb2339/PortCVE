namespace PortCVE.Remote.Advisories;

internal enum RemoteAdvisoryConfidence
{
    Exact,
    Strong,
    Heuristic,
    Unresolved,
}

internal enum RemoteAdvisoryStatus
{
    NotRequested,
    Unresolved,
    Complete,
    Partial,
    Unavailable,
    Failed,
}

internal enum RemoteAdvisorySeverity
{
    Unknown,
    Low,
    Medium,
    High,
    Critical,
}

internal sealed record RemoteAdvisoryIdentity(
    string Product,
    string Version,
    string Evidence,
    RemoteAdvisoryConfidence Confidence,
    RemoteBannerCpeCatalog.Resolution? CpeResolution);

internal sealed record RemoteAdvisoryRequest(
    RemoteAdvisoryIdentity Identity,
    bool ExplicitOnline,
    string? NvdApiKey = null);

internal sealed record RemoteAdvisoryDiagnostic(
    string Code,
    string Message);

internal enum RemoteAdvisoryApplicabilityDisposition
{
    DirectCandidate,
    ConditionalCandidate,
    Inconclusive,
}

internal enum RemoteAdvisoryCpeAlignment
{
    NoMatch,
    Proven,
    ConditionalOnUnobservedQualifier,
    InconclusiveConstraint,
}

internal sealed record RemoteAdvisoryCpeMatch(
    bool Vulnerable,
    string Criteria,
    string MatchCriteriaId,
    string? VersionStartExcluding,
    string? VersionStartIncluding,
    string? VersionEndExcluding,
    string? VersionEndIncluding,
    RemoteAdvisoryCpeAlignment IdentityAlignment,
    bool MatchesQueriedIdentity,
    bool HasUnobservedQualifiers);

internal sealed record RemoteAdvisoryApplicabilityNode(
    string Operator,
    bool Negate,
    IReadOnlyList<RemoteAdvisoryCpeMatch> CpeMatches);

internal sealed record RemoteAdvisoryConfiguration(
    string? Operator,
    bool Negate,
    IReadOnlyList<RemoteAdvisoryApplicabilityNode> Nodes);

internal sealed record RemoteAdvisoryApplicability(
    RemoteAdvisoryApplicabilityDisposition Disposition,
    bool QueriedCpeVulnerableLeafFound,
    bool HasRequiredCofactors,
    IReadOnlyList<RemoteAdvisoryConfiguration> Configurations,
    IReadOnlyList<string> Limitations);

internal sealed record RemoteAdvisoryMatch(
    string AdvisoryId,
    string Classification,
    string MatchMethod,
    string Product,
    string Version,
    string Cpe23Uri,
    string Evidence,
    RemoteAdvisoryConfidence Confidence,
    string NvdStatus,
    DateTimeOffset NvdLastModified,
    RemoteAdvisoryApplicability Applicability,
    RemoteAdvisorySeverity Severity,
    string? SeveritySource,
    string? Description,
    IReadOnlyList<string> References,
    bool ReferencesTruncated,
    string Exploitability);

internal sealed record RemoteAdvisoryResult(
    RemoteAdvisoryStatus Status,
    string Provider,
    string NetworkMode,
    DateTimeOffset? SourceTimestamp,
    IReadOnlyList<RemoteAdvisoryMatch> Matches,
    IReadOnlyList<RemoteAdvisoryDiagnostic> Diagnostics)
{
    internal const string ProviderName = "nvd_cve_api_2.0";
    internal const string ExplicitOnlineNetworkMode = "online_explicit";
    internal const string OfflineNetworkMode = "offline";
}

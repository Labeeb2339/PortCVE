using System.Text.Json.Serialization;
using PortCVE.Remote.Advisories;

namespace PortCVE.Remote;

internal enum RemoteIdentityDisposition
{
    Resolved,
    Unresolved,
    NotEligible,
}

internal sealed record RemoteAdvisoryAssessment(
    string SubjectId,
    string Target,
    string Address,
    int Port,
    string Product,
    string? Version,
    RemoteProductConfidence EvidenceConfidence,
    string Evidence,
    RemoteIdentityDisposition IdentityDisposition,
    string? Cpe23Uri,
    string? MappingSource,
    string? AdvisoryResultId,
    IReadOnlyList<RemoteAdvisoryDiagnostic> Diagnostics);

internal sealed record RemoteAdvisoryProviderResult(
    string ResultId,
    string Product,
    string Version,
    string Cpe23Uri,
    string MappingSource,
    RemoteAdvisoryStatus Status,
    string Provider,
    string NetworkMode,
    DateTimeOffset? SourceTimestamp,
    IReadOnlyList<RemoteAdvisoryMatch> Matches,
    IReadOnlyList<RemoteAdvisoryDiagnostic> Diagnostics);

internal sealed record RemoteAuditSummary(
    int TargetCount,
    int ResolvedTargetCount,
    int EndpointCount,
    int OpenPortCount,
    int ProductCandidateCount,
    int AdvisoryAssessmentCount,
    int AdvisoryResultCount,
    int AdvisoryMatchCount,
    int ConditionalCount,
    int InconclusiveCount,
    int CriticalCount,
    int HighCount,
    bool IsComplete);

internal sealed record RemoteAuditReport(
    int SchemaVersion,
    string ToolVersion,
    DateTimeOffset GeneratedAt,
    string Selector,
    string Transport,
    string ProbeProfile,
    bool AuthorizationAsserted,
    bool OnlineAdvisoriesRequested,
    RemoteAdvisoryStatus AdvisoryStatus,
    int AdvisoryIdentityLimit,
    IReadOnlyList<int> RequestedPorts,
    IReadOnlyList<RemoteHostReport> Hosts,
    IReadOnlyList<RemoteAdvisoryAssessment> AdvisoryAssessments,
    IReadOnlyList<RemoteAdvisoryProviderResult> AdvisoryResults,
    RemoteAuditSummary Summary,
    IReadOnlyList<RemoteDiagnostic> Diagnostics,
    string ClaimBoundary,
    string? NvdNotice)
{
    internal const int CurrentSchemaVersion = 1;

    [JsonIgnore]
    internal bool AdvisoryProviderFailed => OnlineAdvisoriesRequested
        && AdvisoryStatus is RemoteAdvisoryStatus.Unavailable or RemoteAdvisoryStatus.Failed;
}

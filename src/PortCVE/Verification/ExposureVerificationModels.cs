using PortCVE.Domain;
using PortCVE.Remote.Imports;
using PortCVE.Snapshots;
using System.Text.Json.Serialization;

namespace PortCVE.Verification;

internal enum VerificationInputKind
{
    NmapXml,
    NucleiJsonl,
    NessusXml,
    LiveWindows,
}

internal enum VerificationPrivacyMode
{
    Private,
    Reduced,
}

internal enum ExposureCorrelation
{
    CorrelatedOpen,
    OutsideOnly,
    LoopbackMismatch,
    OutsideNegativeLocalPresent,
    ConsistentAbsent,
    Inconclusive,
}

internal enum FindingCorrelation
{
    OwnerCorroborated,
    OwnerAmbiguous,
    ScannerOnly,
    Inconclusive,
}

internal sealed record VerificationPortMapping(
    string Protocol,
    int ExternalPort,
    int LocalPort);

internal sealed record VerificationAssociation(
    string ImportedTarget,
    bool AssociationAsserted,
    string Vantage,
    IReadOnlyList<VerificationPortMapping> PortMappings);

internal sealed record VerificationInput(
    VerificationInputKind Source,
    string? FileName,
    long? SizeBytes,
    string? Sha256,
    string? SourceVersion,
    bool IsComplete,
    DateTimeOffset? ObservedAt);

internal sealed record OutsideEndpointObservation(
    string Source,
    string Target,
    string? Hostname,
    string State,
    string? StateReason,
    ImportedServiceIdentity? Service);

internal sealed record VerificationLocalListener(
    IpFamily Family,
    BindScope BindScope,
    string LocalAddress,
    int LocalPort,
    string OwnerIdentity,
    OwnerIdentityStrength OwnerIdentityStrength,
    string ImageName,
    IReadOnlyList<string> Services,
    IReadOnlyList<string> ContainerImages,
    FirewallVerdict HostPolicy,
    Confidence HostPolicyConfidence,
    IReadOnlyList<string> Limitations);

internal sealed record VerificationFindingObservation(
    string Source,
    string FindingId,
    string Title,
    string Severity,
    ImportedClaimStatus ClaimStatus,
    ImportedEvidenceStrength EvidenceStrength,
    IReadOnlyList<string> AdvisoryIds,
    string SourceRecordSha256,
    string? Matcher);

internal sealed record VerificationFindingGroup(
    string FindingGroupId,
    string Title,
    string HighestReportedSeverity,
    IReadOnlyList<string> AdvisoryIds,
    FindingCorrelation Correlation,
    string Exploitability,
    IReadOnlyList<VerificationFindingObservation> Observations);

internal sealed record VerifiedExposureEndpoint(
    string Protocol,
    int ExternalPort,
    int LocalPort,
    ExposureCorrelation Correlation,
    IReadOnlyList<OutsideEndpointObservation> OutsideObservations,
    IReadOnlyList<VerificationLocalListener> LocalListeners,
    IReadOnlyList<VerificationFindingGroup> Findings,
    IReadOnlyList<string> Limitations);

internal sealed record VerificationDiagnostic(
    string Code,
    string Message);

internal sealed record ExposureVerificationSummary(
    int OutsideEndpointCount,
    int OutsideOpenCount,
    int CorrelatedOpenCount,
    int OutsideOnlyCount,
    int LoopbackMismatchCount,
    int OutsideNegativeLocalPresentCount,
    int ConsistentAbsentCount,
    int InconclusiveCount,
    int FindingGroupCount,
    int CriticalCount,
    int HighCount,
    bool IsComplete);

internal sealed record ExposureVerificationReport(
    int SchemaVersion,
    string ToolVersion,
    VerificationPrivacyMode PrivacyMode,
    DateTimeOffset GeneratedAt,
    VerificationAssociation Association,
    IReadOnlyList<VerificationInput> Inputs,
    IReadOnlyList<VerifiedExposureEndpoint> Endpoints,
    IReadOnlyList<VerificationFindingGroup> TargetFindings,
    ExposureVerificationSummary Summary,
    IReadOnlyList<VerificationDiagnostic> Diagnostics,
    string ClaimBoundary)
{
    internal const int CurrentSchemaVersion = 1;

    [JsonIgnore]
    public IReadOnlyList<string> PrivateRedactionAliases { get; init; } = [];
}

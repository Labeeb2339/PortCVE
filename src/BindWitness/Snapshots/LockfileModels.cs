using System.Text.Json.Serialization;
using BindWitness.Domain;

namespace BindWitness.Snapshots;

public enum OwnerIdentityStrength
{
    Sha256,
    ContainerImage,
    Service,
    Kernel,
    NameOnly,
    Unknown,
}

public enum EvidenceCompleteness
{
    Complete,
    Partial,
    NotCollected,
}

public sealed record LockfileEvidence(
    EvidenceCompleteness Ownership,
    EvidenceCompleteness BindScope,
    EvidenceCompleteness HostPolicy,
    EvidenceCompleteness Containers);

public sealed record LockfileSelector(
    int? Port,
    TransportProtocol? Protocol,
    string? Process,
    string? Scope);

public sealed record LockedListener(
    string Key,
    TransportProtocol Protocol,
    IpFamily Family,
    string Address,
    int Port,
    BindScope Scope,
    string OwnerIdentity,
    OwnerIdentityStrength OwnerIdentityStrength,
    Confidence HostPolicyConfidence,
    FirewallVerdict HostPolicy);

public sealed record ListenerLockfile(
    int SchemaVersion,
    string CreatedBy,
    bool IncludesUdp,
    LockfileSelector Selector,
    LockfileEvidence Evidence,
    IReadOnlyList<LockedListener> Listeners)
{
    public const int CurrentSchemaVersion = 1;

    [JsonIgnore]
    public bool IsComplete =>
        Evidence.Ownership == EvidenceCompleteness.Complete
        && Evidence.BindScope == EvidenceCompleteness.Complete
        && Evidence.HostPolicy is EvidenceCompleteness.Complete or EvidenceCompleteness.NotCollected
        && Evidence.Containers is EvidenceCompleteness.Complete or EvidenceCompleteness.NotCollected;
}

using System.Text.Json.Serialization;
using PortCVE.Domain;

namespace PortCVE.Snapshots;

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
    FirewallVerdict HostPolicy)
{
    [JsonIgnore]
    internal string? ObservedOwnerNameIdentity { get; init; }
}

public sealed record ListenerLockfile(
    int SchemaVersion,
    string CreatedBy,
    bool IncludesUdp,
    LockfileSelector Selector,
    LockfileEvidence Evidence,
    IReadOnlyList<LockedListener> Listeners,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    bool AllowWeakOwner = false)
{
    public const int CurrentSchemaVersion = 1;

    [JsonIgnore]
    public bool HasSufficientOwnerEvidence =>
        (Evidence.Ownership == EvidenceCompleteness.Complete
            && Listeners.All(static listener => IsStrongOwner(listener.OwnerIdentityStrength)))
        || (AllowWeakOwner
            && Evidence.Ownership == EvidenceCompleteness.Partial
            && Listeners.Any(static listener => listener.OwnerIdentityStrength == OwnerIdentityStrength.NameOnly)
            && Listeners.All(static listener => HasAtLeastNameOnlyOwner(listener.OwnerIdentityStrength)));

    [JsonIgnore]
    public bool IsComplete =>
        HasSufficientOwnerEvidence
        && Evidence.BindScope == EvidenceCompleteness.Complete
        && Evidence.HostPolicy is EvidenceCompleteness.Complete or EvidenceCompleteness.NotCollected
        && Evidence.Containers is EvidenceCompleteness.Complete or EvidenceCompleteness.NotCollected;

    private static bool IsStrongOwner(OwnerIdentityStrength strength) => strength is
        OwnerIdentityStrength.Sha256
        or OwnerIdentityStrength.ContainerImage
        or OwnerIdentityStrength.Service
        or OwnerIdentityStrength.Kernel;

    private static bool HasAtLeastNameOnlyOwner(OwnerIdentityStrength strength) =>
        strength != OwnerIdentityStrength.Unknown;
}

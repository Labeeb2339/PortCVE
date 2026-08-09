using System.Text.Json.Serialization;

namespace PortCVE.Domain;

public enum TransportProtocol
{
    Tcp,
    Udp,
}

public enum IpFamily
{
    Ipv4,
    Ipv6,
}

public enum BindScope
{
    Loopback,
    Interface,
    Wildcard,
    Unknown,
}

public enum CollectorStatus
{
    Complete,
    Partial,
    Unavailable,
    Failed,
}

public enum FirewallVerdict
{
    NotEvaluated,
    Allow,
    Block,
    Mixed,
    Unknown,
    Disabled,
}

public enum Confidence
{
    High,
    Medium,
    Low,
}

public sealed record CollectorDiagnostic(
    string Collector,
    CollectorStatus Status,
    string Code,
    string Message);

public sealed record CollectorReport(
    string Name,
    CollectorStatus Status,
    DateTimeOffset ObservedAt,
    long DurationMs,
    IReadOnlyList<CollectorDiagnostic> Diagnostics);

public sealed record NetworkInterfaceEvidence(
    string Id,
    string Name,
    int Index,
    string Address,
    int PrefixLength,
    string Profile,
    bool IsUp);

public sealed record OwnerEvidence(
    int Pid,
    DateTimeOffset? CreationTime,
    string ImageName,
    string? ImagePath,
    string? ImageSha256,
    int? ParentPid,
    string? ParentImageName,
    string? UserSid,
    string? AccountName,
    IReadOnlyList<string> Services,
    bool ServicesAreCandidates,
    bool IsComplete,
    IReadOnlyList<string> Limitations);

public sealed record ContainerExposureEvidence(
    string Runtime,
    string ContainerId,
    string ContainerName,
    string Image,
    string? ImageId,
    string HostAddress,
    int HostPort,
    int ContainerPort,
    TransportProtocol Protocol,
    Confidence Confidence,
    IReadOnlyList<string> Limitations);

public sealed record FirewallRuleEvidence(
    string Id,
    string Name,
    string Action,
    IReadOnlyList<string> Profiles,
    string Protocol,
    string LocalPort,
    string LocalAddress,
    string RemoteAddress,
    string Application,
    string Service,
    IReadOnlyList<string> UnsupportedConstraints);

public sealed record HostPolicyEvidence(
    FirewallVerdict Verdict,
    Confidence Confidence,
    string Summary,
    IReadOnlyList<FirewallRuleEvidence> MatchingRules,
    IReadOnlyList<string> Limitations)
{
    public static HostPolicyEvidence NotEvaluated { get; } = new(
        FirewallVerdict.NotEvaluated,
        Confidence.Low,
        "Host firewall was not evaluated.",
        [],
        ["Run a direct port query or pass --firewall to collect host-policy evidence."]);
}

public sealed record ListenerEvidence(
    string Key,
    TransportProtocol Protocol,
    IpFamily Family,
    string LocalAddress,
    int LocalPort,
    string SocketState,
    BindScope BindScope,
    string BindSummary,
    OwnerEvidence Owner,
    IReadOnlyList<NetworkInterfaceEvidence> ActiveOn,
    HostPolicyEvidence HostPolicy,
    IReadOnlyList<string> Evidence,
    IReadOnlyList<string> Limitations,
    IReadOnlyList<ContainerExposureEvidence>? ContainerExposures = null);

public sealed record SystemSnapshot(
    int SchemaVersion,
    string ToolVersion,
    DateTimeOffset GeneratedAt,
    long CollectionWindowMs,
    string Platform,
    IReadOnlyList<CollectorReport> Collectors,
    IReadOnlyList<NetworkInterfaceEvidence> Interfaces,
    IReadOnlyList<ListenerEvidence> Listeners,
    IReadOnlyList<CollectorDiagnostic> Diagnostics)
{
    public const int CurrentSchemaVersion = 1;

    [JsonIgnore]
    public bool IsComplete => Collectors.All(static report => report.Status == CollectorStatus.Complete);
}

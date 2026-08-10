using PortCVE.Domain;
using PortCVE.Remote.Imports;
using PortCVE.Vulnerabilities;

namespace PortCVE.Cli;

public enum CommandKind
{
    List,
    Inspect,
    Scan,
    ScanHost,
    Import,
    DbStatus,
    DbUpdate,
    Lock,
    Snapshot,
    Diff,
    Check,
    Watch,
    Doctor,
    Help,
    Version,
}

public sealed record CliOptions(
    CommandKind Command,
    int? Port = null,
    TransportProtocol? Protocol = null,
    string? ProcessFilter = null,
    string? ScopeFilter = null,
    string? InputPath = null,
    string? OutputPath = null,
    bool Json = false,
    bool IncludeFirewall = false,
    bool ShowEvidence = false,
    bool Strict = false,
    bool Force = false,
    bool AllowIncomplete = false,
    bool IncludeUdp = false,
    bool IncludePrivate = false,
    bool ResolveAccounts = false,
    TimeSpan? Interval = null,
    int? Iterations = null,
    bool All = false,
    string? SbomPath = null,
    VulnerabilitySeverity? FailOn = null,
    string? RemoteTarget = null,
    string? RemotePorts = null,
    bool Active = false,
    bool Authorized = false,
    bool OnlineAdvisories = false,
    int? Concurrency = null,
    int? Rate = null,
    TimeSpan? ConnectTimeout = null,
    TimeSpan? ReadTimeout = null,
    int? MaximumHosts = null,
    RemoteImportFormat? ImportFormat = null);

public sealed class CliUsageException(string message) : Exception(message);

public static class ExitCodes
{
    public const int Success = 0;
    public const int NegativeResult = 1;
    public const int UsageOrSchema = 2;
    public const int IncompleteEvidence = 3;
    public const int RuntimeFailure = 4;
    public const int Interrupted = 130;
}

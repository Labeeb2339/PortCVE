using System.Collections.ObjectModel;
using System.Globalization;
using System.Net;

namespace PortCVE.Remote;

internal enum ProbeDepth
{
    Passive,
    Active,
}

internal enum RemotePortState
{
    Open,
    Closed,
    TimedOut,
    Unreachable,
    Error,
}

internal enum RemoteFingerprintKind
{
    Greeting,
    Ssh,
    Ftp,
    Smtp,
    Pop3,
    Imap,
    Http,
    Tls,
    HttpOptions,
    HttpEndpoint,
    TlsProtocolProbe,
}

internal enum RemoteFingerprintConfidence
{
    Observed,
    StrongPattern,
    ProtocolConfirmed,
}

internal enum RemoteProductConfidence
{
    BannerPattern,
    HeaderReported,
}

internal sealed class RemoteScanOptions
{
    internal const int MaximumPortCount = 65_535;
    internal const int MaximumConcurrency = 512;
    internal const int MaximumConnectionsPerSecondLimit = 10_000;
    internal const int MaximumEndpointCount = 262_144;
    internal const int MinimumEvidenceBytes = 256;
    internal const int MaximumEvidenceBytesLimit = 65_536;
    internal static readonly TimeSpan MaximumTimeout = TimeSpan.FromMinutes(5);

    public RemoteScanOptions(
        string target,
        IReadOnlyList<int> ports,
        TimeSpan connectTimeout,
        TimeSpan readTimeout,
        int concurrency,
        ProbeDepth probeDepth = ProbeDepth.Passive,
        int maximumEvidenceBytes = 8_192,
        int maxConnectionsPerSecond = 100)
    {
        Target = NormalizeTarget(target);
        Ports = ValidatePorts(ports);
        ConnectTimeout = ValidateTimeout(connectTimeout, nameof(connectTimeout));
        ReadTimeout = ValidateTimeout(readTimeout, nameof(readTimeout));

        if (concurrency is < 1 or > MaximumConcurrency)
        {
            throw new ArgumentOutOfRangeException(
                nameof(concurrency),
                string.Create(
                    CultureInfo.InvariantCulture,
                    $"Concurrency must be between 1 and {MaximumConcurrency}."));
        }

        if (!Enum.IsDefined(probeDepth))
        {
            throw new ArgumentOutOfRangeException(nameof(probeDepth));
        }

        if (maximumEvidenceBytes is < MinimumEvidenceBytes or > MaximumEvidenceBytesLimit)
        {
            throw new ArgumentOutOfRangeException(
                nameof(maximumEvidenceBytes),
                string.Create(
                    CultureInfo.InvariantCulture,
                    $"Evidence bytes must be between {MinimumEvidenceBytes} and {MaximumEvidenceBytesLimit}."));
        }

        if (maxConnectionsPerSecond is < 1 or > MaximumConnectionsPerSecondLimit)
        {
            throw new ArgumentOutOfRangeException(
                nameof(maxConnectionsPerSecond),
                string.Create(
                    CultureInfo.InvariantCulture,
                    $"Connection rate must be between 1 and {MaximumConnectionsPerSecondLimit} per second."));
        }

        Concurrency = concurrency;
        ProbeDepth = probeDepth;
        MaximumEvidenceBytes = maximumEvidenceBytes;
        MaxConnectionsPerSecond = maxConnectionsPerSecond;
    }

    public string Target { get; }

    public IReadOnlyList<int> Ports { get; }

    public TimeSpan ConnectTimeout { get; }

    public TimeSpan ReadTimeout { get; }

    public int Concurrency { get; }

    public ProbeDepth ProbeDepth { get; }

    public int MaximumEvidenceBytes { get; }

    public int MaxConnectionsPerSecond { get; }

    private static string NormalizeTarget(string target)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(target);
        var candidate = target.Trim();
        if (candidate.Length >= 2
            && candidate[0] == '['
            && candidate[^1] == ']'
            && IPAddress.TryParse(candidate[1..^1], out var bracketedAddress))
        {
            return bracketedAddress.ToString();
        }

        if (IPAddress.TryParse(candidate, out var address))
        {
            return address.ToString();
        }

        if (candidate.Length > 253
            || Uri.CheckHostName(candidate) != UriHostNameType.Dns)
        {
            throw new ArgumentException("Target must be one DNS hostname or IP address.", nameof(target));
        }

        string ascii;
        try
        {
            ascii = new IdnMapping().GetAscii(candidate.TrimEnd('.'));
        }
        catch (ArgumentException exception)
        {
            throw new ArgumentException("Target contains an invalid DNS hostname.", nameof(target), exception);
        }

        if (ascii.Length is 0 or > 253 || ascii.Contains("..", StringComparison.Ordinal))
        {
            throw new ArgumentException("Target contains an invalid DNS hostname.", nameof(target));
        }

        return ascii.ToLowerInvariant();
    }

    private static IReadOnlyList<int> ValidatePorts(IReadOnlyList<int> ports)
    {
        ArgumentNullException.ThrowIfNull(ports);
        if (ports.Count is 0 or > MaximumPortCount)
        {
            throw new ArgumentOutOfRangeException(
                nameof(ports),
                $"At least one and at most {MaximumPortCount} explicit ports are required.");
        }

        var result = ports
            .Distinct()
            .Order()
            .ToArray();
        if (result.Any(static port => port is < 1 or > IPEndPoint.MaxPort))
        {
            throw new ArgumentOutOfRangeException(nameof(ports), "Ports must be between 1 and 65535.");
        }

        return Array.AsReadOnly(result);
    }

    private static TimeSpan ValidateTimeout(TimeSpan timeout, string parameterName)
    {
        if (timeout <= TimeSpan.Zero || timeout > MaximumTimeout)
        {
            throw new ArgumentOutOfRangeException(
                parameterName,
                $"Timeout must be greater than zero and no more than {MaximumTimeout}.");
        }

        return timeout;
    }
}

internal sealed record RemoteDiagnostic(string Code, string Message);

internal sealed record RemoteFingerprint(
    RemoteFingerprintKind Kind,
    string Service,
    RemoteFingerprintConfidence Confidence,
    string Source,
    string Evidence,
    IReadOnlyDictionary<string, string> Attributes)
{
    public static IReadOnlyDictionary<string, string> ReadOnlyAttributes(
        IDictionary<string, string>? attributes = null) =>
        new ReadOnlyDictionary<string, string>(
            attributes is null
                ? new Dictionary<string, string>(StringComparer.Ordinal)
                : new Dictionary<string, string>(attributes, StringComparer.Ordinal));
}

internal sealed record RemoteProductCandidate(
    string Product,
    string? Version,
    RemoteProductConfidence Confidence,
    string Source,
    string Evidence);

internal sealed record RemotePortResult(
    string Address,
    string AddressFamily,
    int Port,
    RemotePortState State,
    long DurationMs,
    IReadOnlyList<RemoteFingerprint> Fingerprints,
    IReadOnlyList<RemoteProductCandidate> ProductCandidates,
    IReadOnlyList<RemoteDiagnostic> Diagnostics);

internal sealed record RemoteHostReport(
    string Target,
    IReadOnlyList<string> ResolvedAddresses,
    IReadOnlyList<RemotePortResult> Ports,
    IReadOnlyList<RemoteDiagnostic> Diagnostics);

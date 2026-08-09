namespace PortCVE.Remote;

internal sealed class RemoteProbePolicy
{
    private static readonly int[] DefaultHttpPorts = [
        80, 81, 3000, 5000, 8000, 8008, 8080, 8081, 8888,
    ];

    private static readonly int[] DefaultTlsPorts = [
        443, 465, 636, 853, 989, 990, 992, 993, 994, 995, 8443, 9443,
    ];

    private static readonly int[] DefaultHttpsPorts = [443, 8443, 9443];

    public RemoteProbePolicy(
        IEnumerable<int>? httpPorts = null,
        IEnumerable<int>? tlsPorts = null,
        IEnumerable<int>? httpsPorts = null)
    {
        HttpPorts = ValidatePortSet(httpPorts ?? DefaultHttpPorts, nameof(httpPorts));
        TlsPorts = ValidatePortSet(tlsPorts ?? DefaultTlsPorts, nameof(tlsPorts));
        HttpsPorts = ValidatePortSet(httpsPorts ?? DefaultHttpsPorts, nameof(httpsPorts));

        if (HttpsPorts.Any(port => !TlsPorts.Contains(port)))
        {
            throw new ArgumentException("Every HTTPS port must also be configured as a TLS port.", nameof(httpsPorts));
        }
    }

    public IReadOnlySet<int> HttpPorts { get; }

    public IReadOnlySet<int> TlsPorts { get; }

    public IReadOnlySet<int> HttpsPorts { get; }

    private static IReadOnlySet<int> ValidatePortSet(IEnumerable<int> ports, string parameterName)
    {
        ArgumentNullException.ThrowIfNull(ports);
        var result = ports.ToHashSet();
        if (result.Any(static port => port is < 1 or > 65_535))
        {
            throw new ArgumentOutOfRangeException(parameterName, "Probe-policy ports must be between 1 and 65535.");
        }

        return result;
    }
}

using System.Globalization;
using System.Net;
using System.Net.Sockets;

namespace PortCVE.Remote;

internal sealed class RemoteInputException(string message) : Exception(message);

internal sealed record RemoteTargetPlan(
    string Selector,
    IReadOnlyList<string> Targets,
    bool IsRange);

internal static class RemoteInputParser
{
    public const int DefaultMaximumHosts = 256;
    public const int AbsoluteMaximumHosts = 65_536;

    private static readonly int[] CommonTcpPorts =
    [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 389, 443, 445, 465, 587,
        636, 993, 995, 1433, 1521, 2049, 2375, 2376, 3000, 3306, 3389, 5000, 5432,
        5601, 5672, 5900, 5985, 5986, 6379, 6443, 8000, 8008, 8080, 8081, 8443,
        8888, 9000, 9090, 9200, 9300, 11211, 27017,
    ];

    public static IReadOnlyList<int> ParsePorts(string? specification)
    {
        if (specification is null
            || specification.Equals("common", StringComparison.OrdinalIgnoreCase))
        {
            return CommonTcpPorts;
        }

        if (string.IsNullOrWhiteSpace(specification))
        {
            throw new RemoteInputException("--ports must select at least one TCP port.");
        }

        if (specification.Equals("all", StringComparison.OrdinalIgnoreCase))
        {
            return Enumerable.Range(1, 65535).ToArray();
        }

        var ports = new SortedSet<int>();
        foreach (var rawToken in specification.Split(',', StringSplitOptions.TrimEntries))
        {
            if (rawToken.Length == 0)
            {
                throw new RemoteInputException("--ports contains an empty item.");
            }

            var rangeParts = rawToken.Split('-', 2, StringSplitOptions.TrimEntries);
            var first = ParsePort(rangeParts[0]);
            var last = rangeParts.Length == 1 ? first : ParsePort(rangeParts[1]);
            if (last < first)
            {
                throw new RemoteInputException($"Port range '{rawToken}' is descending.");
            }

            for (var port = first; port <= last; port++)
            {
                ports.Add(port);
            }
        }

        if (ports.Count == 0)
        {
            throw new RemoteInputException("--ports must select at least one TCP port.");
        }

        return ports.ToArray();
    }

    public static RemoteTargetPlan ParseTargets(
        string selector,
        int maximumHosts = DefaultMaximumHosts)
    {
        if (string.IsNullOrWhiteSpace(selector))
        {
            throw new RemoteInputException("scan-host requires an IP address, hostname, or IPv4 CIDR.");
        }

        if (maximumHosts is < 1 or > AbsoluteMaximumHosts)
        {
            throw new RemoteInputException(
                $"--max-hosts must be from 1 to {AbsoluteMaximumHosts.ToString(CultureInfo.InvariantCulture)}.");
        }

        var trimmed = selector.Trim();
        if (trimmed.Contains("//", StringComparison.Ordinal)
            || trimmed.Contains('\\')
            || trimmed.Contains('?')
            || trimmed.Contains('#'))
        {
            throw new RemoteInputException("Target must be a host or CIDR, not a URL or path.");
        }

        if (!trimmed.Contains('/'))
        {
            if (IPAddress.TryParse(trimmed, out var literal))
            {
                return new(trimmed, [literal.ToString()], false);
            }

            if (Uri.CheckHostName(trimmed) is not UriHostNameType.Dns)
            {
                throw new RemoteInputException($"Target '{trimmed}' is not a valid IP address or DNS hostname.");
            }

            return new(trimmed, [trimmed], false);
        }

        var slash = trimmed.LastIndexOf('/');
        var addressText = trimmed[..slash];
        var prefixText = trimmed[(slash + 1)..];
        if (!IPAddress.TryParse(addressText, out var address)
            || address.AddressFamily != AddressFamily.InterNetwork)
        {
            throw new RemoteInputException("CIDR scanning currently supports IPv4 ranges only.");
        }

        if (!int.TryParse(prefixText, NumberStyles.None, CultureInfo.InvariantCulture, out var prefix)
            || prefix is < 0 or > 32)
        {
            throw new RemoteInputException($"CIDR prefix '{prefixText}' must be from 0 to 32.");
        }

        var hostCount = 1L << (32 - prefix);
        if (hostCount > maximumHosts)
        {
            throw new RemoteInputException(
                $"CIDR selects {hostCount.ToString(CultureInfo.InvariantCulture)} addresses; "
                + $"the current --max-hosts limit is {maximumHosts.ToString(CultureInfo.InvariantCulture)}.");
        }

        var bytes = address.GetAddressBytes();
        var raw = ((uint)bytes[0] << 24)
            | ((uint)bytes[1] << 16)
            | ((uint)bytes[2] << 8)
            | bytes[3];
        var mask = prefix == 0 ? 0u : uint.MaxValue << (32 - prefix);
        var network = raw & mask;
        var targets = new string[hostCount];
        for (long index = 0; index < hostCount; index++)
        {
            var current = network + (uint)index;
            targets[index] = new IPAddress(
            [
                (byte)(current >> 24),
                (byte)(current >> 16),
                (byte)(current >> 8),
                (byte)current,
            ]).ToString();
        }

        return new(trimmed, targets, true);
    }

    private static int ParsePort(string value)
    {
        if (!int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var port)
            || port is < 1 or > 65535)
        {
            throw new RemoteInputException($"Port '{value}' must be an integer from 1 to 65535.");
        }

        return port;
    }
}

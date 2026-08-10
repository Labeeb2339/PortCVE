using System.Globalization;
using PortCVE.Domain;

namespace PortCVE.Verification;

internal readonly record struct VerificationEndpointKey(
    TransportProtocol Protocol,
    int Port)
{
    public override string ToString() => $"{Protocol.ToString().ToLowerInvariant()}/{Port}";
}

internal sealed class VerificationInputException(string message) : Exception(message);

internal static class PortMappingParser
{
    internal static IReadOnlyDictionary<VerificationEndpointKey, VerificationEndpointKey> Parse(string? value)
    {
        var mappings = new Dictionary<VerificationEndpointKey, VerificationEndpointKey>();
        if (string.IsNullOrWhiteSpace(value))
        {
            return mappings;
        }

        foreach (var rawMapping in value.Split(',', StringSplitOptions.TrimEntries))
        {
            if (rawMapping.Length == 0)
            {
                throw new VerificationInputException("Port mappings must not contain empty entries.");
            }

            var pair = rawMapping.Split('=', StringSplitOptions.TrimEntries);
            if (pair.Length != 2)
            {
                throw new VerificationInputException(
                    $"Invalid port mapping '{rawMapping}'; expected tcp/443=tcp/8443.");
            }

            var external = ParseEndpoint(pair[0], rawMapping);
            var local = ParseEndpoint(pair[1], rawMapping);
            if (external.Protocol != local.Protocol)
            {
                throw new VerificationInputException(
                    $"Port mapping '{rawMapping}' changes transport protocol; TCP and UDP cannot be correlated.");
            }

            if (!mappings.TryAdd(external, local))
            {
                throw new VerificationInputException($"Port mapping for {external} is duplicated.");
            }
        }

        return mappings;
    }

    private static VerificationEndpointKey ParseEndpoint(string value, string rawMapping)
    {
        var parts = value.Split('/', StringSplitOptions.TrimEntries);
        var protocol = parts.Length == 2 ? parts[0].ToLowerInvariant() switch
        {
            "tcp" => TransportProtocol.Tcp,
            "udp" => TransportProtocol.Udp,
            _ => (TransportProtocol?)null,
        } : null;
        if (protocol is null
            || !int.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out var port)
            || port is < 1 or > 65535)
        {
            throw new VerificationInputException(
                $"Invalid endpoint in port mapping '{rawMapping}'; expected tcp/443 or udp/53.");
        }

        return new(protocol.Value, port);
    }
}

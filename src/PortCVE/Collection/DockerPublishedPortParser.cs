using System.Globalization;
using System.Net;
using System.Text.Json;

namespace PortCVE.Collection;

internal static class DockerPublishedPortParser
{
    internal static string ParseApiVersion(string json)
    {
        using var document = ParseDocument(json);
        if (document.RootElement.ValueKind != JsonValueKind.Object)
        {
            throw new JsonException("The Docker version response must be a JSON object.");
        }

        var apiVersion = ReadRequiredString(document.RootElement, "ApiVersion");
        var parts = apiVersion.Split('.', StringSplitOptions.None);
        if (parts.Length != 2
            || parts.Any(static part => part.Length == 0 || !part.All(char.IsAsciiDigit)))
        {
            throw new JsonException($"Docker returned an invalid API version '{apiVersion}'.");
        }

        return apiVersion;
    }

    internal static IReadOnlyList<DockerPublishedPort> ParseContainers(string json)
    {
        using var document = ParseDocument(json);
        if (document.RootElement.ValueKind != JsonValueKind.Array)
        {
            throw new JsonException("The Docker containers response must be a JSON array.");
        }

        var publishedPorts = new List<DockerPublishedPort>();
        foreach (var container in document.RootElement.EnumerateArray())
        {
            if (container.ValueKind != JsonValueKind.Object)
            {
                throw new JsonException("Each Docker container entry must be a JSON object.");
            }

            var containerId = ReadRequiredString(container, "Id");
            var containerName = ReadContainerName(container);
            var image = ReadRequiredString(container, "Image");
            var imageId = ReadRequiredString(container, "ImageID");

            if (!container.TryGetProperty("Ports", out var ports) || ports.ValueKind == JsonValueKind.Null)
            {
                continue;
            }

            if (ports.ValueKind != JsonValueKind.Array)
            {
                throw new JsonException("Docker container 'Ports' must be a JSON array.");
            }

            foreach (var port in ports.EnumerateArray())
            {
                if (port.ValueKind != JsonValueKind.Object)
                {
                    throw new JsonException("Each Docker port entry must be a JSON object.");
                }

                // PublicPort is omitted for an exposed container port that is not published on the host.
                if (!port.TryGetProperty("PublicPort", out var publicPortElement)
                    || publicPortElement.ValueKind == JsonValueKind.Null)
                {
                    continue;
                }

                var hostPort = ReadPort(publicPortElement, "PublicPort");
                if (!port.TryGetProperty("PrivatePort", out var privatePortElement))
                {
                    throw new JsonException("A published Docker port is missing 'PrivatePort'.");
                }

                var containerPort = ReadPort(privatePortElement, "PrivatePort");
                var protocol = ReadRequiredString(port, "Type").ToLowerInvariant();
                if (protocol is not ("tcp" or "udp"))
                {
                    throw new JsonException($"Docker returned unsupported published-port protocol '{protocol}'.");
                }

                var hostAddress = ReadHostAddress(port);

                publishedPorts.Add(new(
                    containerId,
                    containerName,
                    image,
                    imageId,
                    hostAddress,
                    hostPort,
                    containerPort,
                    protocol));
            }
        }

        return publishedPorts;
    }

    internal static bool HostAddressMatches(string publishedHostAddress, string endpointAddress)
    {
        if (!IPAddress.TryParse(endpointAddress, out var endpoint))
        {
            return false;
        }

        if (string.IsNullOrWhiteSpace(publishedHostAddress) || publishedHostAddress == "*")
        {
            return true;
        }

        if (!IPAddress.TryParse(publishedHostAddress, out var published)
            || published.AddressFamily != endpoint.AddressFamily)
        {
            return false;
        }

        return IsWildcard(published)
            || IsWildcard(endpoint)
            || published.Equals(endpoint);
    }

    private static JsonDocument ParseDocument(string json)
    {
        ArgumentNullException.ThrowIfNull(json);
        return JsonDocument.Parse(json, new JsonDocumentOptions
        {
            AllowTrailingCommas = false,
            CommentHandling = JsonCommentHandling.Disallow,
            MaxDepth = 32,
        });
    }

    private static string ReadRequiredString(JsonElement element, string propertyName)
    {
        if (!element.TryGetProperty(propertyName, out var property)
            || property.ValueKind != JsonValueKind.String
            || string.IsNullOrWhiteSpace(property.GetString()))
        {
            throw new JsonException($"Docker response property '{propertyName}' must be a non-empty string.");
        }

        return property.GetString()!;
    }

    private static string ReadContainerName(JsonElement container)
    {
        if (!container.TryGetProperty("Names", out var names) || names.ValueKind == JsonValueKind.Null)
        {
            return string.Empty;
        }

        if (names.ValueKind != JsonValueKind.Array)
        {
            throw new JsonException("Docker container 'Names' must be a JSON array.");
        }

        foreach (var name in names.EnumerateArray())
        {
            if (name.ValueKind != JsonValueKind.String)
            {
                throw new JsonException("Each Docker container name must be a string.");
            }

            var normalized = name.GetString()?.Trim().TrimStart('/');
            if (!string.IsNullOrWhiteSpace(normalized))
            {
                return normalized;
            }
        }

        return string.Empty;
    }

    private static int ReadPort(JsonElement element, string propertyName)
    {
        if (element.ValueKind != JsonValueKind.Number
            || !element.TryGetInt32(out var port)
            || port is < 1 or > ushort.MaxValue)
        {
            throw new JsonException(
                $"Docker response property '{propertyName}' must be an integer from 1 to {ushort.MaxValue.ToString(CultureInfo.InvariantCulture)}.");
        }

        return port;
    }

    private static string ReadHostAddress(JsonElement port)
    {
        if (!port.TryGetProperty("IP", out var address) || address.ValueKind == JsonValueKind.Null)
        {
            return "*";
        }

        if (address.ValueKind != JsonValueKind.String)
        {
            throw new JsonException("Docker response property 'IP' must be a string.");
        }

        var value = address.GetString();
        if (string.IsNullOrWhiteSpace(value) || value == "*")
        {
            return "*";
        }

        if (!IPAddress.TryParse(value, out var parsed))
        {
            throw new JsonException($"Docker returned an invalid published host address '{value}'.");
        }

        return parsed.ToString();
    }

    private static bool IsWildcard(IPAddress address) =>
        address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any);
}

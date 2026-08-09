using System.Security.Cryptography;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace PortCVE.Remote.Imports;

internal static class ImportText
{
    private static readonly string[] SensitiveMarkers =
    [
        "authorization:",
        "proxy-authorization:",
        "cookie:",
        "set-cookie:",
        "bearer ",
        "api_key",
        "api-key",
        "apikey",
        "access_token",
        "refresh_token",
        "password=",
        "passwd=",
        "secret=",
        "token=",
        "private key",
    ];

    public static string? Sanitize(string? value, int maximumCharacters = 2048)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        var builder = new StringBuilder(Math.Min(value.Length, maximumCharacters));
        foreach (var character in value)
        {
            if (builder.Length >= maximumCharacters)
            {
                break;
            }

            builder.Append(char.IsControl(character) ? '\uFFFD' : character);
        }

        return builder.ToString().Trim();
    }

    public static string Sha256(string value) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(value)));

    public static string Sha256(ReadOnlySpan<byte> value) =>
        Convert.ToHexStringLower(SHA256.HashData(value));

    public static string? SanitizeIdentifier(string? value, int maximumCharacters = 256)
    {
        var sanitized = Sanitize(value, maximumCharacters);
        if (sanitized is null || LooksSensitive(sanitized))
        {
            return null;
        }

        foreach (var character in sanitized)
        {
            var isAllowed = character is >= 'a' and <= 'z'
                or >= 'A' and <= 'Z'
                or >= '0' and <= '9'
                or '.'
                or '_'
                or ':'
                or '-';
            if (isAllowed)
            {
                continue;
            }

            return null;
        }

        var result = sanitized.Trim('-', '.', '_', ':');
        return result.Length == 0 ? null : result;
    }

    public static string? SanitizePublicLabel(string? value, int maximumCharacters = 512)
    {
        var sanitized = Sanitize(value, maximumCharacters);
        if (sanitized is null || LooksSensitive(sanitized))
        {
            return null;
        }

        return Uri.TryCreate(sanitized, UriKind.Absolute, out var uri)
            && (!string.IsNullOrWhiteSpace(uri.Host) || uri.Scheme is "data" or "file" or "javascript" or "vbscript")
            ? null
            : sanitized;
    }

    public static string? SanitizeTarget(string? value)
    {
        var sanitized = Sanitize(value, 2048);
        if (sanitized is null)
        {
            return null;
        }

        if (Uri.TryCreate(sanitized, UriKind.Absolute, out var absolute)
            && !string.IsNullOrWhiteSpace(absolute.Host)
            && IsSafeEndpointScheme(absolute.Scheme))
        {
            return BuildOrigin(absolute);
        }

        var delimiter = sanitized.IndexOfAny(['?', '#', '/', '\\']);
        var endpoint = delimiter >= 0 ? sanitized[..delimiter] : sanitized;
        var userInfo = endpoint.LastIndexOf('@');
        if (userInfo >= 0)
        {
            endpoint = endpoint[(userInfo + 1)..];
        }

        endpoint = endpoint.Trim();
        if (IPAddress.TryParse(endpoint.Trim('[', ']'), out var ipAddress))
        {
            return ipAddress.AddressFamily == AddressFamily.InterNetworkV6
                ? $"[{ipAddress}]"
                : ipAddress.ToString();
        }

        if (endpoint.Length == 0 || LooksSensitive(endpoint)
            || !Uri.TryCreate($"tcp://{endpoint}", UriKind.Absolute, out var parsed)
            || string.IsNullOrWhiteSpace(parsed.Host))
        {
            return null;
        }

        var host = FormatHost(parsed);
        return parsed.Port is >= 1 and <= 65535 ? $"{host}:{parsed.Port}" : host;
    }

    public static string? SanitizeReference(string? value)
    {
        var sanitized = Sanitize(value, 2048);
        if (sanitized is null
            || !Uri.TryCreate(sanitized, UriKind.Absolute, out var uri)
            || uri.Scheme is not ("http" or "https")
            || string.IsNullOrWhiteSpace(uri.Host))
        {
            return null;
        }

        var origin = BuildOrigin(uri);
        if (origin is null)
        {
            return null;
        }

        var escapedPath = uri.GetComponents(UriComponents.Path, UriFormat.UriEscaped);
        if (escapedPath.Length == 0)
        {
            return origin;
        }

        var safeSegments = new List<string>();
        var previousSegmentNamesSecret = false;
        foreach (var segment in escapedPath.Split('/', StringSplitOptions.RemoveEmptyEntries))
        {
            string decoded;
            try
            {
                decoded = Uri.UnescapeDataString(segment);
            }
            catch (UriFormatException)
            {
                break;
            }

            if (previousSegmentNamesSecret || LooksSensitive(decoded) || LooksLikeOpaqueToken(decoded))
            {
                break;
            }

            safeSegments.Add(segment);
            previousSegmentNamesSecret = IsSecretPathMarker(decoded);
        }

        return safeSegments.Count == 0 ? origin : $"{origin}/{string.Join('/', safeSegments)}";
    }

    private static bool LooksSensitive(string value) =>
        SensitiveMarkers.Any(marker => value.Contains(marker, StringComparison.OrdinalIgnoreCase));

    private static bool LooksLikeOpaqueToken(string value)
    {
        if (value.Length < 24)
        {
            return false;
        }

        var tokenCharacters = 0;
        foreach (var character in value)
        {
            if (character is >= 'a' and <= 'z'
                or >= 'A' and <= 'Z'
                or >= '0' and <= '9'
                or '-'
                or '_'
                or '='
                or '.')
            {
                tokenCharacters++;
            }
        }

        return tokenCharacters == value.Length;
    }

    private static bool IsSecretPathMarker(string value) =>
        value.Equals("token", StringComparison.OrdinalIgnoreCase)
        || value.Equals("secret", StringComparison.OrdinalIgnoreCase)
        || value.Equals("password", StringComparison.OrdinalIgnoreCase)
        || value.Equals("reset", StringComparison.OrdinalIgnoreCase)
        || value.Equals("session", StringComparison.OrdinalIgnoreCase)
        || value.Equals("apikey", StringComparison.OrdinalIgnoreCase)
        || value.Equals("api-key", StringComparison.OrdinalIgnoreCase);

    private static bool IsSafeEndpointScheme(string scheme) =>
        scheme is not ("data" or "file" or "javascript" or "vbscript");

    private static string? BuildOrigin(Uri uri)
    {
        if (!IsSafeEndpointScheme(uri.Scheme))
        {
            return null;
        }

        var host = FormatHost(uri);
        if (host.Length == 0)
        {
            return null;
        }

        var port = uri.IsDefaultPort || uri.Port is < 1 or > 65535 ? string.Empty : $":{uri.Port}";
        return $"{uri.Scheme.ToLowerInvariant()}://{host}{port}";
    }

    private static string FormatHost(Uri uri) =>
        uri.HostNameType == UriHostNameType.IPv6 ? $"[{uri.IdnHost}]" : uri.IdnHost.ToLowerInvariant();
}

using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text.Json;
using PortCVE.Domain;

namespace PortCVE.Collection;

public sealed class NetworkInterfaceCollector
{
    private const string ProfileScript = """
        $ErrorActionPreference = 'Stop'
        $rows = @(
          Get-NetConnectionProfile -ErrorAction Stop |
            ForEach-Object {
              [pscustomobject]@{
                interface_index = [int]$_.InterfaceIndex
                profile = [string]$_.NetworkCategory
                name = [string]$_.Name
              }
            }
        )
        ConvertTo-Json -InputObject $rows -Compress
        """;

    public async Task<CollectionResult<IReadOnlyList<NetworkInterfaceEvidence>>> CollectAsync(
        bool includeProfiles,
        CancellationToken cancellationToken)
    {
        var startedAt = DateTimeOffset.UtcNow;
        var stopwatch = Stopwatch.StartNew();
        var diagnostics = new List<CollectorDiagnostic>();
        var profiles = includeProfiles
            ? await CollectProfilesAsync(diagnostics, cancellationToken)
            : [];
        var interfaces = new List<NetworkInterfaceEvidence>();

        try
        {
            foreach (var networkInterface in NetworkInterface.GetAllNetworkInterfaces())
            {
                cancellationToken.ThrowIfCancellationRequested();
                var properties = networkInterface.GetIPProperties();
                var index4 = TryGetIndex(properties, AddressFamily.InterNetwork);
                var index6 = TryGetIndex(properties, AddressFamily.InterNetworkV6);
                var isUp = networkInterface.OperationalStatus == OperationalStatus.Up;

                foreach (var address in properties.UnicastAddresses)
                {
                    var index = address.Address.AddressFamily == AddressFamily.InterNetwork ? index4 : index6;
                    if (index is null)
                    {
                        continue;
                    }

                    profiles.TryGetValue(index.Value, out var profile);
                    interfaces.Add(new(
                        networkInterface.Id,
                        networkInterface.Name,
                        index.Value,
                        address.Address.ToString(),
                        address.PrefixLength,
                        profile ?? "Unknown",
                        isUp));
                }
            }
        }
        catch (NetworkInformationException exception)
        {
            diagnostics.Add(new(
                "interfaces",
                CollectorStatus.Partial,
                "network_information_error",
                exception.Message));
        }

        stopwatch.Stop();
        var status = interfaces.Count == 0
            ? CollectorStatus.Unavailable
            : diagnostics.Count == 0 ? CollectorStatus.Complete : CollectorStatus.Partial;

        return new(
            interfaces
                .OrderBy(static item => item.Index)
                .ThenBy(static item => item.Address, StringComparer.Ordinal)
                .ToArray(),
            new("interfaces", status, startedAt, stopwatch.ElapsedMilliseconds, diagnostics));
    }

    private static int? TryGetIndex(IPInterfaceProperties properties, AddressFamily family)
    {
        try
        {
            return properties.GetIPv4Properties() is { } ipv4 && family == AddressFamily.InterNetwork
                ? ipv4.Index
                : properties.GetIPv6Properties() is { } ipv6 && family == AddressFamily.InterNetworkV6
                    ? ipv6.Index
                    : null;
        }
        catch (NetworkInformationException)
        {
            return null;
        }
    }

    private static async Task<Dictionary<int, string>> CollectProfilesAsync(
        List<CollectorDiagnostic> diagnostics,
        CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsWindows())
        {
            return [];
        }

        var result = await PowerShellJsonRunner.RunAsync(
            ProfileScript,
            TimeSpan.FromSeconds(8),
            cancellationToken,
            TrustedWindowsPowerShellModule.NetConnection);
        if (!result.Succeeded)
        {
            diagnostics.Add(new(
                "network_profiles",
                CollectorStatus.Partial,
                result.TimedOut ? "profile_timeout" : "profile_unavailable",
                string.IsNullOrWhiteSpace(result.StandardError)
                    ? "Windows network profiles could not be collected."
                    : result.StandardError));
            return [];
        }

        try
        {
            if (string.IsNullOrWhiteSpace(result.StandardOutput))
            {
                return [];
            }

            var records = JsonSerializer.Deserialize<ProfileRecord[]>(result.StandardOutput, JsonOptions) ?? [];
            return records
                .GroupBy(static item => item.InterfaceIndex)
                .ToDictionary(
                    static group => group.Key,
                    static group => string.Join(
                        ',',
                        group.Select(static item => NormalizeProfile(item.Profile))
                            .Distinct(StringComparer.OrdinalIgnoreCase)));
        }
        catch (JsonException exception)
        {
            diagnostics.Add(new(
                "network_profiles",
                CollectorStatus.Partial,
                "profile_json_invalid",
                exception.Message));
            return [];
        }
    }

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
    };

    internal static string NormalizeProfile(string profile) =>
        profile.Equals("DomainAuthenticated", StringComparison.OrdinalIgnoreCase)
            ? "Domain"
            : profile;

    private sealed record ProfileRecord(int InterfaceIndex, string Profile, string Name);
}

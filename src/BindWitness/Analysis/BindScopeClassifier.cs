using System.Net;
using BindWitness.Domain;

namespace BindWitness.Analysis;

public sealed record BindClassification(
    BindScope Scope,
    string Summary,
    IReadOnlyList<NetworkInterfaceEvidence> ActiveOn,
    IReadOnlyList<string> Limitations);

public static class BindScopeClassifier
{
    public static BindClassification Classify(
        IPAddress address,
        IpFamily family,
        IReadOnlyList<NetworkInterfaceEvidence> interfaces)
    {
        if (IPAddress.IsLoopback(address))
        {
            return new(
                BindScope.Loopback,
                "this machine only",
                [],
                []);
        }

        if (address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any))
        {
            var candidates = interfaces
                .Where(item => item.IsUp && AddressMatchesFamily(item.Address, family))
                .OrderBy(static item => item.Index)
                .ThenBy(static item => item.Address, StringComparer.Ordinal)
                .ToArray();

            var familyLabel = family == IpFamily.Ipv4 ? "IPv4" : "IPv6";
            return new(
                BindScope.Wildcard,
                $"all {familyLabel} interfaces",
                candidates,
                candidates.Length == 0 ? ["No active matching interface was observed."] : []);
        }

        var exact = interfaces
            .Where(item => IPAddress.TryParse(item.Address, out var candidate) && candidate.Equals(address))
            .OrderBy(static item => item.Index)
            .ToArray();

        if (exact.Length > 0)
        {
            return new(
                BindScope.Interface,
                $"specific interface address {address}",
                exact,
                []);
        }

        return new(
            BindScope.Unknown,
            $"address {address} was not mapped to an active interface",
            [],
            ["The interface may have changed during collection or may be hidden by the platform."]);
    }

    private static bool AddressMatchesFamily(string value, IpFamily family)
    {
        return IPAddress.TryParse(value, out var address)
            && ((family == IpFamily.Ipv4 && address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                || (family == IpFamily.Ipv6 && address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6));
    }
}

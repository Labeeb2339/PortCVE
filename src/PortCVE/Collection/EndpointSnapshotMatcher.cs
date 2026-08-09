using System.Net.Sockets;
using PortCVE.Platforms.Windows;

namespace PortCVE.Collection;

internal sealed record EndpointSnapshotOccurrence(
    WindowsRawEndpoint Endpoint,
    bool IsStable);

internal static class EndpointSnapshotMatcher
{
    internal static IReadOnlyList<EndpointSnapshotOccurrence> Match(
        IReadOnlyList<WindowsRawEndpoint> beforeOwnerCollection,
        IReadOnlyList<WindowsRawEndpoint> afterOwnerCollection)
    {
        ArgumentNullException.ThrowIfNull(beforeOwnerCollection);
        ArgumentNullException.ThrowIfNull(afterOwnerCollection);

        var remainingBefore = new Dictionary<EndpointIdentity, int>();
        foreach (var endpoint in beforeOwnerCollection)
        {
            var identity = EndpointIdentity.From(endpoint);
            remainingBefore[identity] = remainingBefore.GetValueOrDefault(identity) + 1;
        }

        var occurrences = new EndpointSnapshotOccurrence[afterOwnerCollection.Count];
        for (var index = 0; index < afterOwnerCollection.Count; index++)
        {
            var endpoint = afterOwnerCollection[index];
            var identity = EndpointIdentity.From(endpoint);
            var isStable = remainingBefore.TryGetValue(identity, out var remaining)
                && remaining > 0;

            if (isStable)
            {
                if (remaining == 1)
                {
                    remainingBefore.Remove(identity);
                }
                else
                {
                    remainingBefore[identity] = remaining - 1;
                }
            }

            occurrences[index] = new(endpoint, isStable);
        }

        return occurrences;
    }

    private readonly record struct EndpointIdentity(
        WindowsEndpointProtocol Protocol,
        AddressFamily AddressFamily,
        string LocalAddress,
        int LocalPort,
        uint ProcessId)
    {
        internal static EndpointIdentity From(WindowsRawEndpoint endpoint) => new(
            endpoint.Protocol,
            endpoint.AddressFamily,
            endpoint.LocalAddress.ToString(),
            endpoint.LocalPort,
            endpoint.ProcessId);
    }
}

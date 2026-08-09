using System.Net;
using System.Net.NetworkInformation;
using PortCVE.Collection;
using PortCVE.Domain;
using PortCVE.Platforms.Windows;

namespace PortCVE.Tests;

public sealed class EndpointSnapshotMatcherTests
{
    [Fact]
    public void Match_UsesPostOwnerSnapshotAsAuthoritative()
    {
        var disappeared = Udp("127.0.0.1", 5000, 10);
        var stable = Tcp("0.0.0.0", 6000, 20);
        var appeared = Udp("0.0.0.0", 7000, 30);

        var result = EndpointSnapshotMatcher.Match(
            [disappeared, stable],
            [stable, appeared]);

        Assert.Equal([stable, appeared], result.Select(static occurrence => occurrence.Endpoint));
        Assert.True(result[0].IsStable);
        Assert.False(result[1].IsStable);
    }

    [Fact]
    public void Match_PreservesDuplicateUdpMultiplicity()
    {
        var sharedBind = Udp("0.0.0.0", 5353, 100);

        var result = EndpointSnapshotMatcher.Match(
            [sharedBind, sharedBind],
            [sharedBind, sharedBind, sharedBind]);

        Assert.Equal(3, result.Count);
        Assert.Equal([true, true, false], result.Select(static occurrence => occurrence.IsStable));
    }

    [Fact]
    public void Match_IncludesEndpointTupleAndPidInIdentity()
    {
        var before = Udp("0.0.0.0", 5353, 100);
        var reusedTuple = Udp("0.0.0.0", 5353, 101);
        var newPortForSamePid = Udp("0.0.0.0", 5354, 100);

        var result = EndpointSnapshotMatcher.Match(
            [before],
            [reusedTuple, newPortForSamePid]);

        Assert.All(result, static occurrence => Assert.False(occurrence.IsStable));
    }

    [Fact]
    public void Match_DistinguishesIpv6ScopeIds()
    {
        var before = Udp(ScopedAddress(2), 1900, 100);
        var movedInterface = Udp(ScopedAddress(22), 1900, 100);

        var result = EndpointSnapshotMatcher.Match([before], [movedInterface]);

        Assert.False(Assert.Single(result).IsStable);
    }

    [Fact]
    public void ResolveOwnerEvidence_NewOccurrenceDoesNotReuseEarlierPidMetadata()
    {
        var collectedOwner = CompleteOwner(100);
        var owners = new Dictionary<int, OwnerEvidence> { [100] = collectedOwner };

        var stableOwner = SnapshotBuilder.ResolveOwnerEvidence(100, true, owners);
        var appearedOwner = SnapshotBuilder.ResolveOwnerEvidence(100, false, owners);

        Assert.Same(collectedOwner, stableOwner);
        Assert.NotSame(collectedOwner, appearedOwner);
        Assert.Equal(100, appearedOwner.Pid);
        Assert.Equal("pid-100", appearedOwner.ImageName);
        Assert.False(appearedOwner.IsComplete);
        Assert.Contains(
            appearedOwner.Limitations,
            static limitation => limitation.Contains("withheld", StringComparison.OrdinalIgnoreCase));
    }

    private static WindowsRawEndpoint Tcp(string address, int port, uint pid) =>
        Endpoint(WindowsEndpointProtocol.Tcp, IPAddress.Parse(address), port, pid);

    private static WindowsRawEndpoint Udp(string address, int port, uint pid) =>
        Udp(IPAddress.Parse(address), port, pid);

    private static WindowsRawEndpoint Udp(IPAddress address, int port, uint pid) =>
        Endpoint(WindowsEndpointProtocol.Udp, address, port, pid);

    private static WindowsRawEndpoint Endpoint(
        WindowsEndpointProtocol protocol,
        IPAddress address,
        int port,
        uint pid) => new(
            protocol,
            address.AddressFamily,
            address,
            port,
            pid,
            protocol == WindowsEndpointProtocol.Tcp ? TcpState.Listen : null);

    private static IPAddress ScopedAddress(long scopeId) =>
        new(IPAddress.Parse("fe80::1").GetAddressBytes(), scopeId);

    private static OwnerEvidence CompleteOwner(int pid) => new(
        pid,
        DateTimeOffset.UnixEpoch,
        "server.exe",
        "C:\\Apps\\server.exe",
        null,
        null,
        null,
        "S-1-5-18",
        null,
        [],
        false,
        true,
        []);
}

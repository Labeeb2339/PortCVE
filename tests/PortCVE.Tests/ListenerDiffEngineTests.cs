using PortCVE.Analysis;
using PortCVE.Domain;
using PortCVE.Snapshots;

namespace PortCVE.Tests;

public sealed class ListenerDiffEngineTests
{
    [Fact]
    public void CompareEvidence_ReportsContainerCollectionRegressionWithoutListenerChanges()
    {
        var before = new LockfileEvidence(
            EvidenceCompleteness.Complete,
            EvidenceCompleteness.Complete,
            EvidenceCompleteness.NotCollected,
            EvidenceCompleteness.Complete);
        var after = before with { Containers = EvidenceCompleteness.Partial };

        var change = Assert.Single(ListenerDiffEngine.CompareEvidence(before, after));

        Assert.Equal(ListenerChangeKind.EvidenceRegressed, change.Kind);
        Assert.Equal("evidence/containers", change.Key);
        Assert.Contains("Complete to Partial", change.Summary, StringComparison.Ordinal);
    }

    [Fact]
    public void Compare_IdenticalMultisets_HasNoChanges()
    {
        var item = Listener("tcp/ipv4/0.0.0.0/80", "process:web.exe", BindScope.Wildcard);

        var changes = ListenerDiffEngine.Compare([item, item], [item, item]);

        Assert.Empty(changes);
    }

    [Fact]
    public void Compare_DuplicateUdpBind_ReportsOnlyExtraInstance()
    {
        var item = Listener("udp/ipv4/0.0.0.0/5353", "process:mdns.exe", BindScope.Wildcard, TransportProtocol.Udp, 5353);

        var changes = ListenerDiffEngine.Compare([item], [item, item]);

        var change = Assert.Single(changes);
        Assert.Equal(ListenerChangeKind.Added, change.Kind);
    }

    [Fact]
    public void Compare_SameBindDifferentOwner_ReportsOwnerChanged()
    {
        var before = Listener("tcp/ipv4/0.0.0.0/8080", "process:old.exe", BindScope.Wildcard);
        var after = Listener("tcp/ipv4/0.0.0.0/8080", "process:new.exe", BindScope.Wildcard);

        var change = Assert.Single(ListenerDiffEngine.Compare([before], [after]));

        Assert.Equal(ListenerChangeKind.OwnerChanged, change.Kind);
    }

    [Fact]
    public void Compare_LoopbackToWildcard_CoalescesAsExposureExpansion()
    {
        var before = Listener("tcp/ipv4/127.0.0.1/8080", "process:web.exe", BindScope.Loopback);
        var after = Listener("tcp/ipv4/0.0.0.0/8080", "process:web.exe", BindScope.Wildcard);

        var change = Assert.Single(ListenerDiffEngine.Compare([before], [after]));

        Assert.Equal(ListenerChangeKind.ExposureExpanded, change.Kind);
        Assert.Contains("127.0.0.1", change.Summary, StringComparison.Ordinal);
        Assert.Contains("0.0.0.0", change.Summary, StringComparison.Ordinal);
    }

    [Fact]
    public void Compare_RemovedContainerMappingIsOwnerChangeWhenDockerEvidenceIsComplete()
    {
        var before = Listener("tcp/ipv4/0.0.0.0/8080", "container-image-set:old", BindScope.Wildcard) with
        {
            OwnerIdentityStrength = OwnerIdentityStrength.ContainerImage,
        };
        var after = Listener("tcp/ipv4/0.0.0.0/8080", "sha256:host-forwarder", BindScope.Wildcard) with
        {
            OwnerIdentityStrength = OwnerIdentityStrength.Sha256,
        };

        var change = Assert.Single(ListenerDiffEngine.Compare([before], [after]));

        Assert.Equal(ListenerChangeKind.OwnerChanged, change.Kind);
        Assert.Contains("container-backed", change.Summary, StringComparison.Ordinal);
    }

    [Fact]
    public void Compare_NameOnlyToShaForSameObservedProcessIsEvidenceImprovementNotOwnerChange()
    {
        var before = Listener("tcp/ipv4/0.0.0.0/8080", "process:web.exe", BindScope.Wildcard);
        var after = before with
        {
            OwnerIdentity = $"sha256:{new string('a', 64)}",
            OwnerIdentityStrength = OwnerIdentityStrength.Sha256,
            ObservedOwnerNameIdentity = "process:web.exe",
        };

        var change = Assert.Single(ListenerDiffEngine.Compare([before], [after]));

        Assert.Equal(ListenerChangeKind.EvidenceImproved, change.Kind);
        Assert.DoesNotContain("owner changed", change.Summary, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Compare_NameOnlyToShaForDifferentObservedProcessIsOwnerChange()
    {
        var before = Listener("tcp/ipv4/0.0.0.0/8080", "process:web.exe", BindScope.Wildcard);
        var after = before with
        {
            OwnerIdentity = $"sha256:{new string('a', 64)}",
            OwnerIdentityStrength = OwnerIdentityStrength.Sha256,
            ObservedOwnerNameIdentity = "process:other.exe",
        };

        var change = Assert.Single(ListenerDiffEngine.Compare([before], [after]));

        Assert.Equal(ListenerChangeKind.OwnerChanged, change.Kind);
    }

    [Fact]
    public void Compare_ShaToNameOnlyRemainsEvidenceRegression()
    {
        var before = Listener("tcp/ipv4/0.0.0.0/8080", $"sha256:{new string('a', 64)}", BindScope.Wildcard) with
        {
            OwnerIdentityStrength = OwnerIdentityStrength.Sha256,
        };
        var after = Listener("tcp/ipv4/0.0.0.0/8080", "process:web.exe", BindScope.Wildcard);

        var change = Assert.Single(ListenerDiffEngine.Compare([before], [after]));

        Assert.Equal(ListenerChangeKind.EvidenceRegressed, change.Kind);
    }

    [Fact]
    public void Compare_NameOnlyToContainerIdentityRemainsOwnerChange()
    {
        var before = Listener("tcp/ipv4/0.0.0.0/8080", "process:docker.exe", BindScope.Wildcard);
        var after = before with
        {
            OwnerIdentity = "container-image-set:digest",
            OwnerIdentityStrength = OwnerIdentityStrength.ContainerImage,
            ObservedOwnerNameIdentity = "process:docker.exe",
        };

        var change = Assert.Single(ListenerDiffEngine.Compare([before], [after]));

        Assert.Equal(ListenerChangeKind.OwnerChanged, change.Kind);
        Assert.Contains("container-backed", change.Summary, StringComparison.Ordinal);
    }

    [Fact]
    public void Compare_NameOnlyToShaWithNarrowerScopeDoesNotBecomeRemoveAndAdd()
    {
        var before = Listener("tcp/ipv4/0.0.0.0/8080", "process:web.exe", BindScope.Wildcard);
        var after = Listener("tcp/ipv4/127.0.0.1/8080", $"sha256:{new string('a', 64)}", BindScope.Loopback) with
        {
            OwnerIdentityStrength = OwnerIdentityStrength.Sha256,
            ObservedOwnerNameIdentity = "process:web.exe",
        };

        var change = Assert.Single(ListenerDiffEngine.Compare([before], [after]));

        Assert.Equal(ListenerChangeKind.ExposureNarrowed, change.Kind);
    }

    private static LockedListener Listener(
        string key,
        string owner,
        BindScope scope,
        TransportProtocol protocol = TransportProtocol.Tcp,
        int port = 8080) => new(
            key,
            protocol,
            IpFamily.Ipv4,
            key.Contains("127.0.0.1", StringComparison.Ordinal) ? "127.0.0.1" : "0.0.0.0",
            port,
            scope,
            owner,
            OwnerIdentityStrength.NameOnly,
            Confidence.Low,
            FirewallVerdict.NotEvaluated);
}

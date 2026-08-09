using BindWitness.Domain;
using BindWitness.Output;
using BindWitness.Snapshots;

namespace BindWitness.Tests;

public sealed class LockfileServiceTests
{
    [Fact]
    public void Create_IsNormalizedSortedAndOmitsRuntimeIdentity()
    {
        var snapshot = Snapshot(
            Listener("udp/ipv4/0.0.0.0/5353", 5353, 900, "mdns.exe"),
            Listener("tcp/ipv4/127.0.0.1/80", 80, 901, "web.exe"));

        var result = new LockfileService().Create(snapshot);
        var json = JsonOutput.Serialize(result);

        Assert.Equal("tcp/ipv4/loopback/80", result.Listeners[0].Key);
        Assert.Equal("udp/ipv4/any/5353", result.Listeners[1].Key);
        Assert.DoesNotContain("created_at", json, StringComparison.Ordinal);
        Assert.DoesNotContain("\"pid\"", json, StringComparison.Ordinal);
        Assert.DoesNotContain("command", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("900", json, StringComparison.Ordinal);
    }

    [Fact]
    public void Create_SameObservedListeners_ProducesSameNormalizedModel()
    {
        var first = new LockfileService().Create(Snapshot(Listener("tcp/ipv4/0.0.0.0/443", 443, 100, "server.exe")));
        var second = new LockfileService().Create(Snapshot(Listener("tcp/ipv4/0.0.0.0/443", 443, 999, "server.exe")));

        Assert.Equal(JsonOutput.Serialize(first), JsonOutput.Serialize(second));
    }

    [Fact]
    public async Task WriteAsync_RejectsUnsupportedSelectorBeforeCreatingFile()
    {
        var service = new LockfileService();
        var lockfile = service.Create(Snapshot(Listener("tcp/ipv4/0.0.0.0/443", 443, 100, "server.exe"))) with
        {
            Selector = new(null, null, "server.exe", null),
        };
        var path = Path.Combine(Path.GetTempPath(), $"bindwitness-invalid-{Guid.NewGuid():N}.lock.json");

        await Assert.ThrowsAsync<InvalidDataException>(() =>
            service.WriteAsync(path, lockfile, overwrite: false, CancellationToken.None));
        Assert.False(File.Exists(path));
    }

    [Fact]
    public void Create_ContainerPublicationUsesStableImageIdentityAndCompleteness()
    {
        var listener = Listener("tcp/ipv4/0.0.0.0/8080", 8080, 100, "docker-backend.exe") with
        {
            ContainerExposures =
            [
                new(
                    "docker",
                    "ephemeral-container-id",
                    "web",
                    "example/web:1.0",
                    $"sha256:{new string('b', 64)}",
                    "0.0.0.0",
                    8080,
                    80,
                    TransportProtocol.Tcp,
                    Confidence.Medium,
                    []),
            ],
        };
        var snapshot = Snapshot(listener) with
        {
            Collectors = [new("docker", CollectorStatus.Complete, DateTimeOffset.UnixEpoch, 1, [])],
        };

        var result = new LockfileService().Create(
            snapshot,
            includesContainerEvidence: true);

        var locked = Assert.Single(result.Listeners);
        Assert.Equal(OwnerIdentityStrength.ContainerImage, locked.OwnerIdentityStrength);
        Assert.StartsWith("container-image-set:", locked.OwnerIdentity, StringComparison.Ordinal);
        Assert.DoesNotContain("ephemeral-container-id", locked.OwnerIdentity, StringComparison.Ordinal);
        Assert.Equal(EvidenceCompleteness.Complete, result.Evidence.Containers);
    }

    [Fact]
    public void Create_ExpectedContainerEvidenceIsPartialWhenDockerCollectionDegrades()
    {
        var snapshot = Snapshot(Listener("tcp/ipv4/0.0.0.0/8080", 8080, 100, "docker-backend.exe")) with
        {
            Collectors = [new("docker", CollectorStatus.Unavailable, DateTimeOffset.UnixEpoch, 1, [])],
        };

        var result = new LockfileService().Create(
            snapshot,
            includesContainerEvidence: true);

        Assert.Equal(EvidenceCompleteness.Partial, result.Evidence.Containers);
        Assert.False(result.IsComplete);
    }

    private static SystemSnapshot Snapshot(params ListenerEvidence[] listeners) => new(
        SystemSnapshot.CurrentSchemaVersion,
        "test",
        DateTimeOffset.UnixEpoch,
        10,
        "Windows",
        [],
        [],
        listeners,
        []);

    private static ListenerEvidence Listener(string key, int port, int pid, string image) => new(
        key,
        key.StartsWith("tcp", StringComparison.Ordinal) ? TransportProtocol.Tcp : TransportProtocol.Udp,
        IpFamily.Ipv4,
        key.Contains("127.0.0.1", StringComparison.Ordinal) ? "127.0.0.1" : "0.0.0.0",
        port,
        "BOUND",
        key.Contains("127.0.0.1", StringComparison.Ordinal) ? BindScope.Loopback : BindScope.Wildcard,
        "test",
        new(pid, DateTimeOffset.UnixEpoch, image, $"C:\\Program Files\\{image}", null, null, null, "S-1", "TEST\\user", [], false, true, []),
        [],
        HostPolicyEvidence.NotEvaluated,
        [],
        []);
}

using System.Text.Json.Nodes;
using PortCVE.Domain;
using PortCVE.Output;
using PortCVE.Snapshots;

namespace PortCVE.Tests;

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

        Assert.Equal("portcve/test", result.CreatedBy);
        Assert.Equal("tcp/ipv4/loopback/80", result.Listeners[0].Key);
        Assert.Equal("udp/ipv4/any/5353", result.Listeners[1].Key);
        Assert.DoesNotContain("created_at", json, StringComparison.Ordinal);
        Assert.DoesNotContain("\"pid\"", json, StringComparison.Ordinal);
        Assert.DoesNotContain("command", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("900", json, StringComparison.Ordinal);
        Assert.DoesNotContain("allow_weak_owner", json, StringComparison.Ordinal);
    }

    [Fact]
    public void Create_ExplicitWeakOwnerPolicyAcceptsNameOnlyWithoutRelabelingEvidence()
    {
        var result = new LockfileService().Create(
            Snapshot(Listener("tcp/ipv4/0.0.0.0/443", 443, 100, "server.exe")),
            allowWeakOwner: true);

        var listener = Assert.Single(result.Listeners);
        Assert.Equal(OwnerIdentityStrength.NameOnly, listener.OwnerIdentityStrength);
        Assert.Equal(EvidenceCompleteness.Partial, result.Evidence.Ownership);
        Assert.True(result.AllowWeakOwner);
        Assert.True(result.HasSufficientOwnerEvidence);
        Assert.True(result.IsComplete);
        Assert.Contains("\"allow_weak_owner\": true", JsonOutput.Serialize(result), StringComparison.Ordinal);
    }

    [Fact]
    public void Create_ExplicitWeakOwnerPolicyNeverAcceptsUnknownOwner()
    {
        var listener = Listener("tcp/ipv4/0.0.0.0/443", 443, 100, "server.exe") with
        {
            Owner = Listener("tcp/ipv4/0.0.0.0/443", 443, 100, "server.exe").Owner with
            {
                ImageName = "pid-100",
                ImagePath = null,
                IsComplete = false,
            },
        };

        var result = new LockfileService().Create(
            Snapshot(listener),
            allowWeakOwner: true);

        Assert.Equal(OwnerIdentityStrength.Unknown, Assert.Single(result.Listeners).OwnerIdentityStrength);
        Assert.False(result.HasSufficientOwnerEvidence);
        Assert.False(result.IsComplete);
    }

    [Fact]
    public void WeakOwnerPolicyRejectsMixedUnknownAndHandAuthoredPartialWithoutNameOnly()
    {
        var weak = Listener("tcp/ipv4/0.0.0.0/443", 443, 100, "server.exe");
        var unknown = Listener("tcp/ipv4/0.0.0.0/8443", 8443, 101, "server.exe") with
        {
            Owner = weak.Owner with
            {
                Pid = 101,
                ImageName = "pid-101",
                ImagePath = null,
                IsComplete = false,
            },
        };
        var mixed = new LockfileService().Create(
            Snapshot(weak, unknown),
            allowWeakOwner: true);

        Assert.Contains(mixed.Listeners, listener => listener.OwnerIdentityStrength == OwnerIdentityStrength.NameOnly);
        Assert.Contains(mixed.Listeners, listener => listener.OwnerIdentityStrength == OwnerIdentityStrength.Unknown);
        Assert.False(mixed.HasSufficientOwnerEvidence);
        Assert.False(mixed.IsComplete);

        var strong = new LockfileService().Create(Snapshot(weak with
        {
            Owner = weak.Owner with { ImageSha256 = new string('a', 64) },
        }), allowWeakOwner: true);
        var handAuthoredPartial = strong with
        {
            Evidence = strong.Evidence with { Ownership = EvidenceCompleteness.Partial },
        };

        Assert.False(handAuthoredPartial.HasSufficientOwnerEvidence);
        Assert.False(handAuthoredPartial.IsComplete);
    }

    [Fact]
    public async Task ReadAsync_LegacyWeakLockWithoutPolicyRemainsIncomplete()
    {
        var service = new LockfileService();
        var path = Path.Combine(Path.GetTempPath(), $"portcve-legacy-weak-{Guid.NewGuid():N}.lock.json");
        try
        {
            var lockfile = service.Create(
                Snapshot(Listener("tcp/ipv4/0.0.0.0/443", 443, 100, "server.exe")),
                allowWeakOwner: true);
            await service.WriteAsync(path, lockfile, overwrite: false, CancellationToken.None);
            var document = JsonNode.Parse(await File.ReadAllTextAsync(path))!.AsObject();
            Assert.True(document.Remove("allow_weak_owner"));
            await File.WriteAllTextAsync(path, document.ToJsonString(LockfileService.SerializerOptions));

            var legacy = await service.ReadAsync(path, CancellationToken.None);

            Assert.False(legacy.AllowWeakOwner);
            Assert.Equal(EvidenceCompleteness.Partial, legacy.Evidence.Ownership);
            Assert.False(legacy.IsComplete);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task ReadAsync_RejectsInputAboveByteLimit()
    {
        var path = Path.Combine(Path.GetTempPath(), $"portcve-oversized-{Guid.NewGuid():N}.lock.json");
        try
        {
            await File.WriteAllBytesAsync(path, new byte[LockfileService.MaximumLockfileBytes + 1]);

            var error = await Assert.ThrowsAsync<InvalidDataException>(() =>
                new LockfileService().ReadAsync(path, CancellationToken.None));

            Assert.Contains("16 MiB", error.Message, StringComparison.Ordinal);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task WriteAsync_RejectsListenerCountAboveLimitBeforeCreatingFile()
    {
        var service = new LockfileService();
        var template = service.Create(
            Snapshot(Listener("tcp/ipv4/0.0.0.0/443", 443, 100, "server.exe"))).Listeners[0];
        var lockfile = service.Create(Snapshot()) with
        {
            Listeners = Enumerable.Repeat(template, LockfileService.MaximumListenerCount + 1).ToArray(),
        };
        var path = Path.Combine(Path.GetTempPath(), $"portcve-too-many-{Guid.NewGuid():N}.lock.json");

        var error = await Assert.ThrowsAsync<InvalidDataException>(() =>
            service.WriteAsync(path, lockfile, overwrite: false, CancellationToken.None));

        Assert.Contains("50,000 listeners", error.Message, StringComparison.Ordinal);
        Assert.False(File.Exists(path));
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
        var path = Path.Combine(Path.GetTempPath(), $"portcve-invalid-{Guid.NewGuid():N}.lock.json");

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

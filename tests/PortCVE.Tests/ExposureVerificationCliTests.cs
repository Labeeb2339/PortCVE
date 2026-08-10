using PortCVE.Cli;
using PortCVE.Collection;
using PortCVE.Domain;
using PortCVE.Snapshots;

namespace PortCVE.Tests;

public sealed class ExposureVerificationCliTests
{
    [Fact]
    public async Task VerifyJson_CorrelatesMappedPortAndRedactsTarget()
    {
        var nmapPath = await WriteNmapAsync("192.0.2.10", 443, "open");
        try
        {
            var builder = new FixedSnapshotBuilder(Snapshot(CollectorStatus.Complete));
            var application = new CliApplication(builder, new LockfileService());
            using var output = new StringWriter();
            using var error = new StringWriter();

            var exitCode = await application.RunAsync(
                new(
                    CommandKind.Verify,
                    InputPath: nmapPath,
                    Json: true,
                    IncludeFirewall: true,
                    Strict: true,
                    VerifyTarget: "192.0.2.10",
                    Vantage: "internet",
                    PortMappings: "tcp/443=tcp/8443"),
                output,
                error,
                CancellationToken.None);

            Assert.Equal(ExitCodes.Success, exitCode);
            Assert.Contains("\"correlation\": \"correlated_open\"", output.ToString(), StringComparison.Ordinal);
            Assert.Contains("\"imported_target\": \"target-1\"", output.ToString(), StringComparison.Ordinal);
            Assert.Contains("\"external_port\": 443", output.ToString(), StringComparison.Ordinal);
            Assert.Contains("\"local_port\": 8443", output.ToString(), StringComparison.Ordinal);
            Assert.DoesNotContain("192.0.2.10", output.ToString(), StringComparison.Ordinal);
            Assert.DoesNotContain("0.0.0.0", output.ToString(), StringComparison.Ordinal);
            Assert.DoesNotContain(new string('a', 64), output.ToString(), StringComparison.Ordinal);
            Assert.Equal(1, builder.CollectionCount);
        }
        finally
        {
            File.Delete(nmapPath);
        }
    }

    [Fact]
    public async Task VerifyMissingTarget_ReturnsUsageWithoutCollectingHostEvidence()
    {
        var nmapPath = await WriteNmapAsync("192.0.2.10", 443, "open");
        try
        {
            var builder = new FixedSnapshotBuilder(Snapshot(CollectorStatus.Complete));
            var application = new CliApplication(builder, new LockfileService());
            using var output = new StringWriter();
            using var error = new StringWriter();

            var exitCode = await application.RunAsync(
                new(
                    CommandKind.Verify,
                    InputPath: nmapPath,
                    VerifyTarget: "192.0.2.99"),
                output,
                error,
                CancellationToken.None);

            Assert.Equal(ExitCodes.UsageOrSchema, exitCode);
            Assert.Equal(0, builder.CollectionCount);
            Assert.Contains("not found", error.ToString(), StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            File.Delete(nmapPath);
        }
    }

    [Fact]
    public async Task VerifyStrict_PartialOwnerEvidenceReturnsIncomplete()
    {
        var nmapPath = await WriteNmapAsync("192.0.2.10", 443, "open");
        try
        {
            var application = new CliApplication(
                new FixedSnapshotBuilder(Snapshot(CollectorStatus.Partial)),
                new LockfileService());
            using var output = new StringWriter();
            using var error = new StringWriter();

            var exitCode = await application.RunAsync(
                new(
                    CommandKind.Verify,
                    InputPath: nmapPath,
                    IncludeFirewall: true,
                    Strict: true,
                    VerifyTarget: "192.0.2.10",
                    PortMappings: "tcp/443=tcp/8443"),
                output,
                error,
                CancellationToken.None);

            Assert.Equal(ExitCodes.IncompleteEvidence, exitCode);
            Assert.Contains("Evidence complete no", output.ToString(), StringComparison.Ordinal);
        }
        finally
        {
            File.Delete(nmapPath);
        }
    }

    [Fact]
    public async Task VerifyOutput_CannotReplaceSourceEvidenceEvenWithForce()
    {
        var nmapPath = await WriteNmapAsync("192.0.2.10", 443, "open");
        try
        {
            var original = await File.ReadAllTextAsync(nmapPath);
            var builder = new FixedSnapshotBuilder(Snapshot(CollectorStatus.Complete));
            var application = new CliApplication(builder, new LockfileService());
            using var output = new StringWriter();
            using var error = new StringWriter();

            var exitCode = await application.RunAsync(
                new(
                    CommandKind.Verify,
                    InputPath: nmapPath,
                    OutputPath: nmapPath,
                    Force: true,
                    VerifyTarget: "192.0.2.10"),
                output,
                error,
                CancellationToken.None);

            Assert.Equal(ExitCodes.UsageOrSchema, exitCode);
            Assert.Equal(0, builder.CollectionCount);
            Assert.Equal(original, await File.ReadAllTextAsync(nmapPath));
            Assert.Contains("must not replace", error.ToString(), StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            File.Delete(nmapPath);
        }
    }

    private static async Task<string> WriteNmapAsync(string address, int port, string state)
    {
        var path = Path.Combine(Path.GetTempPath(), $"portcve-verify-{Guid.NewGuid():N}.xml");
        var xml = $"""
            <nmaprun version="7.98">
              <host>
                <address addr="{address}" addrtype="ipv4" />
                <hostnames><hostname name="fixture.example" /></hostnames>
                <ports>
                  <port protocol="tcp" portid="{port}">
                    <state state="{state}" reason="syn-ack" />
                    <service name="https" product="fixture" version="1.0" method="probed" conf="10" />
                  </port>
                </ports>
              </host>
              <runstats><finished exit="success" /></runstats>
            </nmaprun>
            """;
        await File.WriteAllTextAsync(path, xml);
        return path;
    }

    private static SystemSnapshot Snapshot(CollectorStatus ownerStatus)
    {
        var ownerDiagnostic = ownerStatus == CollectorStatus.Complete
            ? Array.Empty<CollectorDiagnostic>()
            : [new("process_owners", ownerStatus, "fixture_partial", "Fixture owner evidence is partial.")];
        var listener = new ListenerEvidence(
            "tcp/ipv4/0.0.0.0/8443",
            TransportProtocol.Tcp,
            IpFamily.Ipv4,
            "0.0.0.0",
            8443,
            "LISTEN",
            BindScope.Wildcard,
            "all IPv4 interfaces",
            new(
                42,
                DateTimeOffset.UnixEpoch,
                "fixture.exe",
                "C:\\Apps\\fixture.exe",
                ownerStatus == CollectorStatus.Complete ? new string('a', 64) : null,
                null,
                null,
                null,
                null,
                [],
                false,
                ownerStatus == CollectorStatus.Complete,
                []),
            [],
            new(FirewallVerdict.Allow, Confidence.High, "Fixture allow.", [], []),
            [],
            []);
        return new(
            SystemSnapshot.CurrentSchemaVersion,
            "test",
            DateTimeOffset.UnixEpoch,
            1,
            "Windows",
            [
                new("sockets", CollectorStatus.Complete, DateTimeOffset.UnixEpoch, 1, []),
                new("process_owners", ownerStatus, DateTimeOffset.UnixEpoch, 1, ownerDiagnostic),
                new("interfaces", CollectorStatus.Complete, DateTimeOffset.UnixEpoch, 1, []),
                new("windows_firewall", CollectorStatus.Complete, DateTimeOffset.UnixEpoch, 1, []),
                new("docker", CollectorStatus.Unavailable, DateTimeOffset.UnixEpoch, 1, []),
            ],
            [],
            [listener],
            ownerDiagnostic);
    }

    private sealed class FixedSnapshotBuilder(SystemSnapshot snapshot) : ISnapshotBuilder
    {
        internal int CollectionCount { get; private set; }

        public Task<SystemSnapshot> CollectAsync(SnapshotOptions options, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            CollectionCount++;
            Assert.True(options.HashBinaries);
            return Task.FromResult(snapshot);
        }
    }
}

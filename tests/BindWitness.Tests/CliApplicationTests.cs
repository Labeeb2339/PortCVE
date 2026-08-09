using BindWitness.Cli;
using BindWitness.Collection;
using BindWitness.Domain;
using BindWitness.Snapshots;

namespace BindWitness.Tests;

public sealed class CliApplicationTests
{
    [Fact]
    public async Task CheckStrict_IncompleteCollectorNeverPrintsPass()
    {
        var snapshot = IncompleteSnapshot();
        var lockfileService = new LockfileService();
        var baseline = lockfileService.Create(snapshot);
        var path = Path.Combine(Path.GetTempPath(), $"bindwitness-check-{Guid.NewGuid():N}.lock.json");
        try
        {
            await lockfileService.WriteAsync(path, baseline, overwrite: false, CancellationToken.None);
            var application = new CliApplication(new FixedSnapshotBuilder(snapshot), lockfileService);
            using var output = new StringWriter();
            using var error = new StringWriter();

            var exitCode = await application.RunAsync(
                new(CommandKind.Check, InputPath: path, Strict: true),
                output,
                error,
                CancellationToken.None);

            Assert.Equal(ExitCodes.IncompleteEvidence, exitCode);
            Assert.Contains("INCOMPLETE", output.ToString(), StringComparison.Ordinal);
            Assert.DoesNotContain("PASS", output.ToString(), StringComparison.Ordinal);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Theory]
    [InlineData(CommandKind.Doctor)]
    [InlineData(CommandKind.Watch)]
    public async Task StrictCommands_StopOnIncompleteInitialEvidence(CommandKind command)
    {
        var application = new CliApplication(
            new FixedSnapshotBuilder(IncompleteSnapshot()),
            new LockfileService());
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await application.RunAsync(
            new(command, Strict: true, Interval: TimeSpan.FromMilliseconds(250), Iterations: 1),
            output,
            error,
            CancellationToken.None);

        Assert.Equal(ExitCodes.IncompleteEvidence, exitCode);
    }

    [Fact]
    public async Task DoctorStrict_DockerUnavailableDoesNotMakeCoreEvidenceIncomplete()
    {
        var baseSnapshot = IncompleteSnapshot();
        var snapshot = baseSnapshot with
        {
            Collectors =
            [
                new("sockets", CollectorStatus.Complete, DateTimeOffset.UnixEpoch, 1, []),
                new("process_owners", CollectorStatus.Complete, DateTimeOffset.UnixEpoch, 1, []),
                new("interfaces", CollectorStatus.Complete, DateTimeOffset.UnixEpoch, 1, []),
                new("docker", CollectorStatus.Unavailable, DateTimeOffset.UnixEpoch, 1, []),
            ],
            Diagnostics = [],
        };
        var application = new CliApplication(new FixedSnapshotBuilder(snapshot), new LockfileService());
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await application.RunAsync(
            new(CommandKind.Doctor, Strict: true),
            output,
            error,
            CancellationToken.None);

        Assert.Equal(ExitCodes.Success, exitCode);
    }

    [Theory]
    [InlineData(false, ExitCodes.Success)]
    [InlineData(true, ExitCodes.IncompleteEvidence)]
    public async Task Diff_ReportsRequiredContainerEvidenceRegression(
        bool strict,
        int expectedExitCode)
    {
        var baselineSnapshot = EmptySnapshot(CollectorStatus.Complete);
        var currentSnapshot = EmptySnapshot(CollectorStatus.Unavailable);
        var lockfileService = new LockfileService();
        var baseline = lockfileService.Create(
            baselineSnapshot,
            includesContainerEvidence: true);
        var path = Path.Combine(Path.GetTempPath(), $"bindwitness-diff-{Guid.NewGuid():N}.lock.json");
        try
        {
            await lockfileService.WriteAsync(path, baseline, overwrite: false, CancellationToken.None);
            var application = new CliApplication(new FixedSnapshotBuilder(currentSnapshot), lockfileService);
            using var output = new StringWriter();
            using var error = new StringWriter();

            var exitCode = await application.RunAsync(
                new(CommandKind.Diff, InputPath: path, Json: true, Strict: strict),
                output,
                error,
                CancellationToken.None);

            Assert.Equal(expectedExitCode, exitCode);
            Assert.Contains("evidence/containers", output.ToString(), StringComparison.Ordinal);
            Assert.Contains("evidence_regressed", output.ToString(), StringComparison.Ordinal);
            Assert.DoesNotContain("No listener drift", output.ToString(), StringComparison.Ordinal);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(true, true)]
    public async Task DoctorJson_PrivateDiagnosticDetailsRequireExplicitOptIn(
        bool includePrivate,
        bool expectsSecret)
    {
        const string secret = "C:\\Users\\SecretUser\\private-tool.exe";
        var diagnostic = new CollectorDiagnostic(
            "process_owners",
            CollectorStatus.Partial,
            "fixture_partial",
            secret);
        var baseSnapshot = IncompleteSnapshot();
        var snapshot = baseSnapshot with
        {
            Collectors = baseSnapshot.Collectors.Select(report =>
                report.Name == "process_owners"
                    ? report with { Diagnostics = [diagnostic] }
                    : report).ToArray(),
            Diagnostics = [diagnostic],
        };
        var application = new CliApplication(new FixedSnapshotBuilder(snapshot), new LockfileService());
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await application.RunAsync(
            new(CommandKind.Doctor, Json: true, IncludePrivate: includePrivate),
            output,
            error,
            CancellationToken.None);

        Assert.Equal(ExitCodes.Success, exitCode);
        Assert.Equal(expectsSecret, output.ToString().Contains("SecretUser", StringComparison.Ordinal));
        Assert.Contains("\"schema_version\": 1", output.ToString(), StringComparison.Ordinal);
    }

    private static SystemSnapshot IncompleteSnapshot()
    {
        var listener = new ListenerEvidence(
            "tcp/ipv4/0.0.0.0/445",
            TransportProtocol.Tcp,
            IpFamily.Ipv4,
            "0.0.0.0",
            445,
            "LISTEN",
            BindScope.Wildcard,
            "all IPv4 interfaces",
            new(
                4,
                DateTimeOffset.UnixEpoch,
                "System",
                null,
                null,
                null,
                null,
                "S-1-5-18",
                null,
                [],
                false,
                true,
                []),
            [],
            HostPolicyEvidence.NotEvaluated,
            [],
            []);
        var diagnostic = new CollectorDiagnostic(
            "process_owners",
            CollectorStatus.Partial,
            "fixture_partial",
            "Fixture owner collector is intentionally partial.");
        return new(
            1,
            "test",
            DateTimeOffset.UnixEpoch,
            1,
            "Windows",
            [
                new("sockets", CollectorStatus.Complete, DateTimeOffset.UnixEpoch, 1, []),
                new("process_owners", CollectorStatus.Partial, DateTimeOffset.UnixEpoch, 1, [diagnostic]),
                new("interfaces", CollectorStatus.Complete, DateTimeOffset.UnixEpoch, 1, []),
            ],
            [],
            [listener],
            [diagnostic]);
    }

    private static SystemSnapshot EmptySnapshot(CollectorStatus dockerStatus) => new(
        1,
        "test",
        DateTimeOffset.UnixEpoch,
        1,
        "Windows",
        [
            new("sockets", CollectorStatus.Complete, DateTimeOffset.UnixEpoch, 1, []),
            new("process_owners", CollectorStatus.Complete, DateTimeOffset.UnixEpoch, 1, []),
            new("interfaces", CollectorStatus.Complete, DateTimeOffset.UnixEpoch, 1, []),
            new("docker", dockerStatus, DateTimeOffset.UnixEpoch, 1, []),
        ],
        [],
        [],
        []);

    private sealed class FixedSnapshotBuilder(SystemSnapshot snapshot) : ISnapshotBuilder
    {
        public Task<SystemSnapshot> CollectAsync(SnapshotOptions options, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(snapshot);
        }
    }
}

using PortCVE.Cli;
using PortCVE.Collection;
using PortCVE.Domain;
using PortCVE.Snapshots;

namespace PortCVE.Tests;

public sealed class CliApplicationTests
{
    [Fact]
    public async Task Help_UsesPortCVEProductAndCommandNames()
    {
        var application = new CliApplication(
            new FixedSnapshotBuilder(EmptySnapshot(CollectorStatus.Unavailable)),
            new LockfileService());
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await application.RunAsync(
            new(CommandKind.Help),
            output,
            error,
            CancellationToken.None);

        Assert.Equal(ExitCodes.Success, exitCode);
        Assert.Contains("PortCVE explains local ports", output.ToString(), StringComparison.Ordinal);
        Assert.Contains("portcve 8080", output.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task CheckStrict_IncompleteCollectorNeverPrintsPass()
    {
        var snapshot = IncompleteSnapshot();
        var lockfileService = new LockfileService();
        var baseline = lockfileService.Create(snapshot);
        var path = Path.Combine(Path.GetTempPath(), $"portcve-check-{Guid.NewGuid():N}.lock.json");
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

    [Fact]
    public async Task LockAndCheckStrict_ExplicitWeakOwnerPolicyAcceptsStableProcessName()
    {
        var snapshot = OwnerSnapshot("agent.exe", imageSha256: null, CollectorStatus.Partial);
        var service = new LockfileService();
        var path = Path.Combine(Path.GetTempPath(), $"portcve-weak-owner-{Guid.NewGuid():N}.lock.json");
        try
        {
            var application = new CliApplication(new FixedSnapshotBuilder(snapshot), service);
            using var lockOutput = new StringWriter();
            using var lockError = new StringWriter();

            var lockExit = await application.RunAsync(
                new(
                    CommandKind.Lock,
                    OutputPath: path,
                    Strict: true,
                    AllowWeakOwner: true),
                lockOutput,
                lockError,
                CancellationToken.None);

            Assert.Equal(ExitCodes.Success, lockExit);
            var baseline = await service.ReadAsync(path, CancellationToken.None);
            Assert.True(baseline.AllowWeakOwner);
            Assert.Equal(EvidenceCompleteness.Partial, baseline.Evidence.Ownership);
            Assert.True(baseline.IsComplete);

            using var checkOutput = new StringWriter();
            using var checkError = new StringWriter();
            var checkExit = await application.RunAsync(
                new(CommandKind.Check, InputPath: path, Strict: true),
                checkOutput,
                checkError,
                CancellationToken.None);

            Assert.Equal(ExitCodes.Success, checkExit);
            Assert.Contains("PASS", checkOutput.ToString(), StringComparison.Ordinal);
            Assert.Contains("stored policy accepts process-name identity", checkOutput.ToString(), StringComparison.Ordinal);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task Check_WeakOwnerPolicyRejectsUnknownCurrentOwnerAsIncomplete()
    {
        var result = await RunWeakOwnerCheckAsync(
            OwnerSnapshot("pid-100", imageSha256: null, CollectorStatus.Partial));

        Assert.Equal(ExitCodes.IncompleteEvidence, result.ExitCode);
        Assert.Contains("INCOMPLETE", result.Output, StringComparison.Ordinal);
        Assert.DoesNotContain("PASS", result.Output, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Check_WeakOwnerPolicyFailsChangedProcessName()
    {
        var result = await RunWeakOwnerCheckAsync(
            OwnerSnapshot("other.exe", imageSha256: null, CollectorStatus.Partial));

        Assert.Equal(ExitCodes.NegativeResult, result.ExitCode);
        Assert.Contains("ownerchanged", result.Output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("FAIL", result.Output, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Check_NameOnlyBaselineToShaForSameProcessPassesWithoutUpgradingBaseline()
    {
        var result = await RunWeakOwnerCheckAsync(
            OwnerSnapshot("agent.exe", new string('a', 64), CollectorStatus.Complete));

        Assert.Equal(ExitCodes.Success, result.ExitCode);
        Assert.Contains("evidenceimproved", result.Output, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("ownerchanged", result.Output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("PASS", result.Output, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Check_ShaBaselineToNameOnlyRemainsIncompleteEvenWhenPolicyAllowsWeakOwners()
    {
        var service = new LockfileService();
        var baseline = service.Create(
            OwnerSnapshot("agent.exe", new string('a', 64), CollectorStatus.Complete),
            allowWeakOwner: true);
        var path = Path.Combine(Path.GetTempPath(), $"portcve-strong-owner-{Guid.NewGuid():N}.lock.json");
        try
        {
            await service.WriteAsync(path, baseline, overwrite: false, CancellationToken.None);
            var application = new CliApplication(
                new FixedSnapshotBuilder(OwnerSnapshot("agent.exe", imageSha256: null, CollectorStatus.Partial)),
                service);
            using var output = new StringWriter();
            using var error = new StringWriter();

            var exitCode = await application.RunAsync(
                new(CommandKind.Check, InputPath: path, Json: true, Strict: true),
                output,
                error,
                CancellationToken.None);

            Assert.Equal(ExitCodes.IncompleteEvidence, exitCode);
            Assert.Contains("\"allow_weak_owner\": true", output.ToString(), StringComparison.Ordinal);
            Assert.Contains("evidence_regressed", output.ToString(), StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task Check_OversizedLockfileReturnsStableUsageError()
    {
        var path = Path.Combine(Path.GetTempPath(), $"portcve-oversized-cli-{Guid.NewGuid():N}.lock.json");
        try
        {
            await File.WriteAllBytesAsync(path, new byte[LockfileService.MaximumLockfileBytes + 1]);
            var application = new CliApplication(
                new FixedSnapshotBuilder(EmptySnapshot(CollectorStatus.Unavailable)),
                new LockfileService());
            using var output = new StringWriter();
            using var error = new StringWriter();

            var exitCode = await application.RunAsync(
                new(CommandKind.Check, InputPath: path),
                output,
                error,
                CancellationToken.None);

            Assert.Equal(ExitCodes.UsageOrSchema, exitCode);
            Assert.Contains("16 MiB", error.ToString(), StringComparison.Ordinal);
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
            includesContainerEvidence: true,
            allowWeakOwner: true);
        var path = Path.Combine(Path.GetTempPath(), $"portcve-diff-{Guid.NewGuid():N}.lock.json");
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

    private static SystemSnapshot OwnerSnapshot(
        string imageName,
        string? imageSha256,
        CollectorStatus ownerStatus)
    {
        var limitation = ownerStatus == CollectorStatus.Complete
            ? Array.Empty<string>()
            : ["Only process-name owner identity was available."];
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
                100,
                DateTimeOffset.UnixEpoch,
                imageName,
                imageSha256 is null ? null : $"C:\\Apps\\{imageName}",
                imageSha256,
                null,
                null,
                null,
                null,
                [],
                false,
                ownerStatus == CollectorStatus.Complete,
                limitation),
            [],
            HostPolicyEvidence.NotEvaluated,
            [],
            limitation);
        var diagnostics = ownerStatus == CollectorStatus.Complete
            ? Array.Empty<CollectorDiagnostic>()
            : [new("process_owners", ownerStatus, "owner_name_only", "Only process-name owner identity was available.")];
        return new(
            1,
            "test",
            DateTimeOffset.UnixEpoch,
            1,
            "Windows",
            [
                new("sockets", CollectorStatus.Complete, DateTimeOffset.UnixEpoch, 1, []),
                new("process_owners", ownerStatus, DateTimeOffset.UnixEpoch, 1, diagnostics),
                new("interfaces", CollectorStatus.Complete, DateTimeOffset.UnixEpoch, 1, []),
                new("docker", CollectorStatus.Unavailable, DateTimeOffset.UnixEpoch, 1, []),
            ],
            [],
            [listener],
            diagnostics);
    }

    private static async Task<(int ExitCode, string Output)> RunWeakOwnerCheckAsync(
        SystemSnapshot currentSnapshot)
    {
        var service = new LockfileService();
        var baseline = service.Create(
            OwnerSnapshot("agent.exe", imageSha256: null, CollectorStatus.Partial),
            allowWeakOwner: true);
        var path = Path.Combine(Path.GetTempPath(), $"portcve-weak-check-{Guid.NewGuid():N}.lock.json");
        try
        {
            await service.WriteAsync(path, baseline, overwrite: false, CancellationToken.None);
            var application = new CliApplication(new FixedSnapshotBuilder(currentSnapshot), service);
            using var output = new StringWriter();
            using var error = new StringWriter();
            var exitCode = await application.RunAsync(
                new(CommandKind.Check, InputPath: path, Strict: true),
                output,
                error,
                CancellationToken.None);
            return (exitCode, output.ToString());
        }
        finally
        {
            File.Delete(path);
        }
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

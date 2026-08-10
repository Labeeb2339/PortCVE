using PortCVE.Vulnerabilities;

namespace PortCVE.Tests;

public sealed class TrivyDatabaseServiceTests
{
    private static readonly DateTimeOffset Now = new(2026, 8, 10, 2, 0, 0, TimeSpan.Zero);

    [Fact]
    public async Task Status_IsOfflineAndReportsExecutableVersionSchemaAndFreshness()
    {
        using var fixture = new DatabaseFixture(Now.AddHours(-2));
        var runner = new RecordingProcessRunner((index, invocation) => index == 0
            ? VersionSuccess()
            : ValidationSuccess(invocation));
        var service = fixture.Service(runner);

        var status = await service.GetStatusAsync(CancellationToken.None);

        Assert.Equal(TrivyDatabaseState.Ready, status.State);
        Assert.True(status.Ready);
        Assert.False(status.NetworkRequested);
        Assert.Equal(Path.GetFullPath(fixture.Executable), status.ExecutablePath);
        Assert.Equal("0.73.0", status.EngineVersion);
        Assert.Equal(Path.GetFullPath(fixture.Cache), status.CacheDirectory);
        Assert.Equal(2, status.DatabaseSchemaVersion);
        Assert.Equal(Now.AddHours(-2), status.DatabaseUpdatedAt);
        Assert.Equal(7200, status.DatabaseAgeSeconds);
        Assert.Equal((long)TimeSpan.FromHours(72).TotalSeconds, status.MaximumDatabaseAgeSeconds);
        Assert.Equal(2, runner.Invocations.Count);
        var version = runner.Invocations[0];
        Assert.Equal(["--version"], version.Arguments);
        Assert.Equal("true", version.EnvironmentVariablesToSet!["TRIVY_SKIP_DB_UPDATE"]);
        Assert.Equal("true", version.EnvironmentVariablesToSet["TRIVY_OFFLINE_SCAN"]);
        Assert.Contains("TRIVY_", version.EnvironmentVariablePrefixesToRemove!);
        Assert.Contains("AWS_", version.EnvironmentVariablePrefixesToRemove!);
        Assert.Contains("GITHUB_TOKEN", version.EnvironmentVariablesToRemove!);
        var validation = runner.Invocations[1];
        Assert.Equal("filesystem", validation.Arguments[0]);
        AssertFlag(validation.Arguments, "--scanners", "vuln");
        AssertFlag(validation.Arguments, "--format", "json");
        AssertFlag(validation.Arguments, "--cache-dir", Path.GetFullPath(fixture.Cache));
        Assert.Contains("--skip-db-update", validation.Arguments);
        Assert.Contains("--offline-scan", validation.Arguments);
        Assert.Contains("--disable-telemetry", validation.Arguments);
        Assert.Equal("true", validation.EnvironmentVariablesToSet!["TRIVY_SKIP_DB_UPDATE"]);
        Assert.Equal("true", validation.EnvironmentVariablesToSet["TRIVY_OFFLINE_SCAN"]);
    }

    [Fact]
    public async Task Status_StaleDatabaseFailsClosedWithoutDownloading()
    {
        using var fixture = new DatabaseFixture(Now.AddHours(-73));
        var runner = new RecordingProcessRunner((_, _) =>
            VersionSuccess());

        var status = await fixture.Service(runner).GetStatusAsync(CancellationToken.None);

        Assert.Equal(TrivyDatabaseState.Stale, status.State);
        Assert.False(status.Ready);
        Assert.Equal("vulnerability_db_stale", status.Code);
        Assert.False(status.NetworkRequested);
        Assert.Single(runner.Invocations);
    }

    [Fact]
    public async Task Status_InvalidMetadataSchemaFailsClosed()
    {
        using var fixture = new DatabaseFixture(Now.AddHours(-1));
        File.WriteAllText(
            Path.Combine(fixture.Cache, "db", "metadata.json"),
            $"{{\"UpdatedAt\":\"{Now.AddHours(-1):O}\"}}");
        var runner = new RecordingProcessRunner((_, _) =>
            VersionSuccess());

        var status = await fixture.Service(runner).GetStatusAsync(CancellationToken.None);

        Assert.Equal(TrivyDatabaseState.Invalid, status.State);
        Assert.Equal("vulnerability_db_invalid", status.Code);
    }

    [Fact]
    public async Task Update_IsTheOnlyOperationThatUsesDownloadDbOnlyAndVerifiesResult()
    {
        using var fixture = new DatabaseFixture(updatedAt: null);
        var runner = new RecordingProcessRunner((index, invocation) =>
        {
            if (index == 0)
            {
                return VersionSuccess();
            }

            if (index == 1)
            {
                fixture.WriteDatabase(Now.AddMinutes(-1));
                return new(true, 0, string.Empty, string.Empty, 20);
            }

            return ValidationSuccess(invocation);
        });

        var status = await fixture.Service(runner).UpdateAsync(CancellationToken.None);

        Assert.Equal(TrivyDatabaseState.Ready, status.State);
        Assert.True(status.Ready);
        Assert.True(status.NetworkRequested);
        Assert.Equal(3, runner.Invocations.Count);
        var update = runner.Invocations[1];
        Assert.Equal(Path.GetFullPath(fixture.Executable), update.FileName);
        Assert.Equal("image", update.Arguments[0]);
        Assert.Contains("--download-db-only", update.Arguments);
        AssertFlag(update.Arguments, "--cache-dir", Path.GetFullPath(fixture.Cache));
        AssertFlag(update.Arguments, "--timeout", "30s");
        Assert.Contains("--skip-java-db-update", update.Arguments);
        Assert.Contains("--skip-check-update", update.Arguments);
        Assert.Contains("--skip-vex-repo-update", update.Arguments);
        Assert.Contains("--skip-version-check", update.Arguments);
        Assert.Contains("--disable-telemetry", update.Arguments);
        Assert.Contains("--no-progress", update.Arguments);
        Assert.DoesNotContain("--skip-db-update", update.Arguments);
        Assert.DoesNotContain("--offline-scan", update.Arguments);
        Assert.False(update.EnvironmentVariablesToSet!.ContainsKey("TRIVY_SKIP_DB_UPDATE"));
        Assert.False(update.EnvironmentVariablesToSet.ContainsKey("TRIVY_OFFLINE_SCAN"));
        Assert.Contains("HTTP_PROXY", update.EnvironmentVariablesToRemove!);
        Assert.Contains("DOCKER_", update.EnvironmentVariablePrefixesToRemove!);
    }

    [Theory]
    [InlineData(true, false, "trivy_update_timeout")]
    [InlineData(false, true, "trivy_update_output_too_large")]
    public async Task Update_BoundedProcessFailuresDoNotRepublishScannerOutput(
        bool timedOut,
        bool outputLimitExceeded,
        string expectedCode)
    {
        using var fixture = new DatabaseFixture(updatedAt: null);
        const string secret = "registry-token-should-never-appear";
        var runner = new RecordingProcessRunner((index, _) => index == 0
            ? VersionSuccess()
            : new(
                true,
                null,
                secret,
                secret,
                20,
                TimedOut: timedOut,
                OutputLimitExceeded: outputLimitExceeded));

        var status = await fixture.Service(runner).UpdateAsync(CancellationToken.None);

        Assert.Equal(TrivyDatabaseState.Failed, status.State);
        Assert.Equal(expectedCode, status.Code);
        Assert.DoesNotContain(secret, status.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain(secret, status.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task UnsafeCacheIsRejectedBeforeLaunchingTrivy()
    {
        using var fixture = new DatabaseFixture(Now.AddHours(-1));
        var runner = new RecordingProcessRunner((_, _) =>
            throw new InvalidOperationException("The process runner must not be reached."));
        var service = new TrivyDatabaseService(
            fixture.Executable,
            fixture.Cache,
            runner,
            new FixedTimeProvider(Now),
            TimeSpan.FromSeconds(30),
            fixture.TempRoot,
            cachePathValidator: _ => new(false, null, "local_path_reparse", "Rejected."));

        var status = await service.UpdateAsync(CancellationToken.None);

        Assert.Equal(TrivyDatabaseState.Invalid, status.State);
        Assert.Equal("trivy_cache_unsafe", status.Code);
        Assert.Empty(runner.Invocations);
    }

    [Fact]
    public void ExecutableLocatorRejectsRelativeConfiguredPaths()
    {
        var validation = TrivyDatabaseService.LocateExecutable("tools\\trivy.exe");

        Assert.False(validation.IsValid);
        Assert.Equal("trivy_executable_invalid", validation.Code);
    }

    [Fact]
    public async Task InvocationTempDirectoryExistsDuringCallsAndIsRemovedAfterward()
    {
        using var fixture = new DatabaseFixture(Now.AddHours(-1));
        string? invocationTemp = null;
        var runner = new RecordingProcessRunner((index, invocation) =>
        {
            invocationTemp = invocation.EnvironmentVariablesToSet!["TEMP"];
            Assert.True(Directory.Exists(invocationTemp));
            return index == 0 ? VersionSuccess() : ValidationSuccess(invocation);
        });

        var status = await fixture.Service(runner).GetStatusAsync(CancellationToken.None);

        Assert.True(status.Ready);
        Assert.NotNull(invocationTemp);
        Assert.False(Directory.Exists(invocationTemp));
    }

    [Theory]
    [InlineData(1, 0x41)]
    [InlineData(3, 0x00)]
    [InlineData(4096, 0xa5)]
    public async Task Status_CorruptTruncatedOrRandomDatabaseFailsOfflineEngineValidation(
        int byteCount,
        int value)
    {
        using var fixture = new DatabaseFixture(Now.AddHours(-1));
        File.WriteAllBytes(
            Path.Combine(fixture.Cache, "db", "trivy.db"),
            Enumerable.Repeat((byte)value, byteCount).ToArray());
        const string hostileOutput = "path=C:\\private\\cache token=secret";
        var runner = new RecordingProcessRunner((index, _) => index == 0
            ? VersionSuccess()
            : new(true, 1, hostileOutput, hostileOutput, 5));

        var status = await fixture.Service(runner).GetStatusAsync(CancellationToken.None);

        Assert.Equal(TrivyDatabaseState.Invalid, status.State);
        Assert.False(status.Ready);
        Assert.Equal("vulnerability_db_unreadable", status.Code);
        Assert.DoesNotContain(hostileOutput, status.ToString(), StringComparison.Ordinal);
        Assert.Equal(2, runner.Invocations.Count);
    }

    [Fact]
    public async Task Status_ExitZeroWithMalformedValidationReportStillFailsClosed()
    {
        using var fixture = new DatabaseFixture(Now.AddHours(-1));
        var runner = new RecordingProcessRunner((index, _) => index == 0
            ? VersionSuccess()
            : new(true, 0, "{\"SchemaVersion\":2}", string.Empty, 5));

        var status = await fixture.Service(runner).GetStatusAsync(CancellationToken.None);

        Assert.Equal(TrivyDatabaseState.Invalid, status.State);
        Assert.False(status.Ready);
        Assert.Equal("trivy_database_validation_output_invalid", status.Code);
    }

    private static ProcessExecutionResult VersionSuccess() =>
        new(true, 0, "Version: 0.73.0\n", string.Empty, 4);

    private static ProcessExecutionResult ValidationSuccess(ProcessInvocation invocation)
    {
        var target = invocation.Arguments[^1];
        Assert.True(Directory.Exists(target));
        Assert.Empty(Directory.EnumerateFileSystemEntries(target));
        return new(
            true,
            0,
            "{\"SchemaVersion\":2,\"Trivy\":{\"Version\":\"0.73.0\"},\"ArtifactType\":\"filesystem\"}",
            string.Empty,
            5);
    }

    private static void AssertFlag(IReadOnlyList<string> arguments, string flag, string expectedValue)
    {
        var index = arguments.IndexOf(flag);
        Assert.True(index >= 0 && index + 1 < arguments.Count, $"Missing flag {flag}.");
        Assert.Equal(expectedValue, arguments[index + 1]);
    }

    private sealed class DatabaseFixture : IDisposable
    {
        private readonly string root = Path.Combine(Path.GetTempPath(), $"portcve-db-test-{Guid.NewGuid():N}");

        public DatabaseFixture(DateTimeOffset? updatedAt)
        {
            Cache = Path.Combine(root, "cache");
            TempRoot = Path.Combine(root, "temp");
            Executable = Path.Combine(root, "tools", "trivy.exe");
            Directory.CreateDirectory(Path.GetDirectoryName(Executable)!);
            File.WriteAllBytes(Executable, [0x4d, 0x5a]);
            if (updatedAt is not null)
            {
                WriteDatabase(updatedAt.Value);
            }
        }

        public string Cache { get; }

        public string Executable { get; }

        public string TempRoot { get; }

        public TrivyDatabaseService Service(IProcessRunner runner) => new(
            Executable,
            Cache,
            runner,
            new FixedTimeProvider(Now),
            TimeSpan.FromSeconds(30),
            TempRoot);

        public void WriteDatabase(DateTimeOffset updatedAt)
        {
            var database = Path.Combine(Cache, "db");
            Directory.CreateDirectory(database);
            File.WriteAllText(
                Path.Combine(database, "metadata.json"),
                $"{{\"Version\":2,\"UpdatedAt\":\"{updatedAt:O}\",\"NextUpdate\":\"{updatedAt.AddHours(6):O}\"}}");
            File.WriteAllBytes(Path.Combine(database, "trivy.db"), [1, 2, 3]);
        }

        public void Dispose()
        {
            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
        }
    }

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }

    private sealed class RecordingProcessRunner(
        Func<int, ProcessInvocation, ProcessExecutionResult> resultFactory) : IProcessRunner
    {
        public List<ProcessInvocation> Invocations { get; } = [];

        public Task<ProcessExecutionResult> RunAsync(
            ProcessInvocation invocation,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var index = Invocations.Count;
            Invocations.Add(invocation);
            return Task.FromResult(resultFactory(index, invocation));
        }
    }
}

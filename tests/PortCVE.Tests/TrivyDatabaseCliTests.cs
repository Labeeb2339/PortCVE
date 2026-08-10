using PortCVE.Cli;
using PortCVE.Vulnerabilities;
using System.Text.Json;

namespace PortCVE.Tests;

public sealed class TrivyDatabaseCliTests
{
    [Theory]
    [InlineData(CommandKind.DbStatus, false)]
    [InlineData(CommandKind.DbUpdate, true)]
    public async Task DatabaseJson_ReducesPathsByDefaultAndEmitsStableContract(
        CommandKind command,
        bool update)
    {
        var operation = update ? TrivyDatabaseOperation.Update : TrivyDatabaseOperation.Status;
        var service = new FixedDatabaseService(Ready(operation));
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await new CliApplication(service).RunAsync(
            new(command, Json: true),
            output,
            error,
            CancellationToken.None);

        Assert.Equal(ExitCodes.Success, exitCode);
        Assert.Equal(command == CommandKind.DbStatus ? 1 : 0, service.StatusCalls);
        Assert.Equal(command == CommandKind.DbUpdate ? 1 : 0, service.UpdateCalls);
        using var document = JsonDocument.Parse(output.ToString());
        var root = document.RootElement;
        Assert.Equal(1, root.GetProperty("schema_version").GetInt32());
        Assert.False(string.IsNullOrWhiteSpace(root.GetProperty("tool_version").GetString()));
        Assert.Equal("reduced", root.GetProperty("privacy_mode").GetString());
        Assert.Equal(TrivyDatabaseDocumentRedactor.ExecutableAlias,
            root.GetProperty("executable_path").GetString());
        Assert.Equal(TrivyDatabaseDocumentRedactor.CacheAlias,
            root.GetProperty("cache_directory").GetString());
        Assert.Equal(2, root.GetProperty("database_schema_version").GetInt32());
        Assert.Equal(update, root.GetProperty("network_requested").GetBoolean());
        Assert.DoesNotContain("C:\\Tools", output.ToString(), StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("C:\\Cache", output.ToString(), StringComparison.OrdinalIgnoreCase);
        Assert.Empty(error.ToString());
    }

    [Theory]
    [InlineData(CommandKind.DbStatus, false)]
    [InlineData(CommandKind.DbUpdate, true)]
    public async Task DatabasePrivateJson_RetainsExactPathsConsistently(
        CommandKind command,
        bool update)
    {
        var operation = update ? TrivyDatabaseOperation.Update : TrivyDatabaseOperation.Status;
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await new CliApplication(new FixedDatabaseService(Ready(operation))).RunAsync(
            new(command, Json: true, IncludePrivate: true),
            output,
            error,
            CancellationToken.None);

        Assert.Equal(ExitCodes.Success, exitCode);
        using var document = JsonDocument.Parse(output.ToString());
        var root = document.RootElement;
        Assert.Equal("private", root.GetProperty("privacy_mode").GetString());
        Assert.Equal("C:\\Tools\\trivy.exe", root.GetProperty("executable_path").GetString());
        Assert.Equal("C:\\Cache\\trivy", root.GetProperty("cache_directory").GetString());
        Assert.Empty(error.ToString());
    }

    [Fact]
    public async Task DatabaseReducedJson_RemovesExactPathsFromMessages()
    {
        var status = Ready(TrivyDatabaseOperation.Status) with
        {
            Message = "Executable C:\\Tools\\trivy.exe uses cache C:\\Cache\\trivy.",
        };
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await new CliApplication(new FixedDatabaseService(status)).RunAsync(
            new(CommandKind.DbStatus, Json: true),
            output,
            error,
            CancellationToken.None);

        Assert.Equal(ExitCodes.Success, exitCode);
        Assert.DoesNotContain("C:\\Tools", output.ToString(), StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("C:\\Cache", output.ToString(), StringComparison.OrdinalIgnoreCase);
        Assert.Contains(TrivyDatabaseDocumentRedactor.ExecutableAlias, output.ToString(), StringComparison.Ordinal);
        Assert.Contains(TrivyDatabaseDocumentRedactor.CacheAlias, output.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task DatabaseStatus_StaleEvidenceReturnsIncomplete()
    {
        var stale = Ready(TrivyDatabaseOperation.Status) with
        {
            State = TrivyDatabaseState.Stale,
            Ready = false,
            Code = "vulnerability_db_stale",
            Message = "The local database is stale.",
        };
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await new CliApplication(new FixedDatabaseService(stale)).RunAsync(
            new(CommandKind.DbStatus),
            output,
            error,
            CancellationToken.None);

        Assert.Equal(ExitCodes.IncompleteEvidence, exitCode);
        Assert.Contains("State            stale", output.ToString(), StringComparison.Ordinal);
        Assert.Contains("vulnerability_db_stale", error.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task DatabaseUpdate_UsesExplicitUpdatePathAndRuntimeFailureExitCode()
    {
        var failed = Ready(TrivyDatabaseOperation.Update) with
        {
            State = TrivyDatabaseState.Failed,
            Ready = false,
            NetworkRequested = true,
            Code = "trivy_update_failed",
            Message = "The update failed.",
        };
        var service = new FixedDatabaseService(failed);
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await new CliApplication(service).RunAsync(
            new(CommandKind.DbUpdate),
            output,
            error,
            CancellationToken.None);

        Assert.Equal(ExitCodes.RuntimeFailure, exitCode);
        Assert.Equal(0, service.StatusCalls);
        Assert.Equal(1, service.UpdateCalls);
        Assert.Contains("Network requested yes", output.ToString(), StringComparison.Ordinal);
        Assert.Contains("trivy_update_failed", error.ToString(), StringComparison.Ordinal);
    }

    private static TrivyDatabaseStatus Ready(TrivyDatabaseOperation operation) => new(
        1,
        "trivy",
        operation,
        TrivyDatabaseState.Ready,
        true,
        operation == TrivyDatabaseOperation.Update,
        "C:\\Tools\\trivy.exe",
        "0.73.0",
        "C:\\Cache\\trivy",
        2,
        DateTimeOffset.UnixEpoch,
        DateTimeOffset.UnixEpoch.AddHours(6),
        60,
        (long)TimeSpan.FromHours(72).TotalSeconds,
        5,
        "ok",
        "Ready.");

    private sealed class FixedDatabaseService(TrivyDatabaseStatus result) : ITrivyDatabaseService
    {
        public int StatusCalls { get; private set; }

        public int UpdateCalls { get; private set; }

        public Task<TrivyDatabaseStatus> GetStatusAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            StatusCalls++;
            return Task.FromResult(result);
        }

        public Task<TrivyDatabaseStatus> UpdateAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            UpdateCalls++;
            return Task.FromResult(result);
        }
    }
}

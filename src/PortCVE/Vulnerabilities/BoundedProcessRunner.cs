using System.ComponentModel;
using System.Diagnostics;
using System.Text;

namespace PortCVE.Vulnerabilities;

internal sealed record ProcessInvocation(
    string FileName,
    IReadOnlyList<string> Arguments,
    TimeSpan Timeout,
    int MaximumStandardOutputCharacters,
    int MaximumStandardErrorCharacters,
    IReadOnlyList<string>? EnvironmentVariablesToRemove = null,
    IReadOnlyDictionary<string, string?>? EnvironmentVariablesToSet = null);

internal sealed record ProcessExecutionResult(
    bool Started,
    int? ExitCode,
    string StandardOutput,
    string StandardError,
    long DurationMs,
    bool TimedOut = false,
    bool OutputLimitExceeded = false,
    string? StartError = null);

internal interface IProcessRunner
{
    Task<ProcessExecutionResult> RunAsync(
        ProcessInvocation invocation,
        CancellationToken cancellationToken);
}

internal sealed class BoundedProcessRunner : IProcessRunner
{
    public async Task<ProcessExecutionResult> RunAsync(
        ProcessInvocation invocation,
        CancellationToken cancellationToken)
    {
        var startedAt = Stopwatch.StartNew();
        using var process = new Process
        {
            StartInfo = CreateStartInfo(invocation),
            EnableRaisingEvents = true,
        };

        try
        {
            if (!process.Start())
            {
                return new(false, null, string.Empty, string.Empty, startedAt.ElapsedMilliseconds,
                    StartError: "The scanner process did not start.");
            }
        }
        catch (Exception exception) when (exception is Win32Exception or InvalidOperationException)
        {
            return new(false, null, string.Empty, string.Empty, startedAt.ElapsedMilliseconds,
                StartError: exception.Message);
        }

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(invocation.Timeout);
        var standardOutputTask = ReadBoundedAsync(
            process.StandardOutput,
            invocation.MaximumStandardOutputCharacters,
            timeout.Token);
        var standardErrorTask = ReadBoundedAsync(
            process.StandardError,
            invocation.MaximumStandardErrorCharacters,
            timeout.Token);
        var readersTask = Task.WhenAll(standardOutputTask, standardErrorTask);
        var exitTask = process.WaitForExitAsync(timeout.Token);

        try
        {
            var first = await Task.WhenAny(exitTask, readersTask);
            if (first == readersTask && readersTask.IsFaulted)
            {
                await readersTask;
            }

            await exitTask;
            var streams = await readersTask;
            return new(
                true,
                process.ExitCode,
                streams[0],
                streams[1],
                startedAt.ElapsedMilliseconds);
        }
        catch (OutputLimitExceededException)
        {
            KillProcessTree(process);
            await WaitAfterKillAsync(process);
            return new(
                true,
                process.HasExited ? process.ExitCode : null,
                string.Empty,
                string.Empty,
                startedAt.ElapsedMilliseconds,
                OutputLimitExceeded: true);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            KillProcessTree(process);
            await WaitAfterKillAsync(process);
            return new(
                true,
                process.HasExited ? process.ExitCode : null,
                string.Empty,
                string.Empty,
                startedAt.ElapsedMilliseconds,
                TimedOut: true);
        }
        catch (OperationCanceledException)
        {
            KillProcessTree(process);
            await WaitAfterKillAsync(process);
            throw;
        }
    }

    internal static ProcessStartInfo CreateStartInfo(ProcessInvocation invocation)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = invocation.FileName,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
            WorkingDirectory = Environment.SystemDirectory,
        };
        foreach (var argument in invocation.Arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        foreach (var name in invocation.EnvironmentVariablesToRemove ?? [])
        {
            startInfo.Environment.Remove(name);
        }

        foreach (var item in invocation.EnvironmentVariablesToSet
            ?? new Dictionary<string, string?>())
        {
            startInfo.Environment[item.Key] = item.Value;
        }

        return startInfo;
    }

    private static async Task<string> ReadBoundedAsync(
        StreamReader reader,
        int maximumCharacters,
        CancellationToken cancellationToken)
    {
        var result = new StringBuilder(Math.Min(maximumCharacters, 16 * 1024));
        var buffer = new char[8192];
        while (true)
        {
            var read = await reader.ReadAsync(buffer.AsMemory(), cancellationToken);
            if (read == 0)
            {
                return result.ToString();
            }

            if (result.Length + read > maximumCharacters)
            {
                throw new OutputLimitExceededException();
            }

            result.Append(buffer, 0, read);
        }
    }

    private static void KillProcessTree(Process process)
    {
        try
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
            }
        }
        catch (InvalidOperationException)
        {
        }
        catch (Win32Exception)
        {
        }
    }

    private static async Task WaitAfterKillAsync(Process process)
    {
        try
        {
            await process.WaitForExitAsync(CancellationToken.None);
        }
        catch (InvalidOperationException)
        {
        }
    }

    private sealed class OutputLimitExceededException : Exception;
}

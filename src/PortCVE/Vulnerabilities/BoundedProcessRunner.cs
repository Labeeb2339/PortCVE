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
    IReadOnlyDictionary<string, string?>? EnvironmentVariablesToSet = null,
    IReadOnlyList<string>? EnvironmentVariablePrefixesToRemove = null);

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
    private static readonly TimeSpan DefaultPostKillGrace = TimeSpan.FromSeconds(2);
    private readonly TimeSpan postKillGrace;

    public BoundedProcessRunner()
        : this(DefaultPostKillGrace)
    {
    }

    internal BoundedProcessRunner(TimeSpan postKillGrace)
    {
        if (postKillGrace <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(postKillGrace));
        }

        this.postKillGrace = postKillGrace;
    }

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
            await WaitAfterKillAsync(process, postKillGrace);
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
            await WaitAfterKillAsync(process, postKillGrace);
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
            await WaitAfterKillAsync(process, postKillGrace);
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

        ApplyEnvironmentPolicy(startInfo.Environment, invocation);
        return startInfo;
    }

    internal static void ApplyEnvironmentPolicy(
        IDictionary<string, string?> environment,
        ProcessInvocation invocation)
    {
        foreach (var name in invocation.EnvironmentVariablesToRemove ?? [])
        {
            environment.Remove(name);
        }

        foreach (var prefix in invocation.EnvironmentVariablePrefixesToRemove ?? [])
        {
            foreach (var name in environment.Keys
                .Where(name => name.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                .ToArray())
            {
                environment.Remove(name);
            }
        }

        foreach (var item in invocation.EnvironmentVariablesToSet
            ?? new Dictionary<string, string?>())
        {
            environment[item.Key] = item.Value;
        }
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

    private static Task<bool> WaitAfterKillAsync(Process process, TimeSpan grace) =>
        WaitWithGraceAsync(token => process.WaitForExitAsync(token), grace);

    internal static async Task<bool> WaitWithGraceAsync(
        Func<CancellationToken, Task> waitAsync,
        TimeSpan grace)
    {
        using var cancellation = new CancellationTokenSource();
        Task waitTask;
        try
        {
            waitTask = waitAsync(cancellation.Token);
        }
        catch (InvalidOperationException)
        {
            return true;
        }

        var delayTask = Task.Delay(grace);
        if (await Task.WhenAny(waitTask, delayTask) != waitTask)
        {
            cancellation.Cancel();
            _ = waitTask.ContinueWith(
                static task => _ = task.Exception,
                CancellationToken.None,
                TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously,
                TaskScheduler.Default);
            return false;
        }

        try
        {
            await waitTask;
        }
        catch (OperationCanceledException)
        {
        }
        catch (InvalidOperationException)
        {
        }

        return true;
    }

    private sealed class OutputLimitExceededException : Exception;
}

using System.Diagnostics;

namespace BindWitness.Collection;

public sealed record PowerShellResult(
    bool Succeeded,
    string StandardOutput,
    string StandardError,
    int? ExitCode,
    bool TimedOut);

public static class PowerShellJsonRunner
{
    public static async Task<PowerShellResult> RunAsync(
        string script,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(script);

        using var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = "powershell.exe",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
            },
        };

        process.StartInfo.ArgumentList.Add("-NoLogo");
        process.StartInfo.ArgumentList.Add("-NoProfile");
        process.StartInfo.ArgumentList.Add("-NonInteractive");
        process.StartInfo.ArgumentList.Add("-Command");
        process.StartInfo.ArgumentList.Add(script);

        try
        {
            if (!process.Start())
            {
                return new(false, string.Empty, "PowerShell did not start.", null, false);
            }

            var outputTask = process.StandardOutput.ReadToEndAsync(cancellationToken);
            var errorTask = process.StandardError.ReadToEndAsync(cancellationToken);
            using var timeoutSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeoutSource.CancelAfter(timeout);

            try
            {
                await process.WaitForExitAsync(timeoutSource.Token);
            }
            catch (OperationCanceledException)
            {
                TryTerminate(process);
                await WaitForTerminationAsync(process);
                if (cancellationToken.IsCancellationRequested)
                {
                    throw new OperationCanceledException(cancellationToken);
                }

                return new(false, string.Empty, "PowerShell collection timed out.", null, true);
            }

            var output = await outputTask;
            var error = await errorTask;
            return new(process.ExitCode == 0, output.Trim(), error.Trim(), process.ExitCode, false);
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            return new(false, string.Empty, exception.Message, null, false);
        }
    }

    private static void TryTerminate(Process process)
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
        catch (System.ComponentModel.Win32Exception)
        {
        }
    }

    private static async Task WaitForTerminationAsync(Process process)
    {
        try
        {
            using var source = new CancellationTokenSource(TimeSpan.FromSeconds(2));
            await process.WaitForExitAsync(source.Token);
        }
        catch (OperationCanceledException)
        {
        }
        catch (InvalidOperationException)
        {
        }
    }
}

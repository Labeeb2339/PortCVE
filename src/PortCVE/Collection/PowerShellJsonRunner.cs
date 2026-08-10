using System.Diagnostics;
using System.Text;
using PortCVE.Vulnerabilities;

namespace PortCVE.Collection;

public sealed record PowerShellResult(
    bool Succeeded,
    string StandardOutput,
    string StandardError,
    int? ExitCode,
    bool TimedOut);

internal enum TrustedWindowsPowerShellModule
{
    NetConnection,
    NetSecurity,
}

public static class PowerShellJsonRunner
{
    internal static async Task<PowerShellResult> RunAsync(
        string script,
        TimeSpan timeout,
        CancellationToken cancellationToken,
        params TrustedWindowsPowerShellModule[] trustedModules)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(script);

        var systemDirectory = ResolveWindowsSystemDirectory();
        var executableValidation = ResolveWindowsPowerShellExecutable(systemDirectory);
        if (!executableValidation.IsValid)
        {
            return new(
                false,
                string.Empty,
                $"Windows PowerShell could not be resolved to its trusted system path: {executableValidation.Message}",
                null,
                false);
        }

        var moduleRootValidation = ResolveWindowsPowerShellModuleRoot(systemDirectory);
        if (!moduleRootValidation.IsValid)
        {
            return new(
                false,
                string.Empty,
                $"Windows PowerShell's trusted module root is unavailable: {moduleRootValidation.Message}",
                null,
                false);
        }

        var moduleValidations = trustedModules
            .Distinct()
            .Select(module => ResolveWindowsPowerShellModule(systemDirectory, module))
            .ToArray();
        var invalidModule = moduleValidations.FirstOrDefault(static validation => !validation.IsValid);
        if (invalidModule is not null)
        {
            return new(
                false,
                string.Empty,
                $"A required trusted Windows PowerShell module is unavailable: {invalidModule.Message}",
                null,
                false);
        }

        using var process = new Process
        {
            StartInfo = CreateStartInfo(
                executableValidation.FullPath!,
                systemDirectory!,
                moduleRootValidation.FullPath!,
                moduleValidations.Select(static validation => validation.FullPath!).ToArray(),
                script),
        };

        try
        {
            var launchValidation = LocalPathPolicy.ValidateExistingWindowsPowerShellExecutable(
                executableValidation.FullPath!);
            if (!launchValidation.IsValid
                || !string.Equals(
                    launchValidation.FullPath,
                    executableValidation.FullPath,
                    StringComparison.OrdinalIgnoreCase))
            {
                return new(
                    false,
                    string.Empty,
                    "Windows PowerShell's trusted system path changed before launch.",
                    null,
                    false);
            }

            var moduleRootLaunchValidation = ResolveWindowsPowerShellModuleRoot(systemDirectory);
            if (!moduleRootLaunchValidation.IsValid
                || !string.Equals(
                    moduleRootLaunchValidation.FullPath,
                    moduleRootValidation.FullPath,
                    StringComparison.OrdinalIgnoreCase))
            {
                return new(
                    false,
                    string.Empty,
                    "Windows PowerShell's trusted module root changed before launch.",
                    null,
                    false);
            }

            foreach (var moduleValidation in moduleValidations)
            {
                var launchModuleValidation = LocalPathPolicy.ValidateExistingWindowsPowerShellModule(
                    moduleValidation.FullPath!);
                if (!launchModuleValidation.IsValid
                    || !string.Equals(
                        launchModuleValidation.FullPath,
                        moduleValidation.FullPath,
                        StringComparison.OrdinalIgnoreCase))
                {
                    return new(
                        false,
                        string.Empty,
                        "A trusted Windows PowerShell module changed before launch.",
                        null,
                        false);
                }
            }

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

    internal static LocalPathValidation ResolveWindowsPowerShellExecutable()
    {
        return ResolveWindowsPowerShellExecutable(ResolveWindowsSystemDirectory());
    }

    internal static LocalPathValidation ResolveWindowsPowerShellExecutable(string? systemDirectory)
    {
        if (string.IsNullOrWhiteSpace(systemDirectory)
            || !Path.IsPathFullyQualified(systemDirectory))
        {
            return InvalidExecutable("The Windows system directory is not an absolute path.");
        }

        string candidate;
        try
        {
            candidate = Path.Combine(
                systemDirectory,
                "WindowsPowerShell",
                "v1.0",
                "powershell.exe");
        }
        catch (Exception exception) when (exception is ArgumentException or NotSupportedException)
        {
            return InvalidExecutable($"The Windows system directory is invalid: {exception.Message}");
        }

        return LocalPathPolicy.ValidateExistingWindowsPowerShellExecutable(candidate);
    }

    internal static LocalPathValidation ResolveWindowsPowerShellModule(
        string? systemDirectory,
        TrustedWindowsPowerShellModule module)
    {
        var rootValidation = ResolveWindowsPowerShellModuleRoot(systemDirectory);
        if (!rootValidation.IsValid)
        {
            return rootValidation;
        }

        var name = module switch
        {
            TrustedWindowsPowerShellModule.NetConnection => "NetConnection",
            TrustedWindowsPowerShellModule.NetSecurity => "NetSecurity",
            _ => throw new ArgumentOutOfRangeException(nameof(module)),
        };
        var candidate = Path.Combine(rootValidation.FullPath!, name, $"{name}.psd1");
        return LocalPathPolicy.ValidateExistingWindowsPowerShellModule(candidate);
    }

    internal static ProcessStartInfo CreateStartInfo(
        string executable,
        string systemDirectory,
        string moduleRoot,
        IReadOnlyList<string> modulePaths,
        string script)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = executable,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        ApplyLaunchPolicy(startInfo, systemDirectory, moduleRoot);
        startInfo.ArgumentList.Add("-NoLogo");
        startInfo.ArgumentList.Add("-NoProfile");
        startInfo.ArgumentList.Add("-NonInteractive");
        startInfo.ArgumentList.Add("-Command");
        startInfo.ArgumentList.Add(ComposeScript(script, modulePaths));
        return startInfo;
    }

    internal static void ApplyLaunchPolicy(
        ProcessStartInfo startInfo,
        string systemDirectory,
        string moduleRoot)
    {
        startInfo.WorkingDirectory = systemDirectory;
        ApplyEnvironmentPolicy(startInfo.Environment, systemDirectory, moduleRoot);
    }

    private static void ApplyEnvironmentPolicy(
        IDictionary<string, string?> environment,
        string systemDirectory,
        string moduleRoot)
    {
        environment["PATH"] = systemDirectory;
        environment["PSModulePath"] = moduleRoot;
    }

    private static string? ResolveWindowsSystemDirectory()
    {
        if (!OperatingSystem.IsWindows())
        {
            return null;
        }

        return Environment.GetFolderPath(Environment.SpecialFolder.System);
    }

    private static LocalPathValidation ResolveWindowsPowerShellModuleRoot(string? systemDirectory)
    {
        if (string.IsNullOrWhiteSpace(systemDirectory)
            || !Path.IsPathFullyQualified(systemDirectory))
        {
            return new(
                false,
                null,
                "powershell_module_invalid",
                "The Windows system directory is not an absolute path.");
        }

        var candidate = Path.Combine(systemDirectory, "WindowsPowerShell", "v1.0", "Modules");
        var validation = LocalPathPolicy.ValidateLocalDirectoryPath(candidate);
        if (!validation.IsValid || !Directory.Exists(validation.FullPath))
        {
            return new(
                false,
                null,
                validation.IsValid ? "powershell_module_not_found" : validation.Code,
                validation.IsValid ? "The trusted Windows PowerShell module root was not found." : validation.Message);
        }

        return validation;
    }

    private static string ComposeScript(string script, IReadOnlyList<string> modulePaths)
    {
        var securedScript = new StringBuilder();
        securedScript.AppendLine("$ErrorActionPreference = 'Stop'");
        foreach (var modulePath in modulePaths)
        {
            securedScript
                .Append("Import-Module -Name '")
                .Append(modulePath.Replace("'", "''", StringComparison.Ordinal))
                .AppendLine("' -Force -ErrorAction Stop");
        }

        securedScript.Append(script);
        return securedScript.ToString();
    }

    private static LocalPathValidation InvalidExecutable(string message) =>
        new(false, null, "powershell_executable_invalid", message);

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

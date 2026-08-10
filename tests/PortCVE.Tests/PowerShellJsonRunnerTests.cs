using PortCVE.Collection;

namespace PortCVE.Tests;

public sealed class PowerShellJsonRunnerTests
{
    [Fact]
    public void ExecutableResolution_UsesExistingAbsoluteWindowsSystemPath()
    {
        var validation = PowerShellJsonRunner.ResolveWindowsPowerShellExecutable();

        Assert.True(validation.IsValid, validation.Message);
        Assert.True(Path.IsPathFullyQualified(validation.FullPath!));
        Assert.Equal("powershell.exe", Path.GetFileName(validation.FullPath));
        Assert.StartsWith(
            Environment.GetFolderPath(Environment.SpecialFolder.System),
            validation.FullPath!,
            StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("powershell.exe")]
    [InlineData("relative\\system32")]
    [InlineData("\\\\server\\share\\system32")]
    public void ExecutableResolution_RejectsUntrustedSystemDirectory(string systemDirectory)
    {
        var validation = PowerShellJsonRunner.ResolveWindowsPowerShellExecutable(systemDirectory);

        Assert.False(validation.IsValid);
        Assert.Null(validation.FullPath);
    }

    [Fact]
    public void ExecutableResolution_RejectsMissingSystemPath()
    {
        var missing = Path.Combine(Path.GetTempPath(), $"portcve-missing-system-{Guid.NewGuid():N}");

        var validation = PowerShellJsonRunner.ResolveWindowsPowerShellExecutable(missing);

        Assert.False(validation.IsValid);
        Assert.Equal("powershell_executable_not_found", validation.Code);
    }

    [Fact]
    public void ExecutableResolution_RejectsReparseSystemPath()
    {
        var parent = Path.Combine(Path.GetTempPath(), $"portcve-powershell-link-{Guid.NewGuid():N}");
        var target = Path.Combine(parent, "target");
        var link = Path.Combine(parent, "system32");
        var executable = Path.Combine(target, "WindowsPowerShell", "v1.0", "powershell.exe");
        Directory.CreateDirectory(Path.GetDirectoryName(executable)!);
        File.WriteAllBytes(executable, []);
        Directory.CreateSymbolicLink(link, target);
        try
        {
            var validation = PowerShellJsonRunner.ResolveWindowsPowerShellExecutable(link);

            Assert.False(validation.IsValid);
            Assert.Equal("powershell_executable_reparse", validation.Code);
        }
        finally
        {
            Directory.Delete(link);
            Directory.Delete(parent, recursive: true);
        }
    }

    [Fact]
    public void ModuleResolution_RejectsReparseManifest()
    {
        var parent = Path.Combine(Path.GetTempPath(), $"portcve-module-link-{Guid.NewGuid():N}");
        var systemDirectory = Path.Combine(parent, "system32");
        var moduleDirectory = Path.Combine(
            systemDirectory,
            "WindowsPowerShell",
            "v1.0",
            "Modules",
            "NetSecurity");
        var target = Path.Combine(parent, "attacker.psd1");
        var link = Path.Combine(moduleDirectory, "NetSecurity.psd1");
        Directory.CreateDirectory(moduleDirectory);
        File.WriteAllText(target, "throw 'attacker module executed'");
        File.CreateSymbolicLink(link, target);
        try
        {
            var validation = PowerShellJsonRunner.ResolveWindowsPowerShellModule(
                systemDirectory,
                TrustedWindowsPowerShellModule.NetSecurity);

            Assert.False(validation.IsValid);
            Assert.Equal("powershell_module_reparse", validation.Code);
        }
        finally
        {
            File.Delete(link);
            Directory.Delete(parent, recursive: true);
        }
    }

    [Fact]
    public void StartInfo_PinsExecutableWorkingDirectoryModulesAndSearchPaths()
    {
        var systemDirectory = Environment.GetFolderPath(Environment.SpecialFolder.System);
        var executable = PowerShellJsonRunner.ResolveWindowsPowerShellExecutable(systemDirectory);
        var module = PowerShellJsonRunner.ResolveWindowsPowerShellModule(
            systemDirectory,
            TrustedWindowsPowerShellModule.NetSecurity);
        var moduleRoot = Path.Combine(systemDirectory, "WindowsPowerShell", "v1.0", "Modules");
        Assert.True(executable.IsValid, executable.Message);
        Assert.True(module.IsValid, module.Message);

        var startInfo = PowerShellJsonRunner.CreateStartInfo(
            executable.FullPath!,
            systemDirectory,
            moduleRoot,
            [module.FullPath!],
            "Write-Output 'safe'");

        Assert.Equal(executable.FullPath, startInfo.FileName);
        Assert.Equal(systemDirectory, startInfo.WorkingDirectory);
        Assert.False(startInfo.UseShellExecute);
        Assert.Equal(systemDirectory, startInfo.Environment["PATH"]);
        Assert.Equal(moduleRoot, startInfo.Environment["PSModulePath"]);
        Assert.DoesNotContain("Import-Module NetSecurity", startInfo.ArgumentList[^1], StringComparison.Ordinal);
        Assert.Contains(module.FullPath!, startInfo.ArgumentList[^1], StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void LaunchPolicy_ReplacesHostileWorkingDirectoryPathAndModuleSearchValues()
    {
        var startInfo = new System.Diagnostics.ProcessStartInfo
        {
            WorkingDirectory = "C:\\attacker",
        };
        startInfo.Environment["PATH"] = "C:\\attacker";
        startInfo.Environment["PSModulePath"] = "C:\\attacker\\modules";
        const string systemDirectory = "C:\\Windows\\System32";
        const string moduleRoot = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\Modules";

        PowerShellJsonRunner.ApplyLaunchPolicy(startInfo, systemDirectory, moduleRoot);

        Assert.Equal(systemDirectory, startInfo.WorkingDirectory);
        Assert.Equal(systemDirectory, startInfo.Environment["PATH"]);
        Assert.Equal(moduleRoot, startInfo.Environment["PSModulePath"]);
        Assert.DoesNotContain(
            startInfo.Environment.Values,
            static value => value?.Contains("attacker", StringComparison.OrdinalIgnoreCase) is true);
    }
}

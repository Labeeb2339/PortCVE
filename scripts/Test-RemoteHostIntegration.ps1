#requires -Version 5.1

<#
.SYNOPSIS
Runs the PortCVE remote scanner against disposable loopback-only fixtures.

.DESCRIPTION
Builds the Release PortCVE executable (unless -SkipBuild is specified), starts
SSH and HTTP fixtures on separate OS-assigned ports, then invokes scan-host
against exactly those two 127.0.0.1 ports. Discovery restraint, adaptive
safe-active identification, default redaction, private output, product parsing,
and the HTTP method allowlist are asserted.

This harness never accepts a target parameter, never requests online advisory
data, and never connects to a non-loopback address. Every child process, socket,
and temporary file is cleaned in guarded finally blocks.
#>
[CmdletBinding()]
param(
    [string]$PortCVEPath,
    [switch]$SkipBuild,
    [ValidateRange(10, 120)]
    [int]$CommandTimeoutSeconds = 30,
    [ValidateRange(30, 600)]
    [int]$BuildTimeoutSeconds = 180
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$loopbackTarget = '127.0.0.1'
$repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$projectPath = Join-Path $repositoryRoot 'src\PortCVE\PortCVE.csproj'
$defaultExecutablePath = Join-Path $repositoryRoot 'src\PortCVE\bin\Release\net10.0\win-x64\portcve.exe'
$runId = [Guid]::NewGuid().ToString('N')
$temporaryRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$temporaryPrefix = $temporaryRoot.TrimEnd(
    [IO.Path]::DirectorySeparatorChar,
    [IO.Path]::AltDirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
$integrationTempDirectory = [IO.Path]::GetFullPath((Join-Path $temporaryRoot "portcve-remote-it-$runId"))
$sshFixture = $null
$httpFixture = $null
$primaryError = $null
$cleanupErrors = [Collections.Generic.List[string]]::new()
$result = $null

if (-not $integrationTempDirectory.StartsWith($temporaryPrefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Refusing to use a remote integration directory outside '$temporaryRoot'."
}
if (Test-Path -LiteralPath $integrationTempDirectory) {
    throw "Refusing to reuse existing integration directory '$integrationTempDirectory'."
}
[void](New-Item -ItemType Directory -Path $integrationTempDirectory)

function Assert-Condition {
    param(
        [bool]$Condition,
        [string]$Message
    )

    if (-not $Condition) {
        throw "Assertion failed: $Message"
    }
}

function ConvertTo-WindowsProcessArgument {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Value)

    if ($Value.Length -gt 0 -and $Value -notmatch '[\s"]') {
        return $Value
    }

    $quoted = [Text.StringBuilder]::new()
    [void]$quoted.Append('"')
    $backslashCount = 0
    foreach ($character in $Value.ToCharArray()) {
        if ($character -eq '\') {
            $backslashCount++
            continue
        }
        if ($character -eq '"') {
            [void]$quoted.Append(('\' * (($backslashCount * 2) + 1)))
            [void]$quoted.Append('"')
            $backslashCount = 0
            continue
        }

        if ($backslashCount -gt 0) {
            [void]$quoted.Append(('\' * $backslashCount))
            $backslashCount = 0
        }
        [void]$quoted.Append($character)
    }
    if ($backslashCount -gt 0) {
        [void]$quoted.Append(('\' * ($backslashCount * 2)))
    }
    [void]$quoted.Append('"')
    return $quoted.ToString()
}

function Invoke-BoundedProcess {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,
        [Parameter(Mandatory = $true)]
        [string[]]$ArgumentList,
        [Parameter(Mandatory = $true)]
        [string]$Description,
        [Parameter(Mandatory = $true)]
        [int]$TimeoutSeconds
    )

    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $FilePath
    $startInfo.Arguments = (($ArgumentList | ForEach-Object {
                ConvertTo-WindowsProcessArgument -Value ([string]$_)
            }) -join ' ')
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    $timedOut = $false
    $stdoutTask = $null
    $stderrTask = $null
    try {
        Assert-Condition $process.Start() "$Description process did not start."
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            $timedOut = $true
            try { $process.Kill() } catch { }
            [void]$process.WaitForExit(5000)
        }
        else {
            # WaitForExit() without a timeout flushes redirected async stream state.
            $process.WaitForExit()
        }

        $stdout = $stdoutTask.GetAwaiter().GetResult()
        $stderr = $stderrTask.GetAwaiter().GetResult()

        if ($timedOut) {
            throw "$Description exceeded its $TimeoutSeconds second limit and was terminated."
        }
        $maximumCapturedCharacters = 4 * 1024 * 1024
        if ($stdout.Length -gt $maximumCapturedCharacters -or $stderr.Length -gt $maximumCapturedCharacters) {
            throw "$Description exceeded the 4 MiB per-stream capture limit."
        }
        if ($process.ExitCode -ne 0) {
            $details = (($stderr + [Environment]::NewLine + $stdout).Trim())
            if ($details.Length -gt 4000) {
                $details = $details.Substring(0, 4000) + '...'
            }
            throw "$Description failed with exit code $($process.ExitCode). $details"
        }

        return [pscustomobject]@{
            ExitCode = $process.ExitCode
            StdOut = $stdout
            StdErr = $stderr
        }
    }
    finally {
        try {
            if (-not $process.HasExited) {
                $process.Kill()
                [void]$process.WaitForExit(5000)
            }
        }
        finally {
            $process.Dispose()
        }
    }
}

function ConvertFrom-CapturedJson {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Json,
        [Parameter(Mandatory = $true)]
        [string]$Description
    )

    try {
        return $Json | ConvertFrom-Json
    }
    catch {
        throw "$Description returned invalid JSON: $($_.Exception.Message)"
    }
}

function Get-RemotePortResult {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Report,
        [Parameter(Mandatory = $true)]
        [int]$Port,
        [Parameter(Mandatory = $true)]
        [string]$Description
    )

    $matches = @($Report.hosts | ForEach-Object { $_.ports } | Where-Object { [int]$_.port -eq $Port })
    Assert-Condition ($matches.Count -eq 1) "$Description did not contain exactly one result for TCP port $Port."
    Assert-Condition ([string]$matches[0].state -ceq 'open') "$Description did not report TCP port $Port open."
    return $matches[0]
}

function Assert-Product {
    param(
        [Parameter(Mandatory = $true)]
        [object]$PortResult,
        [Parameter(Mandatory = $true)]
        [string]$Product,
        [Parameter(Mandatory = $true)]
        [string]$Version,
        [Parameter(Mandatory = $true)]
        [string]$Description
    )

    $matches = @($PortResult.product_candidates | Where-Object {
        [string]$_.product -ceq $Product -and [string]$_.version -ceq $Version
    })
    Assert-Condition ($matches.Count -ge 1) "$Description did not parse $Product $Version."
}

function Assert-NoApplicationIdentity {
    param(
        [Parameter(Mandatory = $true)]
        [object]$PortResult,
        [Parameter(Mandatory = $true)]
        [string]$Description
    )

    Assert-Condition (@($PortResult.fingerprints).Count -eq 0) `
        "$Description unexpectedly fingerprinted a silent nonstandard service."
    Assert-Condition (@($PortResult.product_candidates).Count -eq 0) `
        "$Description unexpectedly assigned a product to a silent nonstandard service."
}

function Assert-AdaptiveHttpFingerprint {
    param(
        [Parameter(Mandatory = $true)]
        [object]$PortResult,
        [Parameter(Mandatory = $true)]
        [string]$Description
    )

    $matches = @($PortResult.fingerprints | Where-Object {
        [string]$_.kind -ceq 'http' -and
        [string]$_.service -ceq 'http' -and
        [string]$_.source -ceq 'active-adaptive-http-head'
    })
    Assert-Condition ($matches.Count -eq 1) `
        "$Description did not retain exactly one adaptive HTTP fingerprint."
}

function Assert-RequestLog {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [string[]]$RequestLines,
        [Parameter(Mandatory = $true)]
        [hashtable]$ExpectedRequests,
        [Parameter(Mandatory = $true)]
        [string]$Description
    )

    $observed = @{}
    foreach ($requestLine in $RequestLines) {
        Assert-Condition ($requestLine -match '^(?<method>[A-Z]+) (?<path>\S+) HTTP/1\.[01]$') `
            "$Description recorded a malformed request line '$requestLine'."
        $method = $Matches.method
        $path = $Matches.path
        Assert-Condition ($method -in @('HEAD', 'OPTIONS')) `
            "$Description used unsafe or unexpected HTTP method '$method'."
        $key = "$method $path"
        if (-not $observed.ContainsKey($key)) { $observed[$key] = 0 }
        $observed[$key]++
    }

    Assert-Condition ($observed.Count -eq $ExpectedRequests.Count) `
        "$Description produced an unexpected set of HTTP requests: $($RequestLines -join ', ')."
    foreach ($key in $ExpectedRequests.Keys) {
        Assert-Condition ($observed.ContainsKey($key)) "$Description did not send expected request '$key'."
        Assert-Condition ($observed[$key] -eq $ExpectedRequests[$key]) `
            "$Description sent '$key' $($observed[$key]) times; expected $($ExpectedRequests[$key])."
    }
}

$fixtureSource = @'
using System;
using System.Collections.Concurrent;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace PortCVEIntegration
{
    public sealed class LoopbackFixture : IDisposable
    {
        private readonly TcpListener listener;
        private readonly string protocol;
        private readonly ConcurrentQueue<string> requestLines = new ConcurrentQueue<string>();
        private readonly Task acceptTask;
        private int stopped;
        private string error;

        private LoopbackFixture(TcpListener startedListener, string fixtureProtocol)
        {
            listener = startedListener;
            protocol = fixtureProtocol;
            acceptTask = Task.Factory.StartNew(
                AcceptLoop,
                CancellationToken.None,
                TaskCreationOptions.LongRunning,
                TaskScheduler.Default);
        }

        public int Port
        {
            get { return ((IPEndPoint)listener.LocalEndpoint).Port; }
        }

        public string Error
        {
            get { return error; }
        }

        public static LoopbackFixture StartSsh()
        {
            TcpListener candidate = new TcpListener(IPAddress.Loopback, 0);
            candidate.Start(16);
            return new LoopbackFixture(candidate, "ssh");
        }

        public static LoopbackFixture StartHttp()
        {
            TcpListener candidate = new TcpListener(IPAddress.Loopback, 0);
            candidate.Start(16);
            return new LoopbackFixture(candidate, "http");
        }

        public string[] GetRequestLines()
        {
            return requestLines.ToArray();
        }

        public void ResetRequestLines()
        {
            string ignored;
            while (requestLines.TryDequeue(out ignored)) { }
        }

        public bool Stop()
        {
            if (Interlocked.Exchange(ref stopped, 1) == 0)
            {
                try { listener.Stop(); } catch { }
            }

            try
            {
                return acceptTask.Wait(5000);
            }
            catch (AggregateException exception)
            {
                error = exception.Flatten().InnerException == null
                    ? exception.Message
                    : exception.Flatten().InnerException.Message;
                return false;
            }
        }

        public void Dispose()
        {
            Stop();
        }

        private void AcceptLoop()
        {
            while (Thread.VolatileRead(ref stopped) == 0)
            {
                TcpClient client = null;
                try
                {
                    client = listener.AcceptTcpClient();
                    HandleClient(client);
                }
                catch (SocketException exception)
                {
                    if (Thread.VolatileRead(ref stopped) == 0)
                    {
                        error = exception.Message;
                        return;
                    }
                }
                catch (ObjectDisposedException)
                {
                    if (Thread.VolatileRead(ref stopped) == 0)
                    {
                        error = "The listener was disposed unexpectedly.";
                        return;
                    }
                }
                catch (Exception exception)
                {
                    error = exception.Message;
                    return;
                }
                finally
                {
                    if (client != null) { client.Close(); }
                }
            }
        }

        private void HandleClient(TcpClient client)
        {
            client.NoDelay = true;
            client.ReceiveTimeout = 5000;
            client.SendTimeout = 5000;
            using (NetworkStream stream = client.GetStream())
            {
                if (StringComparer.Ordinal.Equals(protocol, "ssh"))
                {
                    byte[] banner = Encoding.ASCII.GetBytes("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.13\r\n");
                    stream.Write(banner, 0, banner.Length);
                    stream.Flush();
                    return;
                }

                string request = ReadHeaderBlock(stream, 16384);
                string requestLine = FirstLine(request);
                if (String.IsNullOrEmpty(requestLine))
                {
                    // Discovery and the first active connection only wait for a
                    // greeting. A silent HTTP fixture must not speak until the
                    // adaptive connection sends a bounded request.
                    return;
                }
                requestLines.Enqueue(requestLine);

                byte[] response = Encoding.ASCII.GetBytes(
                    "HTTP/1.1 200 OK\r\n" +
                    "Server: Apache/2.4.58\r\n" +
                    "Allow: HEAD, OPTIONS\r\n" +
                    "Content-Length: 0\r\n" +
                    "Connection: close\r\n\r\n");
                stream.Write(response, 0, response.Length);
                stream.Flush();
            }
        }

        private static string ReadHeaderBlock(Stream stream, int maximumBytes)
        {
            MemoryStream captured = new MemoryStream();
            try
            {
                int state = 0;
                while (captured.Length < maximumBytes)
                {
                    int value = stream.ReadByte();
                    if (value < 0) { break; }
                    captured.WriteByte((byte)value);
                    if ((state == 0 || state == 2) && value == 13) { state++; }
                    else if ((state == 1 || state == 3) && value == 10) { state++; }
                    else { state = value == 13 ? 1 : 0; }
                    if (state == 4) { break; }
                }
                return Encoding.ASCII.GetString(captured.ToArray());
            }
            finally
            {
                captured.Dispose();
            }
        }

        private static string FirstLine(string value)
        {
            int lineEnd = value.IndexOf("\r\n", StringComparison.Ordinal);
            if (lineEnd < 0) { lineEnd = value.IndexOf('\n'); }
            return lineEnd < 0 ? value.Trim() : value.Substring(0, lineEnd).Trim();
        }
    }
}
'@

try {
    Add-Type -TypeDefinition $fixtureSource -Language CSharp

    if ([string]::IsNullOrWhiteSpace($PortCVEPath)) {
        $PortCVEPath = $defaultExecutablePath
    }
    elseif (-not [IO.Path]::IsPathRooted($PortCVEPath)) {
        $PortCVEPath = [IO.Path]::GetFullPath((Join-Path (Get-Location).Path $PortCVEPath))
    }
    else {
        $PortCVEPath = [IO.Path]::GetFullPath($PortCVEPath)
    }

    if (-not $SkipBuild) {
        $dotnetCommand = Get-Command dotnet.exe -CommandType Application -ErrorAction Stop | Select-Object -First 1
        [void](Invoke-BoundedProcess `
            -FilePath $dotnetCommand.Path `
            -ArgumentList @('build', $projectPath, '--configuration', 'Release', '--nologo') `
            -Description 'PortCVE Release build' `
            -TimeoutSeconds $BuildTimeoutSeconds)
    }

    Assert-Condition (Test-Path -LiteralPath $PortCVEPath -PathType Leaf) `
        "PortCVE Release executable was not found at '$PortCVEPath'."

    $sshFixture = [PortCVEIntegration.LoopbackFixture]::StartSsh()
    $httpFixture = [PortCVEIntegration.LoopbackFixture]::StartHttp()
    $sshPort = [int]$sshFixture.Port
    $httpPort = [int]$httpFixture.Port
    Assert-Condition ($sshPort -ne $httpPort) 'The SSH and HTTP fixtures selected the same TCP port.'
    $configuredProbePorts = @(
        80, 81, 3000, 5000, 8000, 8008, 8080, 8081, 8888,
        443, 465, 636, 853, 989, 990, 992, 993, 994, 995, 8443, 9443)
    Assert-Condition ($httpPort -notin $configuredProbePorts) `
        "The OS assigned HTTP port $httpPort overlaps a configured protocol port; adaptive dispatch was not isolated."
    $portSelector = '{0},{1}' -f $sshPort, $httpPort

    $baseArguments = @(
        'scan-host', $loopbackTarget,
        '--authorized',
        '--ports', $portSelector,
        '--json',
        '--concurrency', '2',
        '--rate', '50',
        '--connect-timeout', '2s',
        '--read-timeout', '2s'
    )

    $httpFixture.ResetRequestLines()
    $defaultCapture = Invoke-BoundedProcess `
        -FilePath $PortCVEPath `
        -ArgumentList $baseArguments `
        -Description 'redacted discovery scan' `
        -TimeoutSeconds $CommandTimeoutSeconds
    $defaultReport = ConvertFrom-CapturedJson -Json $defaultCapture.StdOut -Description 'redacted discovery scan'
    $defaultSsh = Get-RemotePortResult -Report $defaultReport -Port $sshPort -Description 'redacted discovery scan'
    $defaultHttp = Get-RemotePortResult -Report $defaultReport -Port $httpPort -Description 'redacted discovery scan'
    Assert-Product -PortResult $defaultSsh -Product 'OpenSSH' -Version '9.6p1' -Description 'redacted discovery scan'
    Assert-NoApplicationIdentity -PortResult $defaultHttp -Description 'redacted discovery scan'
    Assert-Condition ([string]$defaultReport.probe_profile -ceq 'discovery') 'Default scan did not use the discovery profile.'
    Assert-Condition ([bool]$defaultReport.authorization_asserted) 'Default scan did not record the authorization assertion.'
    Assert-Condition (@($defaultReport.requested_ports).Count -eq 2) 'Default scan did not retain exactly two requested ports.'
    Assert-Condition (-not $defaultCapture.StdOut.Contains($loopbackTarget)) 'Default JSON exposed the raw loopback target/address.'
    Assert-Condition (-not $defaultCapture.StdOut.Contains('SSH-2.0-OpenSSH_9.6p1')) 'Default JSON exposed the raw SSH banner.'
    Assert-Condition (-not $defaultCapture.StdOut.Contains('Server: Apache/2.4.58')) 'Default JSON exposed the raw HTTP server evidence.'
    Assert-RequestLog `
        -RequestLines @($httpFixture.GetRequestLines()) `
        -ExpectedRequests @{} `
        -Description 'redacted discovery scan'

    $httpFixture.ResetRequestLines()
    $privateCapture = Invoke-BoundedProcess `
        -FilePath $PortCVEPath `
        -ArgumentList ($baseArguments + @('--include-private')) `
        -Description 'private discovery scan' `
        -TimeoutSeconds $CommandTimeoutSeconds
    $privateReport = ConvertFrom-CapturedJson -Json $privateCapture.StdOut -Description 'private discovery scan'
    $privateSsh = Get-RemotePortResult -Report $privateReport -Port $sshPort -Description 'private discovery scan'
    $privateHttp = Get-RemotePortResult -Report $privateReport -Port $httpPort -Description 'private discovery scan'
    Assert-Product -PortResult $privateSsh -Product 'OpenSSH' -Version '9.6p1' -Description 'private discovery scan'
    Assert-NoApplicationIdentity -PortResult $privateHttp -Description 'private discovery scan'
    Assert-Condition ([string]$privateReport.selector -ceq $loopbackTarget) 'Private JSON did not retain the explicit target.'
    Assert-Condition ($privateCapture.StdOut.Contains('SSH-2.0-OpenSSH_9.6p1')) 'Private JSON did not retain the SSH evidence.'
    Assert-RequestLog `
        -RequestLines @($httpFixture.GetRequestLines()) `
        -ExpectedRequests @{} `
        -Description 'private discovery scan'

    $httpFixture.ResetRequestLines()
    $redactedActiveCapture = Invoke-BoundedProcess `
        -FilePath $PortCVEPath `
        -ArgumentList ($baseArguments + @('--active')) `
        -Description 'redacted safe-active scan' `
        -TimeoutSeconds $CommandTimeoutSeconds
    $redactedActiveReport = ConvertFrom-CapturedJson `
        -Json $redactedActiveCapture.StdOut `
        -Description 'redacted safe-active scan'
    $redactedActiveHttp = Get-RemotePortResult `
        -Report $redactedActiveReport `
        -Port $httpPort `
        -Description 'redacted safe-active scan'
    Assert-Product `
        -PortResult $redactedActiveHttp `
        -Product 'Apache HTTP Server' `
        -Version '2.4.58' `
        -Description 'redacted safe-active scan'
    Assert-AdaptiveHttpFingerprint -PortResult $redactedActiveHttp -Description 'redacted safe-active scan'
    Assert-Condition (-not $redactedActiveCapture.StdOut.Contains($loopbackTarget)) `
        'Default active JSON exposed the raw loopback target/address.'
    Assert-Condition (-not $redactedActiveCapture.StdOut.Contains('Server: Apache/2.4.58')) `
        'Default active JSON exposed the raw adaptive HTTP evidence.'
    Assert-RequestLog `
        -RequestLines @($httpFixture.GetRequestLines()) `
        -ExpectedRequests @{ 'HEAD /' = 1 } `
        -Description 'redacted safe-active scan'

    $httpFixture.ResetRequestLines()
    $activeCapture = Invoke-BoundedProcess `
        -FilePath $PortCVEPath `
        -ArgumentList ($baseArguments + @('--active', '--include-private')) `
        -Description 'private safe-active scan' `
        -TimeoutSeconds $CommandTimeoutSeconds
    $activeReport = ConvertFrom-CapturedJson -Json $activeCapture.StdOut -Description 'private safe-active scan'
    $activeSsh = Get-RemotePortResult -Report $activeReport -Port $sshPort -Description 'private safe-active scan'
    $activeHttp = Get-RemotePortResult -Report $activeReport -Port $httpPort -Description 'private safe-active scan'
    Assert-Product -PortResult $activeSsh -Product 'OpenSSH' -Version '9.6p1' -Description 'private safe-active scan'
    Assert-Product -PortResult $activeHttp -Product 'Apache HTTP Server' -Version '2.4.58' -Description 'private safe-active scan'
    Assert-AdaptiveHttpFingerprint -PortResult $activeHttp -Description 'private safe-active scan'
    Assert-Condition ([string]$activeReport.probe_profile -ceq 'safe_active') 'Active scan did not use the safe_active profile.'
    Assert-Condition ($activeCapture.StdOut.Contains('Server: Apache/2.4.58')) `
        'Private active JSON did not retain the adaptive HTTP evidence.'
    $activeRequests = @($httpFixture.GetRequestLines())
    Assert-RequestLog `
        -RequestLines $activeRequests `
        -ExpectedRequests @{ 'HEAD /' = 1 } `
        -Description 'private safe-active scan'

    Assert-Condition ([string]::IsNullOrEmpty($sshFixture.Error)) "SSH fixture failed: $($sshFixture.Error)"
    Assert-Condition ([string]::IsNullOrEmpty($httpFixture.Error)) "HTTP fixture failed: $($httpFixture.Error)"

    $result = [ordered]@{
        status = 'passed'
        powershell_version = $PSVersionTable.PSVersion.ToString()
        portcve_path = $PortCVEPath
        portcve_version = [string]$activeReport.tool_version
        target = $loopbackTarget
        requested_ports = @($sshPort, $httpPort)
        ssh = [ordered]@{
            port = $sshPort
            state = [string]$activeSsh.state
            product = 'OpenSSH'
            version = '9.6p1'
        }
        http = [ordered]@{
            port = $httpPort
            state = [string]$activeHttp.state
            product = 'Apache HTTP Server'
            version = '2.4.58'
            fingerprint_source = 'active-adaptive-http-head'
            active_request_lines = $activeRequests
        }
        discovery = 'passed (silent nonstandard HTTP left unidentified)'
        safe_active_adaptive_http = 'passed'
        default_json_redaction = 'passed'
        private_json_evidence = 'passed'
        unsafe_http_methods_observed = @()
        online_advisories = 'not requested'
        fixture_cleanup = 'pending'
        temporary_file_cleanup = 'pending'
    }
}
catch {
    $primaryError = $_
}
finally {
    foreach ($fixture in @($sshFixture, $httpFixture)) {
        if ($null -eq $fixture) { continue }
        try {
            $stopped = $fixture.Stop()
            if (-not $stopped) {
                throw "Fixture did not stop cleanly: $($fixture.Error)"
            }
            $fixture.Dispose()
        }
        catch {
            [void]$cleanupErrors.Add("Loopback fixture cleanup failed: $($_.Exception.Message)")
        }
    }

    try {
        if (Test-Path -LiteralPath $integrationTempDirectory) {
            $resolvedTemporaryDirectory = [IO.Path]::GetFullPath((Resolve-Path -LiteralPath $integrationTempDirectory).Path)
            Assert-Condition `
                ($resolvedTemporaryDirectory.Equals($integrationTempDirectory, [StringComparison]::OrdinalIgnoreCase)) `
                'Temporary cleanup target changed unexpectedly.'
            Assert-Condition `
                ($resolvedTemporaryDirectory.StartsWith($temporaryPrefix, [StringComparison]::OrdinalIgnoreCase)) `
                'Temporary cleanup target escaped the system temporary directory.'
            Remove-Item -LiteralPath $resolvedTemporaryDirectory -Recurse -Force
        }
    }
    catch {
        [void]$cleanupErrors.Add("Temporary-file cleanup failed: $($_.Exception.Message)")
    }
}

if ($cleanupErrors.Count -gt 0) {
    $message = $cleanupErrors -join ' '
    if ($null -ne $primaryError) {
        $message = "$($primaryError.Exception.Message) Cleanup errors: $message"
    }
    throw $message
}
if ($null -ne $primaryError) {
    throw $primaryError
}

$result.fixture_cleanup = 'passed'
$result.temporary_file_cleanup = 'passed'
$result | ConvertTo-Json -Depth 8

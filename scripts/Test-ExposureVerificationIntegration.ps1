#requires -Version 5.1

<#
.SYNOPSIS
Validates PortCVE scanner-to-owner verification against a local-only fixture.

.DESCRIPTION
Builds the Release executable unless -SkipBuild is supplied, opens one
OS-assigned IPv4 wildcard TCP listener, writes bounded synthetic Nmap, Nuclei,
and Nessus evidence to a uniquely named system-temporary directory, and runs
`portcve verify` in both default-redacted and private modes.

The imported target is the fixed documentation address 192.0.2.10. It is never
contacted. The harness invokes only the offline `verify` command, passes no
network target parameter, and asserts that the local fixture accepted no
connections. Child processes are time-bounded and all local resources are
released in guarded cleanup.
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

$syntheticTarget = '192.0.2.10'
$syntheticHostname = 'verify-fixture.invalid'
$syntheticVantage = 'local-only-fixture'
$syntheticCve = 'CVE-2024-12345'
$repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$projectPath = Join-Path $repositoryRoot 'src\PortCVE\PortCVE.csproj'
$defaultExecutablePath = Join-Path $repositoryRoot 'src\PortCVE\bin\Release\net10.0\win-x64\portcve.exe'
$runId = [Guid]::NewGuid().ToString('N')
$temporaryRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$temporaryPrefix = $temporaryRoot.TrimEnd(
    [IO.Path]::DirectorySeparatorChar,
    [IO.Path]::AltDirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
$integrationTempDirectory = [IO.Path]::GetFullPath(
    (Join-Path $temporaryRoot "portcve-verify-it-$runId"))
$listener = $null
$primaryError = $null
$cleanupErrors = [Collections.Generic.List[string]]::new()

if (-not $integrationTempDirectory.StartsWith($temporaryPrefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Refusing to use an integration directory outside '$temporaryRoot'."
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

function Get-SingleEndpoint {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Report,
        [Parameter(Mandatory = $true)]
        [int]$Port,
        [Parameter(Mandatory = $true)]
        [string]$Description
    )

    $matches = @($Report.endpoints | Where-Object {
            [string]$_.protocol -ceq 'tcp' -and
            [int]$_.external_port -eq $Port -and
            [int]$_.local_port -eq $Port
        })
    Assert-Condition ($matches.Count -eq 1) "$Description did not contain exactly one mapped TCP endpoint."
    return $matches[0]
}

function Assert-FindingCorrelation {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Endpoint,
        [Parameter(Mandatory = $true)]
        [string]$Description,
        [switch]$ExpectPrivateHashes
    )

    $groups = @($Endpoint.findings | Where-Object {
            @($_.advisory_ids) -ccontains $syntheticCve
        })
    Assert-Condition ($groups.Count -eq 1) `
        "$Description did not deduplicate the shared CVE into one finding group."
    $group = $groups[0]
    Assert-Condition ([string]$group.finding_group_id -ceq "cve:$syntheticCve") `
        "$Description did not use the canonical CVE group identity."
    Assert-Condition ([string]$group.correlation -ceq 'owner_corroborated') `
        "$Description did not corroborate the scanner finding with the local owner."
    Assert-Condition ([string]$group.exploitability -ceq 'not_assessed') `
        "$Description overstated exploitability."

    $observations = @($group.observations)
    Assert-Condition ($observations.Count -eq 2) `
        "$Description did not retain exactly two cross-scanner observations."
    $sources = @($observations | ForEach-Object { [string]$_.source } | Sort-Object -Unique)
    Assert-Condition ($sources.Count -eq 2) "$Description lost scanner provenance."
    Assert-Condition ($sources -ccontains 'nuclei_jsonl') "$Description lost Nuclei provenance."
    Assert-Condition ($sources -ccontains 'nessus_xml') "$Description lost Nessus provenance."

    $recordHashes = @($observations | ForEach-Object { [string]$_.source_record_sha256 })
    foreach ($recordHash in $recordHashes) {
        Assert-Condition ($recordHash -cmatch '^[0-9a-f]{64}$') `
            "$Description emitted an invalid source-record SHA-256."
    }
    if ($ExpectPrivateHashes) {
        Assert-Condition (@($recordHashes | Sort-Object -Unique).Count -eq 2) `
            "$Description collapsed distinct source records or duplicated one record."
    }
    else {
        Assert-Condition (@($recordHashes | Where-Object { $_ -cne ('0' * 64) }).Count -eq 0) `
            "$Description retained reversible source-record hashes."
    }
}

function Assert-InputNames {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Report,
        [Parameter(Mandatory = $true)]
        [hashtable]$ExpectedNames,
        [Parameter(Mandatory = $true)]
        [string]$Description,
        [switch]$ExpectPrivateHashes
    )

    foreach ($source in $ExpectedNames.Keys) {
        $inputs = @($Report.inputs | Where-Object { [string]$_.source -ceq $source })
        Assert-Condition ($inputs.Count -eq 1) "$Description did not retain exactly one '$source' input."
        Assert-Condition ([string]$inputs[0].file_name -ceq [string]$ExpectedNames[$source]) `
            "$Description did not emit the expected '$source' file identity."
        Assert-Condition ([bool]$inputs[0].is_complete) "$Description marked '$source' incomplete."
        $inputHash = [string]$inputs[0].sha256
        Assert-Condition ($inputHash -cmatch '^[0-9a-f]{64}$') `
            "$Description emitted an invalid input SHA-256."
        if ($ExpectPrivateHashes) {
            Assert-Condition ($inputHash -cne ('0' * 64)) `
                "$Description masked an input hash in private mode."
        }
        else {
            Assert-Condition ($inputHash -ceq ('0' * 64)) `
                "$Description retained a reversible input hash."
        }
    }

    $liveInputs = @($Report.inputs | Where-Object { [string]$_.source -ceq 'live_windows' })
    Assert-Condition ($liveInputs.Count -eq 1) "$Description did not retain one live Windows input."
    Assert-Condition ([bool]$liveInputs[0].is_complete) "$Description marked live Windows evidence incomplete."
}

$fixtureSource = @'
using System;
using System.Net;
using System.Net.Sockets;

namespace PortCVEVerificationIntegration
{
    public sealed class WildcardFixture : IDisposable
    {
        private readonly TcpListener listener;
        private bool stopped;

        private WildcardFixture(TcpListener startedListener)
        {
            listener = startedListener;
        }

        public int Port
        {
            get { return ((IPEndPoint)listener.LocalEndpoint).Port; }
        }

        public bool HasPendingConnection
        {
            get { return !stopped && listener.Pending(); }
        }

        public static WildcardFixture Start()
        {
            TcpListener candidate = new TcpListener(IPAddress.Any, 0);
            candidate.Start(8);
            return new WildcardFixture(candidate);
        }

        public void Stop()
        {
            if (stopped) { return; }
            stopped = true;
            listener.Stop();
        }

        public void Dispose()
        {
            Stop();
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
        $dotnetCommand = Get-Command dotnet.exe -CommandType Application -ErrorAction Stop |
            Select-Object -First 1
        [void](Invoke-BoundedProcess `
            -FilePath $dotnetCommand.Path `
            -ArgumentList @(
                'build', $projectPath,
                '--configuration', 'Release',
                '--no-restore',
                '--nologo') `
            -Description 'PortCVE Release build' `
            -TimeoutSeconds $BuildTimeoutSeconds)
    }

    Assert-Condition (Test-Path -LiteralPath $PortCVEPath -PathType Leaf) `
        "PortCVE Release executable was not found at '$PortCVEPath'."

    $listener = [PortCVEVerificationIntegration.WildcardFixture]::Start()
    $fixturePort = [int]$listener.Port
    Assert-Condition ($fixturePort -ge 1 -and $fixturePort -le 65535) `
        'The OS did not assign a valid fixture port.'
    Assert-Condition (-not $listener.HasPendingConnection) `
        'The fixture already had a connection before verification began.'

    $nmapPath = Join-Path $integrationTempDirectory 'synthetic-nmap.xml'
    $nucleiPath = Join-Path $integrationTempDirectory 'synthetic-nuclei.jsonl'
    $nessusPath = Join-Path $integrationTempDirectory 'synthetic-report.nessus'
    $utf8WithoutBom = [Text.UTF8Encoding]::new($false)

    $nmapXml = @"
<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" version="7.98" xmloutputversion="1.05">
  <host>
    <status state="up" reason="user-set" />
    <address addr="$syntheticTarget" addrtype="ipv4" />
    <hostnames><hostname name="$syntheticHostname" type="user" /></hostnames>
    <ports>
      <port protocol="tcp" portid="$fixturePort">
        <state state="open" reason="syn-ack" />
        <service name="http" product="SyntheticFixture" version="1.0" method="probed" conf="10">
          <cpe>cpe:/a:portcve:synthetic_fixture:1.0</cpe>
        </service>
      </port>
    </ports>
  </host>
  <runstats><finished exit="success" /></runstats>
</nmaprun>
"@

    $nucleiJsonl = @"
{"template-id":"synthetic-cve-check","info":{"name":"Synthetic shared CVE check","severity":"high","classification":{"cve-id":["$syntheticCve"]}},"type":"http","scheme":"http","host":"http://${syntheticTarget}:$fixturePort","matched-at":"http://${syntheticTarget}:$fixturePort/bounded-fixture","port":$fixturePort,"matcher-name":"synthetic-header","matcher-status":true}
"@

    $nessusXml = @"
<?xml version="1.0" encoding="UTF-8"?>
<NessusClientData_v2 version="10.8">
  <Report name="Synthetic offline report">
    <ReportHost name="$syntheticHostname">
      <HostProperties><tag name="host-ip">$syntheticTarget</tag></HostProperties>
      <ReportItem port="$fixturePort" svc_name="http" protocol="tcp" severity="3" pluginID="900001" pluginName="Synthetic shared CVE check">
        <cve>$syntheticCve</cve>
      </ReportItem>
    </ReportHost>
  </Report>
</NessusClientData_v2>
"@

    [IO.File]::WriteAllText($nmapPath, $nmapXml, $utf8WithoutBom)
    [IO.File]::WriteAllText($nucleiPath, $nucleiJsonl.Trim() + [Environment]::NewLine, $utf8WithoutBom)
    [IO.File]::WriteAllText($nessusPath, $nessusXml, $utf8WithoutBom)
    foreach ($inputPath in @($nmapPath, $nucleiPath, $nessusPath)) {
        Assert-Condition (Test-Path -LiteralPath $inputPath -PathType Leaf) `
            "Synthetic input '$inputPath' was not created."
        Assert-Condition ((Get-Item -LiteralPath $inputPath).Length -le 64KB) `
            "Synthetic input '$inputPath' exceeded the 64 KiB harness limit."
    }

    $baseArguments = @(
        'verify', $nmapPath,
        '--target', $syntheticTarget,
        '--nuclei', $nucleiPath,
        '--nessus', $nessusPath,
        '--vantage', $syntheticVantage,
        '--no-firewall',
        '--strict',
        '--json'
    )

    $defaultCapture = Invoke-BoundedProcess `
        -FilePath $PortCVEPath `
        -ArgumentList $baseArguments `
        -Description 'default-redacted exposure verification' `
        -TimeoutSeconds $CommandTimeoutSeconds
    $defaultReport = ConvertFrom-CapturedJson `
        -Json $defaultCapture.StdOut `
        -Description 'default-redacted exposure verification'
    Assert-Condition ([int]$defaultReport.schema_version -eq 1) `
        'Default report did not use verification schema version 1.'
    Assert-Condition ([string]$defaultReport.privacy_mode -ceq 'reduced') `
        'Default report did not declare reduced privacy mode.'
    Assert-Condition ([bool]$defaultReport.summary.is_complete) `
        'Default strict report was not complete.'
    Assert-Condition ([int]$defaultReport.summary.correlated_open_count -eq 1) `
        'Default report did not contain exactly one correlated-open endpoint.'
    Assert-Condition ([int]$defaultReport.summary.finding_group_count -eq 1) `
        'Default report did not deduplicate the CVE into one finding group.'
    Assert-Condition ([string]$defaultReport.association.imported_target -ceq 'target-1') `
        'Default report did not redact the imported target.'
    Assert-Condition ([string]$defaultReport.association.vantage -ceq 'operator-labeled-vantage') `
        'Default report did not redact the operator vantage.'
    Assert-Condition (-not $defaultCapture.StdOut.Contains($syntheticTarget)) `
        'Default report leaked the imported target.'
    Assert-Condition (-not $defaultCapture.StdOut.Contains($syntheticHostname)) `
        'Default report leaked the imported hostname.'
    Assert-Condition (-not $defaultCapture.StdOut.Contains($syntheticVantage)) `
        'Default report leaked the operator vantage.'
    Assert-Condition (-not $defaultCapture.StdOut.Contains('0.0.0.0')) `
        'Default report leaked the wildcard local address.'
    Assert-InputNames -Report $defaultReport -ExpectedNames @{
        nmap_xml = 'nmapxml-input'
        nuclei_jsonl = 'nucleijsonl-input'
        nessus_xml = 'nessusxml-input'
    } -Description 'default-redacted exposure verification'

    $defaultEndpoint = Get-SingleEndpoint `
        -Report $defaultReport `
        -Port $fixturePort `
        -Description 'default-redacted exposure verification'
    Assert-Condition ([string]$defaultEndpoint.correlation -ceq 'correlated_open') `
        'Default report did not classify the endpoint as correlated_open.'
    $defaultListeners = @($defaultEndpoint.local_listeners)
    Assert-Condition ($defaultListeners.Count -ge 1) `
        'Default report did not retain the local listener.'
    $defaultWildcardListeners = @($defaultListeners | Where-Object {
            [string]$_.bind_scope -ceq 'wildcard' -and [string]$_.local_address -ceq 'any'
        })
    Assert-Condition ($defaultWildcardListeners.Count -ge 1) `
        'Default report did not alias the wildcard listener address.'
    Assert-FindingCorrelation `
        -Endpoint $defaultEndpoint `
        -Description 'default-redacted exposure verification'

    $privateCapture = Invoke-BoundedProcess `
        -FilePath $PortCVEPath `
        -ArgumentList @($baseArguments + '--include-private') `
        -Description 'private exposure verification' `
        -TimeoutSeconds $CommandTimeoutSeconds
    $privateReport = ConvertFrom-CapturedJson `
        -Json $privateCapture.StdOut `
        -Description 'private exposure verification'
    Assert-Condition ([bool]$privateReport.summary.is_complete) `
        'Private strict report was not complete.'
    Assert-Condition ([string]$privateReport.privacy_mode -ceq 'private') `
        'Private report did not declare private privacy mode.'
    Assert-Condition ([string]$privateReport.association.imported_target -ceq $syntheticTarget) `
        'Private report did not retain the imported target.'
    Assert-Condition ([string]$privateReport.association.vantage -ceq $syntheticVantage) `
        'Private report did not retain the operator vantage.'
    Assert-InputNames -Report $privateReport -ExpectedNames @{
        nmap_xml = [IO.Path]::GetFileName($nmapPath)
        nuclei_jsonl = [IO.Path]::GetFileName($nucleiPath)
        nessus_xml = [IO.Path]::GetFileName($nessusPath)
    } -Description 'private exposure verification' -ExpectPrivateHashes

    $privateEndpoint = Get-SingleEndpoint `
        -Report $privateReport `
        -Port $fixturePort `
        -Description 'private exposure verification'
    Assert-Condition ([string]$privateEndpoint.correlation -ceq 'correlated_open') `
        'Private report did not classify the endpoint as correlated_open.'
    $privateOutside = @($privateEndpoint.outside_observations)
    Assert-Condition ($privateOutside.Count -eq 1) `
        'Private report did not retain exactly one Nmap observation.'
    Assert-Condition ([string]$privateOutside[0].target -ceq $syntheticTarget) `
        'Private report did not retain the imported observation target.'
    Assert-Condition ([string]$privateOutside[0].hostname -ceq $syntheticHostname) `
        'Private report did not retain the imported hostname.'
    $privateWildcardListeners = @($privateEndpoint.local_listeners | Where-Object {
            [string]$_.bind_scope -ceq 'wildcard' -and [string]$_.local_address -ceq '0.0.0.0'
        })
    Assert-Condition ($privateWildcardListeners.Count -ge 1) `
        'Private report did not retain the wildcard listener address.'
    Assert-FindingCorrelation `
        -Endpoint $privateEndpoint `
        -Description 'private exposure verification' `
        -ExpectPrivateHashes

    Assert-Condition (-not $listener.HasPendingConnection) `
        'PortCVE contacted the fixture even though verify must perform no remote traffic.'

    Write-Output ((
        'Exposure verification integration passed: port={0}; strict_runs=2; correlated_open=1; ' +
        'finding_groups=1; observations=2; default_redaction=pass; private_retention=pass; ' +
        'fixture_connections=0') -f $fixturePort)
}
catch {
    $primaryError = $_
}
finally {
    if ($null -ne $listener) {
        try {
            $listener.Stop()
            $listener.Dispose()
        }
        catch {
            $cleanupErrors.Add("Listener cleanup failed: $($_.Exception.Message)")
        }
    }

    try {
        $resolvedTemporaryDirectory = [IO.Path]::GetFullPath($integrationTempDirectory)
        $safeCleanupTarget =
            $resolvedTemporaryDirectory.StartsWith($temporaryPrefix, [StringComparison]::OrdinalIgnoreCase) -and
            [string]::Equals(
                $resolvedTemporaryDirectory,
                $integrationTempDirectory,
                [StringComparison]::OrdinalIgnoreCase) -and
            [IO.Path]::GetFileName($resolvedTemporaryDirectory).StartsWith(
                'portcve-verify-it-',
                [StringComparison]::Ordinal)
        if (-not $safeCleanupTarget) {
            throw "Refusing to remove unsafe cleanup target '$resolvedTemporaryDirectory'."
        }
        if (Test-Path -LiteralPath $resolvedTemporaryDirectory) {
            Remove-Item -LiteralPath $resolvedTemporaryDirectory -Recurse -Force
        }
    }
    catch {
        $cleanupErrors.Add("Temporary-directory cleanup failed: $($_.Exception.Message)")
    }
}

if ($null -ne $primaryError) {
    if ($cleanupErrors.Count -gt 0) {
        throw "$($primaryError.Exception.Message) Cleanup errors: $($cleanupErrors -join ' ')"
    }
    throw $primaryError
}
if ($cleanupErrors.Count -gt 0) {
    throw ($cleanupErrors -join ' ')
}

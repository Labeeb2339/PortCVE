#requires -Version 5.1

<#
.SYNOPSIS
Measures bounded PortCVE daily-workflow performance on the local Windows host.

.DESCRIPTION
Runs repeated no-firewall local inventory and one passive, authorized loopback
scan over a high-port range. The remote leg never targets a LAN or Internet
address and sends no adaptive probes. Temporary output is held only in memory
and the script emits one compact JSON result.
#>
[CmdletBinding()]
param(
    [string]$PortCVEPath,
    [ValidateRange(3, 50)]
    [int]$LocalIterations = 10,
    [ValidateRange(64, 4096)]
    [int]$RemotePortCount = 1000,
    [switch]$EnforceBudgets,
    [ValidateRange(100, 10000)]
    [int]$LocalP95BudgetMilliseconds = 2000,
    [ValidateRange(1000, 120000)]
    [int]$RemoteBudgetMilliseconds = 30000,
    [ValidateRange(128, 2048)]
    [int]$PeakWorkingSetBudgetMiB = 768
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
if ([string]::IsNullOrWhiteSpace($PortCVEPath)) {
    $PortCVEPath = Join-Path $repositoryRoot 'src\PortCVE\bin\Release\net10.0\win-x64\portcve.exe'
}
elseif (-not [IO.Path]::IsPathRooted($PortCVEPath)) {
    $PortCVEPath = [IO.Path]::GetFullPath((Join-Path (Get-Location).Path $PortCVEPath))
}
else {
    $PortCVEPath = [IO.Path]::GetFullPath($PortCVEPath)
}

if (-not (Test-Path -LiteralPath $PortCVEPath -PathType Leaf)) {
    throw "PortCVE executable was not found at '$PortCVEPath'."
}

function ConvertTo-WindowsProcessArgument {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Value)

    if ($Value.Length -gt 0 -and $Value -notmatch '[\s"]') {
        return $Value
    }

    $builder = [Text.StringBuilder]::new()
    [void]$builder.Append('"')
    $slashes = 0
    foreach ($character in $Value.ToCharArray()) {
        if ($character -eq '\') {
            $slashes++
            continue
        }

        if ($character -eq '"') {
            [void]$builder.Append(('\' * (($slashes * 2) + 1)))
            [void]$builder.Append('"')
        }
        else {
            if ($slashes -gt 0) { [void]$builder.Append(('\' * $slashes)) }
            [void]$builder.Append($character)
        }
        $slashes = 0
    }

    if ($slashes -gt 0) { [void]$builder.Append(('\' * ($slashes * 2))) }
    [void]$builder.Append('"')
    return $builder.ToString()
}

function Invoke-MeasuredPortCVE {
    param(
        [string[]]$Arguments,
        [int]$TimeoutMilliseconds
    )

    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $script:PortCVEPath
    $startInfo.Arguments = (($Arguments | ForEach-Object {
        ConvertTo-WindowsProcessArgument -Value ([string]$_)
    }) -join ' ')
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true

    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    $stopwatch = [Diagnostics.Stopwatch]::StartNew()
    try {
        if (-not $process.Start()) { throw 'PortCVE process did not start.' }
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        $peakWorkingSetBytes = 0L
        while (-not $process.HasExited) {
            $process.Refresh()
            $peakWorkingSetBytes = [Math]::Max(
                $peakWorkingSetBytes,
                [long]$process.WorkingSet64)
            if ($stopwatch.ElapsedMilliseconds -ge $TimeoutMilliseconds) {
                try { $process.Kill() } catch { }
                throw "PortCVE exceeded the $TimeoutMilliseconds ms performance-harness timeout."
            }
            Start-Sleep -Milliseconds 10
        }
        $process.WaitForExit()
        try {
            $process.Refresh()
            $peakWorkingSetBytes = [Math]::Max(
                $peakWorkingSetBytes,
                [long]$process.PeakWorkingSet64)
        }
        catch {
            # The sampled working set remains valid if Windows has already
            # released the exited process accounting record.
        }
        $stopwatch.Stop()
        $stdout = $stdoutTask.GetAwaiter().GetResult()
        $stderr = $stderrTask.GetAwaiter().GetResult()
        if ($process.ExitCode -ne 0) {
            throw "PortCVE exited $($process.ExitCode): $stderr"
        }

        return [pscustomobject]@{
            ElapsedMilliseconds = [int][Math]::Ceiling($stopwatch.Elapsed.TotalMilliseconds)
            PeakWorkingSetBytes = $peakWorkingSetBytes
            StdOut = $stdout
        }
    }
    finally {
        $stopwatch.Stop()
        $process.Dispose()
    }
}

function Get-Percentile95 {
    param([int[]]$Values)

    $ordered = @($Values | Sort-Object)
    $index = [Math]::Max(0, [Math]::Ceiling($ordered.Count * 0.95) - 1)
    return [int]$ordered[$index]
}

$localDurations = [Collections.Generic.List[int]]::new()
$peakWorkingSet = 0L
$lastLocal = $null
for ($iteration = 0; $iteration -lt $LocalIterations; $iteration++) {
    $measurement = Invoke-MeasuredPortCVE `
        -Arguments @('list', '--json', '--no-firewall') `
        -TimeoutMilliseconds 30000
    [void]$localDurations.Add($measurement.ElapsedMilliseconds)
    $peakWorkingSet = [Math]::Max($peakWorkingSet, $measurement.PeakWorkingSetBytes)
    $lastLocal = $measurement.StdOut | ConvertFrom-Json
}

$remoteStartPort = 49152
$remoteEndPort = $remoteStartPort + $RemotePortCount - 1
$remote = Invoke-MeasuredPortCVE `
    -Arguments @(
        'scan-host', '127.0.0.1',
        '--ports', "$remoteStartPort-$remoteEndPort",
        '--authorized', '--json',
        '--rate', '10000', '--concurrency', '256',
        '--connect-timeout', '250ms', '--read-timeout', '250ms'
    ) `
    -TimeoutMilliseconds ([Math]::Max(60000, $RemoteBudgetMilliseconds * 2))
$peakWorkingSet = [Math]::Max($peakWorkingSet, $remote.PeakWorkingSetBytes)
$remoteReport = $remote.StdOut | ConvertFrom-Json

$localP95 = Get-Percentile95 -Values $localDurations.ToArray()
$peakMiB = [Math]::Round($peakWorkingSet / 1MB, 1)
if ($EnforceBudgets) {
    if ($localP95 -gt $LocalP95BudgetMilliseconds) {
        throw "Local inventory p95 ${localP95}ms exceeded the ${LocalP95BudgetMilliseconds}ms budget."
    }
    if ($remote.ElapsedMilliseconds -gt $RemoteBudgetMilliseconds) {
        throw "Remote loopback scan $($remote.ElapsedMilliseconds)ms exceeded the ${RemoteBudgetMilliseconds}ms budget."
    }
    if ($peakMiB -gt $PeakWorkingSetBudgetMiB) {
        throw "Peak working set ${peakMiB}MiB exceeded the ${PeakWorkingSetBudgetMiB}MiB budget."
    }
}

[ordered]@{
    status = 'passed'
    windows_version = [Environment]::OSVersion.Version.ToString()
    portcve_version = (& $PortCVEPath --version)
    local_inventory = [ordered]@{
        iterations = $LocalIterations
        endpoint_count = @($lastLocal.listeners).Count
        minimum_ms = ($localDurations | Measure-Object -Minimum).Minimum
        median_ms = [int](@($localDurations | Sort-Object)[[Math]::Floor($localDurations.Count / 2)])
        p95_ms = $localP95
        maximum_ms = ($localDurations | Measure-Object -Maximum).Maximum
    }
    passive_loopback_scan = [ordered]@{
        requested_ports = $RemotePortCount
        reported_endpoints = [int]$remoteReport.summary.endpoint_count
        elapsed_ms = $remote.ElapsedMilliseconds
    }
    peak_working_set_mib = $peakMiB
    budgets_enforced = [bool]$EnforceBudgets
} | ConvertTo-Json -Depth 5

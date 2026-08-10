<#
.SYNOPSIS
Runs a mutating, local Docker integration check for PortCVE.

.DESCRIPTION
This script may pull alpine:3.22, creates and starts one uniquely named and
labeled container, publishes temporary TCP and UDP echo ports, and removes its
container and temporary files in a guarded finally block. By default both
publications are loopback-only. -AllowWildcardUdp intentionally publishes the
UDP echo service on 0.0.0.0 for bind-scope validation and can briefly expose it
to the local network. -ValidateRemoteScan additionally runs PortCVE's authorized
active scanner against only the temporary loopback TCP publication and proves a
generic echo service is not promoted to an application identity.
#>
[CmdletBinding()]
param(
    [string]$PortCVEPath,
    [switch]$ValidateLockCheck,
    [switch]$ValidateRemoteScan,
    [switch]$AllowWildcardUdp,
    [ValidateRange(5, 120)]
    [int]$TimeoutSeconds = 30
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$dockerImage = 'alpine:3.22'
$tcpContainerPort = 18080
$udpContainerPort = 18081
$labelName = 'io.portcve.integration-id'
$runId = [Guid]::NewGuid().ToString('N')
$containerName = 'portcve-it-{0}' -f $runId.Substring(0, 12)
$containerId = $null
$containerCreateAttempted = $false
$commandCounter = 0
$udpHostAddress = if ($AllowWildcardUdp) { '0.0.0.0' } else { '127.0.0.1' }

if ($AllowWildcardUdp) {
    Write-Warning 'The UDP echo fixture will be published on 0.0.0.0 and may be reachable from the local network until cleanup completes.'
}

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
    throw "PortCVE Release executable was not found at '$PortCVEPath'. Build or publish Release first, or pass -PortCVEPath."
}

$dockerCommand = Get-Command docker.exe -CommandType Application -ErrorAction Stop
$dockerPath = $dockerCommand.Path

$temporaryRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$temporaryPrefix = $temporaryRoot.TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
$integrationTempDirectory = [IO.Path]::GetFullPath((Join-Path $temporaryRoot ("portcve-it-$runId")))
if (-not $integrationTempDirectory.StartsWith($temporaryPrefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Refusing to use an integration temporary directory outside '$temporaryRoot'."
}

if (Test-Path -LiteralPath $integrationTempDirectory) {
    throw "Refusing to reuse existing temporary directory '$integrationTempDirectory'."
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

function Invoke-CapturedCommand {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,
        [Parameter(Mandatory = $true)]
        [string[]]$ArgumentList,
        [Parameter(Mandatory = $true)]
        [string]$Description,
        [switch]$AllowFailure
    )

    $script:commandCounter++
    $stdoutPath = Join-Path $script:integrationTempDirectory ('command-{0:D3}.stdout' -f $script:commandCounter)
    $stderrPath = Join-Path $script:integrationTempDirectory ('command-{0:D3}.stderr' -f $script:commandCounter)

    $previousErrorActionPreference = $ErrorActionPreference
    try {
        # Windows PowerShell 5.1 surfaces redirected native stderr as a
        # NativeCommandError. Exit status remains the authoritative result.
        $ErrorActionPreference = 'Continue'
        & $FilePath @ArgumentList 1> $stdoutPath 2> $stderrPath
        $exitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }
    $stdout = if (Test-Path -LiteralPath $stdoutPath) { [IO.File]::ReadAllText($stdoutPath) } else { '' }
    $stderr = if (Test-Path -LiteralPath $stderrPath) { [IO.File]::ReadAllText($stderrPath) } else { '' }

    if ($exitCode -ne 0 -and -not $AllowFailure) {
        $details = (($stderr + [Environment]::NewLine + $stdout).Trim())
        if ($details.Length -gt 4000) {
            $details = $details.Substring(0, 4000) + '...'
        }

        throw "$Description failed with exit code $exitCode. $details"
    }

    return [pscustomobject]@{
        ExitCode = $exitCode
        StdOut = $stdout
        StdErr = $stderr
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

function Get-FreeTcpPort {
    $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
    try {
        $listener.Start()
        return ([Net.IPEndPoint]$listener.LocalEndpoint).Port
    }
    finally {
        $listener.Stop()
    }
}

function Get-FreeUdpPort {
    $client = [Net.Sockets.UdpClient]::new([Net.Sockets.AddressFamily]::InterNetwork)
    try {
        $client.Client.Bind([Net.IPEndPoint]::new([Net.IPAddress]::Any, 0))
        return ([Net.IPEndPoint]$client.Client.LocalEndPoint).Port
    }
    finally {
        $client.Dispose()
    }
}

function Test-TcpEcho {
    param(
        [int]$Port,
        [string]$Payload,
        [int]$TimeoutMilliseconds
    )

    $client = [Net.Sockets.TcpClient]::new()
    try {
        $connection = $client.BeginConnect('127.0.0.1', $Port, $null, $null)
        try {
            if (-not $connection.AsyncWaitHandle.WaitOne($TimeoutMilliseconds)) {
                return $false
            }

            $client.EndConnect($connection)
        }
        finally {
            $connection.AsyncWaitHandle.Close()
        }

        $stream = $client.GetStream()
        $stream.ReadTimeout = $TimeoutMilliseconds
        $stream.WriteTimeout = $TimeoutMilliseconds
        $request = [Text.Encoding]::UTF8.GetBytes($Payload)
        $stream.Write($request, 0, $request.Length)
        $stream.Flush()

        $response = [byte[]]::new($request.Length)
        $received = 0
        while ($received -lt $response.Length) {
            $count = $stream.Read($response, $received, $response.Length - $received)
            if ($count -eq 0) {
                return $false
            }

            $received += $count
        }

        return [Convert]::ToBase64String($request) -eq [Convert]::ToBase64String($response)
    }
    catch {
        return $false
    }
    finally {
        $client.Dispose()
    }
}

function Test-UdpEcho {
    param(
        [int]$Port,
        [string]$Payload,
        [int]$TimeoutMilliseconds
    )

    $client = [Net.Sockets.UdpClient]::new([Net.Sockets.AddressFamily]::InterNetwork)
    try {
        $client.Client.ReceiveTimeout = $TimeoutMilliseconds
        $client.Client.SendTimeout = $TimeoutMilliseconds
        $client.Connect('127.0.0.1', $Port)
        $request = [Text.Encoding]::UTF8.GetBytes($Payload)
        [void]$client.Send($request, $request.Length)
        $remoteEndpoint = [Net.IPEndPoint]::new([Net.IPAddress]::Any, 0)
        $response = $client.Receive([ref]$remoteEndpoint)
        return [Convert]::ToBase64String($request) -eq [Convert]::ToBase64String($response)
    }
    catch {
        return $false
    }
    finally {
        $client.Dispose()
    }
}

function Wait-ForEchoes {
    param(
        [int]$TcpPort,
        [int]$UdpPort,
        [string]$TcpPayload,
        [string]$UdpPayload,
        [int]$Timeout
    )

    $deadline = [DateTime]::UtcNow.AddSeconds($Timeout)
    do {
        $tcpPassed = Test-TcpEcho -Port $TcpPort -Payload $TcpPayload -TimeoutMilliseconds 750
        $udpPassed = Test-UdpEcho -Port $UdpPort -Payload $UdpPayload -TimeoutMilliseconds 750
        if ($tcpPassed -and $udpPassed) {
            return
        }

        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $deadline)

    throw "TCP and UDP echo services did not both respond within $Timeout seconds (tcp=$tcpPassed, udp=$udpPassed)."
}

function Get-PortCVESnapshot {
    param([switch]$IncludePrivate)

    $arguments = @('list', '--json')
    if ($IncludePrivate) {
        $arguments += '--include-private'
    }

    $description = if ($IncludePrivate) { 'PortCVE private JSON collection' } else { 'PortCVE default JSON collection' }
    $capture = Invoke-CapturedCommand -FilePath $script:PortCVEPath -ArgumentList $arguments -Description $description
    $snapshot = ConvertFrom-CapturedJson -Json $capture.StdOut -Description $description
    return [pscustomobject]@{
        Raw = $capture.StdOut
        Snapshot = $snapshot
    }
}

function Test-RemoteEchoScan {
    param([int]$HostPort)

    $description = 'PortCVE authorized Docker-forwarded TCP scan'
    $capture = Invoke-CapturedCommand `
        -FilePath $script:PortCVEPath `
        -ArgumentList @(
            'scan-host', '127.0.0.1',
            '--ports', [string]$HostPort,
            '--authorized', '--active', '--json', '--include-private',
            '--connect-timeout', '2s', '--read-timeout', '2s'
        ) `
        -Description $description
    $report = ConvertFrom-CapturedJson -Json $capture.StdOut -Description $description
    $matches = @($report.hosts |
        ForEach-Object { @($_.ports) } |
        Where-Object { [int]$_.port -eq $HostPort })
    Assert-Condition ($matches.Count -eq 1) "$description did not return exactly one selected endpoint."
    Assert-Condition ($matches[0].state -eq 'open') "$description did not report the Docker-forwarded endpoint open."
    Assert-Condition (@($matches[0].product_candidates).Count -eq 0) `
        "$description promoted a generic echo service to an application identity."

    return [pscustomobject]@{
        state = [string]$matches[0].state
        product_candidate_count = @($matches[0].product_candidates).Count
    }
}

function Assert-DockerCollectorComplete {
    param(
        [Parameter(Mandatory = $true)]
        $Snapshot,
        [string]$Context
    )

    $reports = @($Snapshot.collectors | Where-Object { $_.name -eq 'docker' })
    Assert-Condition ($reports.Count -eq 1) "$Context must contain exactly one Docker collector report."
    Assert-Condition ($reports[0].status -eq 'complete') "$Context Docker collector status was '$($reports[0].status)', expected 'complete'."
}

function Find-ContainerMappings {
    param(
        [Parameter(Mandatory = $true)]
        $Snapshot,
        [int]$HostPort,
        [int]$ContainerPort,
        [string]$Protocol
    )

    $matches = [Collections.Generic.List[object]]::new()
    foreach ($listener in @($Snapshot.listeners)) {
        $property = $listener.PSObject.Properties['container_exposures']
        if ($null -eq $property -or $null -eq $property.Value) {
            continue
        }

        foreach ($exposure in @($property.Value)) {
            if ($null -eq $exposure) {
                continue
            }

            if ([int]$exposure.host_port -eq $HostPort -and
                [int]$exposure.container_port -eq $ContainerPort -and
                $exposure.protocol -eq $Protocol) {
                [void]$matches.Add([pscustomobject]@{
                    Listener = $listener
                    Exposure = $exposure
                })
            }
        }
    }

    return $matches.ToArray()
}

function Wait-ForPortCVEMappings {
    param(
        [int]$TcpHostPort,
        [int]$UdpHostPort,
        [int]$Timeout,
        [switch]$IncludePrivate
    )

    $deadline = [DateTime]::UtcNow.AddSeconds($Timeout)
    $lastReason = 'No snapshot was collected.'
    do {
        try {
            $capture = Get-PortCVESnapshot -IncludePrivate:$IncludePrivate
            $context = if ($IncludePrivate) { 'Private JSON' } else { 'Default JSON' }
            Assert-DockerCollectorComplete -Snapshot $capture.Snapshot -Context $context
            $tcpMatches = @(Find-ContainerMappings -Snapshot $capture.Snapshot -HostPort $TcpHostPort -ContainerPort $script:tcpContainerPort -Protocol 'tcp')
            $udpMatches = @(Find-ContainerMappings -Snapshot $capture.Snapshot -HostPort $UdpHostPort -ContainerPort $script:udpContainerPort -Protocol 'udp')
            if ($tcpMatches.Count -gt 0 -and $udpMatches.Count -gt 0) {
                return [pscustomobject]@{
                    Raw = $capture.Raw
                    Snapshot = $capture.Snapshot
                    TcpMatches = $tcpMatches
                    UdpMatches = $udpMatches
                }
            }

            $lastReason = "Observed tcp=$($tcpMatches.Count), udp=$($udpMatches.Count) correlated mappings."
        }
        catch {
            $lastReason = $_.Exception.Message
        }

        Start-Sleep -Milliseconds 300
    } while ([DateTime]::UtcNow -lt $deadline)

    throw "PortCVE did not report both Docker mappings within $Timeout seconds. Last result: $lastReason"
}

function Assert-PrivateMapping {
    param(
        [object[]]$Matches,
        [string]$Protocol,
        [int]$HostPort,
        [int]$ContainerPort,
        [string]$HostAddress,
        [string]$ExpectedContainerId,
        [string]$ExpectedContainerName,
        [string]$ExpectedImageId
    )

    $exactMatches = @($Matches | Where-Object {
        $_.Exposure.runtime -eq 'docker' -and
        $_.Exposure.container_id -eq $ExpectedContainerId -and
        $_.Exposure.container_name -eq $ExpectedContainerName -and
        $_.Exposure.image -eq $script:dockerImage -and
        $_.Exposure.image_id -eq $ExpectedImageId -and
        $_.Exposure.host_address -eq $HostAddress -and
        [int]$_.Exposure.host_port -eq $HostPort -and
        [int]$_.Exposure.container_port -eq $ContainerPort -and
        $_.Exposure.protocol -eq $Protocol -and
        $_.Listener.protocol -eq $Protocol -and
        [int]$_.Listener.local_port -eq $HostPort
    })

    Assert-Condition ($exactMatches.Count -gt 0) "Private JSON did not expose the exact $Protocol Docker mapping for $ExpectedContainerName."
}

function Assert-RawValueAbsent {
    param(
        [string]$Json,
        [string]$Value,
        [string]$Description
    )

    if (-not [string]::IsNullOrEmpty($Value)) {
        Assert-Condition (-not $Json.Contains($Value)) "Default JSON exposed the real $Description."
    }
}

function Test-LockCheckRoundTrip {
    param(
        [string]$Protocol,
        [int]$Port
    )

    $lockPath = Join-Path $script:integrationTempDirectory ("$Protocol-$Port.lock.json")
    $arguments = @('lock', '--port', $Port.ToString([Globalization.CultureInfo]::InvariantCulture), '--proto', $Protocol, '--output', $lockPath, '--force', '--json')
    if ($Protocol -eq 'udp') {
        $arguments += '--include-udp'
    }

    $lockCapture = Invoke-CapturedCommand -FilePath $script:PortCVEPath -ArgumentList $arguments -Description "PortCVE $Protocol lock"
    $lockResult = ConvertFrom-CapturedJson -Json $lockCapture.StdOut -Description "PortCVE $Protocol lock"
    Assert-Condition ([int]$lockResult.listener_count -gt 0) "$Protocol lock contained no listeners."
    Assert-Condition ($lockResult.evidence.containers -eq 'complete') "$Protocol lock container evidence was not complete."

    $lockfile = ConvertFrom-CapturedJson -Json ([IO.File]::ReadAllText($lockPath)) -Description "PortCVE $Protocol lockfile"
    Assert-Condition ([int]$lockfile.selector.port -eq $Port) "$Protocol lockfile stored the wrong port selector."
    Assert-Condition ($lockfile.selector.protocol -eq $Protocol) "$Protocol lockfile stored the wrong protocol selector."
    $lockedListeners = @($lockfile.listeners)
    Assert-Condition ($lockedListeners.Count -gt 0) "$Protocol lockfile contained no normalized listeners."
    Assert-Condition (
        @($lockedListeners | Where-Object { $_.owner_identity_strength -eq 'container_image' }).Count -eq $lockedListeners.Count
    ) "$Protocol lockfile did not use container_image identity for every selected listener."

    $checkCapture = Invoke-CapturedCommand -FilePath $script:PortCVEPath -ArgumentList @('check', $lockPath, '--json') -Description "PortCVE $Protocol unchanged check"
    $checkResult = ConvertFrom-CapturedJson -Json $checkCapture.StdOut -Description "PortCVE $Protocol unchanged check"
    Assert-Condition ($checkResult.changed -eq $false) "$Protocol lock/check reported endpoint drift immediately after capture."

    return [pscustomobject]@{
        Protocol = $Protocol
        ListenerCount = [int]$lockResult.listener_count
        Changed = [bool]$checkResult.changed
    }
}

$primaryError = $null
$cleanupErrors = [Collections.Generic.List[string]]::new()
$result = $null

try {
    $dockerVersion = Invoke-CapturedCommand -FilePath $dockerPath -ArgumentList @('version', '--format', '{{.Server.Version}}') -Description 'Docker Engine availability check'
    $serverVersion = $dockerVersion.StdOut.Trim()
    Assert-Condition (-not [string]::IsNullOrWhiteSpace($serverVersion)) 'Docker Engine returned an empty server version.'

    $imageCheck = Invoke-CapturedCommand -FilePath $dockerPath -ArgumentList @('image', 'inspect', $dockerImage) -Description 'Docker image availability check' -AllowFailure
    if ($imageCheck.ExitCode -ne 0) {
        [void](Invoke-CapturedCommand -FilePath $dockerPath -ArgumentList @('pull', $dockerImage) -Description "Docker pull $dockerImage")
    }

    $tcpHostPort = Get-FreeTcpPort
    $udpHostPort = Get-FreeUdpPort
    while ($udpHostPort -eq $tcpHostPort) {
        $udpHostPort = Get-FreeUdpPort
    }

    $tcpPublish = "127.0.0.1:${tcpHostPort}:$tcpContainerPort/tcp"
    $udpPublish = "${udpHostAddress}:${udpHostPort}:$udpContainerPort/udp"
    $containerCommand = 'nc -lk -p 18080 -e cat & exec nc -u -lk -p 18081 -e cat'
    $createArguments = @(
        'container', 'create',
        '--name', $containerName,
        '--label', "$labelName=$runId",
        '--publish', $tcpPublish,
        '--publish', $udpPublish,
        $dockerImage,
        'sh', '-c', $containerCommand
    )

    $containerCreateAttempted = $true
    $createResult = Invoke-CapturedCommand -FilePath $dockerPath -ArgumentList $createArguments -Description 'Docker integration container creation'
    $containerId = $createResult.StdOut.Trim()
    Assert-Condition ($containerId -match '^[0-9a-f]{64}$') 'Docker create did not return one full container ID.'

    [void](Invoke-CapturedCommand -FilePath $dockerPath -ArgumentList @('container', 'start', $containerId) -Description 'Docker integration container start')

    $inspectCapture = Invoke-CapturedCommand -FilePath $dockerPath -ArgumentList @('container', 'inspect', $containerId) -Description 'Docker integration container inspection'
    $inspectObjects = @(ConvertFrom-CapturedJson -Json $inspectCapture.StdOut -Description 'Docker integration container inspection')
    Assert-Condition ($inspectObjects.Count -eq 1) 'Docker inspect did not return exactly one integration container.'
    $containerImageId = [string]$inspectObjects[0].Image
    Assert-Condition ($inspectObjects[0].Name.TrimStart('/') -eq $containerName) 'Docker inspect returned the wrong container name.'
    Assert-Condition ($inspectObjects[0].Config.Labels.$labelName -eq $runId) 'Docker inspect returned the wrong integration label.'
    Assert-Condition ($containerImageId -match '^sha256:[0-9a-f]{64}$') 'Docker inspect did not return a canonical image ID.'

    $tcpPayload = "portcve-tcp-$runId"
    $udpPayload = "portcve-udp-$runId"
    Wait-ForEchoes -TcpPort $tcpHostPort -UdpPort $udpHostPort -TcpPayload $tcpPayload -UdpPayload $udpPayload -Timeout $TimeoutSeconds

    $tcpCim = @(Get-NetTCPConnection -State Listen -LocalPort $tcpHostPort -ErrorAction SilentlyContinue |
        Where-Object { $_.LocalAddress -eq '127.0.0.1' })
    $udpCim = @(Get-NetUDPEndpoint -LocalPort $udpHostPort -ErrorAction SilentlyContinue |
        Where-Object { $_.LocalAddress -eq $udpHostAddress })
    Assert-Condition ($tcpCim.Count -gt 0) 'Windows CIM did not observe the published TCP host tuple.'
    Assert-Condition ($udpCim.Count -gt 0) 'Windows CIM did not observe the published UDP host tuple.'

    $privateCapture = Wait-ForPortCVEMappings -TcpHostPort $tcpHostPort -UdpHostPort $udpHostPort -Timeout $TimeoutSeconds -IncludePrivate
    Assert-PrivateMapping -Matches $privateCapture.TcpMatches -Protocol 'tcp' -HostPort $tcpHostPort -ContainerPort $tcpContainerPort -HostAddress '127.0.0.1' -ExpectedContainerId $containerId -ExpectedContainerName $containerName -ExpectedImageId $containerImageId
    Assert-PrivateMapping -Matches $privateCapture.UdpMatches -Protocol 'udp' -HostPort $udpHostPort -ContainerPort $udpContainerPort -HostAddress $udpHostAddress -ExpectedContainerId $containerId -ExpectedContainerName $containerName -ExpectedImageId $containerImageId

    $defaultCapture = Wait-ForPortCVEMappings -TcpHostPort $tcpHostPort -UdpHostPort $udpHostPort -Timeout $TimeoutSeconds
    Assert-RawValueAbsent -Json $defaultCapture.Raw -Value $containerId -Description 'container ID'
    Assert-RawValueAbsent -Json $defaultCapture.Raw -Value $containerId.Substring(0, 12) -Description 'short container ID'
    Assert-RawValueAbsent -Json $defaultCapture.Raw -Value $containerName -Description 'container name'
    Assert-RawValueAbsent -Json $defaultCapture.Raw -Value $containerImageId -Description 'container image ID'
    Assert-RawValueAbsent -Json $defaultCapture.Raw -Value $dockerImage -Description 'container image reference'

    $lockChecks = @()
    if ($ValidateLockCheck) {
        $lockChecks += Test-LockCheckRoundTrip -Protocol 'tcp' -Port $tcpHostPort
        $lockChecks += Test-LockCheckRoundTrip -Protocol 'udp' -Port $udpHostPort
    }

    $remoteScan = $null
    if ($ValidateRemoteScan) {
        $remoteScan = Test-RemoteEchoScan -HostPort $tcpHostPort
    }

    $result = [ordered]@{
        status = 'passed'
        docker_server_version = $serverVersion
        portcve_path = $PortCVEPath
        container_name = $containerName
        tcp = [ordered]@{
            host_address = '127.0.0.1'
            host_port = $tcpHostPort
            container_port = $tcpContainerPort
            echo = 'passed'
            private_mapping_count = @($privateCapture.TcpMatches).Count
            default_mapping_count = @($defaultCapture.TcpMatches).Count
        }
        udp = [ordered]@{
            host_address = $udpHostAddress
            host_port = $udpHostPort
            container_port = $udpContainerPort
            echo = 'passed'
            private_mapping_count = @($privateCapture.UdpMatches).Count
            default_mapping_count = @($defaultCapture.UdpMatches).Count
        }
        docker_collector = 'complete'
        windows_cim = 'passed'
        default_json_redaction = 'passed'
        lock_check = if ($ValidateLockCheck) { 'passed' } else { 'skipped' }
        lock_checks = $lockChecks
        authorized_remote_scan = if ($ValidateRemoteScan) { 'passed' } else { 'skipped' }
        remote_scan = $remoteScan
    }
}
catch {
    $primaryError = $_
}
finally {
    if ($containerCreateAttempted) {
        try {
            $inspectTarget = if ([string]::IsNullOrWhiteSpace($containerId)) { $containerName } else { $containerId }
            $cleanupInspect = Invoke-CapturedCommand -FilePath $dockerPath -ArgumentList @('container', 'inspect', $inspectTarget) -Description 'Docker cleanup inspection' -AllowFailure
            if ($cleanupInspect.ExitCode -eq 0) {
                $cleanupObjects = @(ConvertFrom-CapturedJson -Json $cleanupInspect.StdOut -Description 'Docker cleanup inspection')
                Assert-Condition ($cleanupObjects.Count -eq 1) 'Cleanup inspection did not return exactly one container.'
                $cleanupObject = $cleanupObjects[0]
                Assert-Condition ($cleanupObject.Name.TrimStart('/') -eq $containerName) 'Cleanup target name did not match the integration container.'
                Assert-Condition ($cleanupObject.Config.Labels.$labelName -eq $runId) 'Cleanup target label did not match the integration run.'
                if (-not [string]::IsNullOrWhiteSpace($containerId)) {
                    Assert-Condition ($cleanupObject.Id -eq $containerId) 'Cleanup target ID did not match the created integration container.'
                }

                [void](Invoke-CapturedCommand -FilePath $dockerPath -ArgumentList @('container', 'rm', '--force', $cleanupObject.Id) -Description 'Docker integration container cleanup')
            }
            else {
                $daemonCheck = Invoke-CapturedCommand -FilePath $dockerPath -ArgumentList @('version', '--format', '{{.Server.Version}}') -Description 'Docker cleanup daemon check' -AllowFailure
                if ($daemonCheck.ExitCode -ne 0) {
                    throw 'Docker became unavailable before cleanup; integration container absence could not be confirmed.'
                }
            }
        }
        catch {
            [void]$cleanupErrors.Add("Container cleanup failed: $($_.Exception.Message)")
        }
    }

    try {
        if (Test-Path -LiteralPath $integrationTempDirectory) {
            $resolvedTemporaryDirectory = (Resolve-Path -LiteralPath $integrationTempDirectory).Path
            Assert-Condition ($resolvedTemporaryDirectory.Equals($integrationTempDirectory, [StringComparison]::OrdinalIgnoreCase)) 'Temporary cleanup target changed unexpectedly.'
            Assert-Condition ($resolvedTemporaryDirectory.StartsWith($temporaryPrefix, [StringComparison]::OrdinalIgnoreCase)) 'Temporary cleanup target escaped the system temporary directory.'
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

$result | ConvertTo-Json -Depth 6

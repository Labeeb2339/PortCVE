#requires -Version 5.1

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$installerPath = Join-Path $repositoryRoot 'scripts\install.ps1'
$finalizerPath = Join-Path $repositoryRoot 'scripts\Finalize-ReleaseInstaller.ps1'
$releaseWorkflowPath = Join-Path $repositoryRoot '.github\workflows\release.yml'
$source = [IO.File]::ReadAllText($installerPath)
$tokens = $null
$parseErrors = $null
$ast = [Management.Automation.Language.Parser]::ParseInput($source, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count -ne 0) {
    throw "Installer has PowerShell syntax errors: $($parseErrors.Message -join '; ')"
}

$script:Passed = 0
function Assert-True {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
    $script:Passed++
}

function Assert-Throws {
    param([scriptblock]$Action, [string]$Message)
    try { & $Action; throw "Expected failure: $Message" }
    catch {
        if ($_.Exception.Message -eq "Expected failure: $Message") { throw }
        $script:Passed++
    }
}

$placeholderMatches = [regex]::Matches($source, [regex]::Escape('__PORTCVE_EXPECTED_SIGNER_SUBJECT__'))
Assert-True ($placeholderMatches.Count -eq 1) 'Installer must contain exactly one release-time signer placeholder.'

$parameterNames = @($ast.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath })
Assert-True (($parameterNames -join ',') -ceq 'Version,InstallDirectory') 'Installer exposed an unexpected production parameter.'
Assert-True ($source -notmatch '(?i)skip(signature|checksum)|allowunsigned|localassets?|testassets?') 'Installer contains a bypass or local-asset surface.'
Assert-True ($source -notmatch '(?i)Rfc3161|1\.3\.6\.1\.4\.1\.311\.3\.3\.1') 'PowerShell 5.1 installer contains an unsupported independent RFC 3161 claim or OID-only check.'

$forbiddenCommands = @('cmd', 'cmd.exe', 'curl', 'curl.exe', 'Invoke-Expression', 'Start-Process')
$commands = @($ast.FindAll({
            param($node)
            $node -is [Management.Automation.Language.CommandAst]
        }, $true) | ForEach-Object { $_.GetCommandName() } | Where-Object { $null -ne $_ })
foreach ($forbidden in $forbiddenCommands) {
    Assert-True ($commands -cnotcontains $forbidden) "Installer shells out through forbidden command '$forbidden'."
}

$entrypointMarker = '# PORTCVE_INSTALLER_ENTRYPOINT'
$markerIndex = $source.IndexOf($entrypointMarker, [StringComparison]::Ordinal)
Assert-True ($markerIndex -gt 0) 'Installer entrypoint marker is missing.'
$librarySource = $source.Substring(0, $markerIndex)
Invoke-Expression $librarySource

$workflowSource = [IO.File]::ReadAllText($releaseWorkflowPath)
$workflowPatternMatch = [regex]::Match($workflowSource, "(?m)^\s+\`$pattern = '(?<pattern>[^']+)'\s*$")
Assert-True $workflowPatternMatch.Success 'Release workflow tag pattern was not found.'
Assert-True ([StringComparer]::Ordinal.Equals($workflowPatternMatch.Groups['pattern'].Value, $script:ReleaseTagPattern)) 'Workflow and installer release-tag patterns diverged.'
foreach ($acceptedTag in @('v1.0.0', 'v1.0.0-rc.1', 'v2.3.4-1rc.2')) {
    Assert-True ([regex]::IsMatch($acceptedTag, $script:ReleaseTagPattern)) "Compatible release tag '$acceptedTag' was rejected."
}
foreach ($rejectedTag in @('1.0.0', 'v01.0.0', 'v1.0.0-01', 'v1.0.0--rc', 'v1.0.0+build.1')) {
    Assert-True (-not [regex]::IsMatch($rejectedTag, $script:ReleaseTagPattern)) "Out-of-policy release tag '$rejectedTag' was accepted."
}

$testParent = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd(
    [IO.Path]::DirectorySeparatorChar,
    [IO.Path]::AltDirectorySeparatorChar)
$testLeaf = 'portcve-installer-tests-' + [Guid]::NewGuid().ToString('N')
$testRoot = Join-Path $testParent $testLeaf
[IO.Directory]::CreateDirectory($testRoot) | Out-Null
try {
    $assetName = 'portcve-v1.0.0-win-x64.zip'
    $assetPath = Join-Path $testRoot $assetName
    [IO.File]::WriteAllBytes($assetPath, [byte[]](1, 2, 3, 4, 5))
    $hash = Get-Sha256 $assetPath
    $sumPath = Join-Path $testRoot 'SHA256SUMS.txt'
    [IO.File]::WriteAllText($sumPath, "$hash  $assetName`r`n", [Text.UTF8Encoding]::new($false))
    Assert-True ((Get-ExpectedChecksum -ChecksumPath $sumPath -AssetName $assetName) -ceq $hash) 'Exact checksum lookup failed.'

    [IO.File]::WriteAllText($sumPath, "$hash  $assetName`r`n$hash  $assetName`r`n", [Text.UTF8Encoding]::new($false))
    Assert-Throws { Get-ExpectedChecksum -ChecksumPath $sumPath -AssetName $assetName } 'Duplicate checksum entry was accepted.'

    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $safeZip = Join-Path $testRoot 'safe.zip'
    $archive = [IO.Compression.ZipFile]::Open($safeZip, [IO.Compression.ZipArchiveMode]::Create)
    try {
        $entry = $archive.CreateEntry('portcve.exe')
        $stream = $entry.Open()
        try { $stream.Write([byte[]](77, 90, 1, 2), 0, 4) } finally { $stream.Dispose() }
        $null = $archive.CreateEntry('docs/readme.txt')
    }
    finally { $archive.Dispose() }
    $expanded = Join-Path $testRoot 'expanded'
    $expandedExe = Expand-PortCVEExecutable -ZipPath $safeZip -DestinationDirectory $expanded
    Assert-True ([IO.File]::Exists($expandedExe)) 'Safe archive did not produce portcve.exe.'

    $unsafeZip = Join-Path $testRoot 'unsafe.zip'
    $archive = [IO.Compression.ZipFile]::Open($unsafeZip, [IO.Compression.ZipArchiveMode]::Create)
    try { $null = $archive.CreateEntry('../portcve.exe') } finally { $archive.Dispose() }
    Assert-Throws { Expand-PortCVEExecutable -ZipPath $unsafeZip -DestinationDirectory (Join-Path $testRoot 'unsafe-expanded') } 'Zip traversal entry was accepted.'

    $installPath = Join-Path $testRoot 'PortCVE'
    $updatedPath = Get-UpdatedUserPath -CurrentPath 'C:\Windows' -InstallPath $installPath
    Assert-True ($updatedPath.EndsWith(";$installPath", [StringComparison]::OrdinalIgnoreCase)) 'User PATH was not extended safely.'
    Assert-True ((Get-UpdatedUserPath -CurrentPath "C:\Windows;$installPath" -InstallPath $installPath) -ceq "C:\Windows;$installPath") 'Duplicate PATH entry was added.'

    [IO.Directory]::CreateDirectory($installPath) | Out-Null
    [IO.File]::WriteAllText((Join-Path $installPath 'unexpected.txt'), 'x')
    Assert-Throws { Assert-SafeInstallTarget $installPath } 'Unmanaged install content was accepted.'
    [IO.File]::Delete((Join-Path $installPath 'unexpected.txt'))
    [IO.File]::WriteAllText((Join-Path $installPath 'portcve.exe'), 'old')

    $token = [Guid]::NewGuid().ToString('N')
    $staging = "$installPath.staging-$token"
    [IO.Directory]::CreateDirectory($staging) | Out-Null
    [IO.File]::WriteAllText((Join-Path $staging 'portcve.exe'), 'new')
    [IO.File]::WriteAllText((Join-Path $staging 'install-receipt.json'), '{}')
    Invoke-AtomicInstall -InstallPath $installPath -StagingPath $staging -Token $token -OriginalUserPath 'unchanged' -UpdatedUserPath 'unchanged'
    Assert-True (([IO.File]::ReadAllText((Join-Path $installPath 'portcve.exe'))) -ceq 'new') 'Atomic replacement did not install staged bytes.'

    $unicodeSubject = "CN=Jos$([char]0x00e9) O'Brien, O=PortCVE"
    $finalizedPath = Join-Path $testRoot 'finalized\install.ps1'
    $null = & $finalizerPath -TemplatePath $installerPath -OutputPath $finalizedPath -ExpectedSignerSubject $unicodeSubject
    $finalizedBytes = [IO.File]::ReadAllBytes($finalizedPath)
    Assert-True ($finalizedBytes.Length -ge 3 -and $finalizedBytes[0] -eq 0xef -and $finalizedBytes[1] -eq 0xbb -and $finalizedBytes[2] -eq 0xbf) 'Finalized installer is not UTF-8 with BOM.'

    # This harness runs under Windows PowerShell 5.1. ParseFile therefore proves
    # the BOM preserves a non-ASCII subject for the supported legacy host.
    $finalizedTokens = $null
    $finalizedErrors = $null
    $finalizedAst = [Management.Automation.Language.Parser]::ParseFile($finalizedPath, [ref]$finalizedTokens, [ref]$finalizedErrors)
    Assert-True ($finalizedErrors.Count -eq 0) 'PowerShell 5.1 could not parse the BOM-finalized installer.'
    $subjectAssignments = @($finalizedAst.FindAll({
                param($node)
                $node -is [Management.Automation.Language.AssignmentStatementAst] -and
                    [StringComparer]::Ordinal.Equals($node.Left.Extent.Text, '$script:ExpectedSignerSubject')
            }, $true))
    $subjectPreserved = $subjectAssignments.Count -eq 1 -and
        $subjectAssignments[0].Right -is [Management.Automation.Language.CommandExpressionAst] -and
        $subjectAssignments[0].Right.Expression -is [Management.Automation.Language.StringConstantExpressionAst] -and
        [StringComparer]::Ordinal.Equals([string]$subjectAssignments[0].Right.Expression.Value, $unicodeSubject)
    Assert-True $subjectPreserved 'PowerShell 5.1 did not preserve the exact non-ASCII signer subject.'

    $forbiddenInstallPath = Join-Path $testRoot 'must-not-exist'
    Assert-Throws { & $finalizedPath -Version 'v1.0.0' -InstallDirectory $forbiddenInstallPath } 'Unsigned finalized installer was accepted.'
    Assert-True (-not (Test-Path -LiteralPath $forbiddenInstallPath)) 'Unsigned installer mutated the install target before rejecting its own signature.'
}
finally {
    $resolved = [IO.Path]::GetFullPath($testRoot)
    if ((Split-Path -Parent $resolved) -ne $testParent -or (Split-Path -Leaf $resolved) -ne $testLeaf) {
        throw "Refusing test cleanup outside validated root '$testParent'."
    }
    if (Test-Path -LiteralPath $resolved) { Remove-Item -LiteralPath $resolved -Recurse -Force }
}

Assert-Throws { & $installerPath -Version 'v1.0.0' } 'Unfinalized template did not fail closed before network access.'

Write-Host "Installer offline checks passed: $script:Passed"

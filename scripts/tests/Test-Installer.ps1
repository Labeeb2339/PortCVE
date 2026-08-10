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
Assert-True (($parameterNames -join ',') -ceq 'Version,InstallDirectory,Uninstall') 'Installer exposed an unexpected production parameter.'
Assert-True ($source -notmatch '(?i)skip(signature|checksum)|allowunsigned|localassets?|testassets?') 'Installer contains a bypass or local-asset surface.'
Assert-True ($source -notmatch '(?i)Rfc3161|1\.3\.6\.1\.4\.1\.311\.3\.3\.1') 'PowerShell 5.1 installer contains an unsupported independent RFC 3161 claim or OID-only check.'
Assert-True ($source -cmatch "\`$script:Repository = 'Labeeb2339/PortCVE'") 'Installer repository identity is not the exact PortCVE repository.'

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
Assert-True ($workflowSource -notmatch '(?i)BindWitness') 'Release workflow still contains the former project name.'
Assert-True ($workflowSource -cmatch 'portcve-\$\(\$env:RELEASE_TAG\)-win-x64\.zip') 'Release workflow does not create the canonical PortCVE ZIP name.'
Assert-True ($workflowSource -cmatch 'Test installer lifecycle under Windows PowerShell 5\.1') 'Release workflow does not gate on the PowerShell 5.1 lifecycle harness.'
Assert-True ($workflowSource -cmatch 'Portable ZIP, standalone executable, and signing metadata') 'Release workflow does not bind the portable ZIP to the signed executable metadata.'
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
    Assert-Throws { Assert-SafeInstallTarget '\\server\share\PortCVE' } 'UNC install target was accepted.'
    Assert-Throws { Assert-SafeInstallTarget 'C:\Temp\PortCVE.' } 'Trailing-dot install target was accepted.'
    Assert-Throws { Assert-SafeInstallTarget 'C:\Temp\NUL' } 'Reserved-device install target was accepted.'
    Assert-Throws { Assert-SafeInstallTarget 'C:\Temp\%TEMP%\PortCVE' } 'Environment-expanding install target was accepted.'
    $updatedPath = Get-UpdatedUserPath -CurrentPath 'C:\Windows' -InstallPath $installPath
    Assert-True ($updatedPath.EndsWith(";$installPath", [StringComparison]::OrdinalIgnoreCase)) 'User PATH was not extended safely.'
    Assert-True ((Get-UpdatedUserPath -CurrentPath "C:\Windows;$installPath" -InstallPath $installPath) -ceq "C:\Windows;$installPath") 'Duplicate PATH entry was added.'
    $removedPath = Get-UserPathWithoutInstall -CurrentPath "C:\Windows;$installPath;C:\Tools;$installPath" -InstallPath $installPath
    Assert-True ($removedPath -ceq 'C:\Windows;C:\Tools') 'Uninstall did not remove every exact PortCVE PATH entry.'
    Assert-True ((Get-UserPathWithoutInstall -CurrentPath "C:\Windows;${installPath}-other" -InstallPath $installPath) -ceq "C:\Windows;${installPath}-other") 'Uninstall removed a non-exact PATH entry.'

    [IO.Directory]::CreateDirectory($installPath) | Out-Null
    [IO.File]::WriteAllText((Join-Path $installPath 'unexpected.txt'), 'x')
    Assert-Throws { Assert-SafeInstallTarget $installPath } 'Unmanaged install content was accepted.'
    [IO.File]::Delete((Join-Path $installPath 'unexpected.txt'))
    [IO.Directory]::Delete($installPath)

    function New-LifecycleStage {
        param(
            [Parameter(Mandatory = $true)][string]$StagePath,
            [Parameter(Mandatory = $true)][string]$FinalInstallPath,
            [Parameter(Mandatory = $true)][string]$Version,
            [Parameter(Mandatory = $true)][string]$ExecutableText
        )

        [IO.Directory]::CreateDirectory($StagePath) | Out-Null
        $executablePath = Join-Path $StagePath 'portcve.exe'
        [IO.File]::WriteAllText($executablePath, $ExecutableText, [Text.UTF8Encoding]::new($false))
        $installedInstallerPath = Join-Path $StagePath 'install.ps1'
        [IO.File]::WriteAllText($installedInstallerPath, '# signed-installer-fixture', [Text.UTF8Encoding]::new($false))
        $receipt = [ordered]@{
            schema_version = 1
            product = 'PortCVE'
            version = $Version
            repository = 'Labeeb2339/PortCVE'
            install_path = $FinalInstallPath
            zip_asset = "portcve-$Version-win-x64.zip"
            zip_sha256 = 'a' * 64
            executable_sha256 = Get-Sha256 $executablePath
            installer_sha256 = Get-Sha256 $installedInstallerPath
            signer_subject = 'CN=PortCVE Test Signer'
            timestamp_subject = 'CN=PortCVE Test TSA'
            installed_at_utc = '2026-08-10T00:00:00.0000000Z'
        } | ConvertTo-Json
        [IO.File]::WriteAllText((Join-Path $StagePath 'install-receipt.json'), $receipt + "`r`n", [Text.UTF8Encoding]::new($false))
    }

    # The lifecycle fixture uses deterministic Authenticode results so the
    # production signature path is exercised without trusting a test root CA.
    $originalExpectedSignerSubject = $script:ExpectedSignerSubject
    $originalEkuFunction = (Get-Item Function:\Test-CertificateEku).ScriptBlock
    $script:ExpectedSignerSubject = 'CN=PortCVE Test Signer'
    $script:AuthenticodeFixtureValid = $true
    function Test-CertificateEku { return $true }
    function Get-AuthenticodeSignature {
        param([Parameter(Mandatory = $true)][string]$LiteralPath)

        if (-not $script:AuthenticodeFixtureValid) {
            return [pscustomobject]@{
                Status = [Management.Automation.SignatureStatus]::NotSigned
                StatusMessage = 'offline invalid-signature fixture'
                SignatureType = 'None'
                SignerCertificate = $null
                TimeStamperCertificate = $null
            }
        }
        return [pscustomobject]@{
            Status = [Management.Automation.SignatureStatus]::Valid
            StatusMessage = 'offline valid-signature fixture'
            SignatureType = 'Authenticode'
            SignerCertificate = [pscustomobject]@{ Subject = 'CN=PortCVE Test Signer' }
            TimeStamperCertificate = [pscustomobject]@{ Subject = 'CN=PortCVE Test TSA' }
        }
    }

    # Offline lifecycle fixture: clean install.
    $cleanToken = [Guid]::NewGuid().ToString('N')
    $cleanStage = "$installPath.staging-$cleanToken"
    New-LifecycleStage -StagePath $cleanStage -FinalInstallPath $installPath -Version 'v1.0.0' -ExecutableText 'version-one'
    Invoke-AtomicInstall -InstallPath $installPath -StagingPath $cleanStage -Token $cleanToken -OriginalUserPath 'unchanged' -UpdatedUserPath 'unchanged'
    $null = Assert-ManagedInstallation $installPath
    Assert-True (([IO.File]::ReadAllText((Join-Path $installPath 'portcve.exe'))) -ceq 'version-one') 'Clean install did not install staged bytes.'
    Assert-True (Test-Path -LiteralPath (Join-Path $installPath 'install.ps1') -PathType Leaf) 'Clean install did not retain its signed maintenance script fixture.'

    # Update replaces the exact managed directory and receipt.
    $updateToken = [Guid]::NewGuid().ToString('N')
    $updateStage = "$installPath.staging-$updateToken"
    New-LifecycleStage -StagePath $updateStage -FinalInstallPath $installPath -Version 'v1.1.0' -ExecutableText 'version-two'
    Invoke-AtomicInstall -InstallPath $installPath -StagingPath $updateStage -Token $updateToken -OriginalUserPath 'unchanged' -UpdatedUserPath 'unchanged'
    $updatedReceipt = Read-PortCVEInstallReceipt $installPath
    Assert-True (([string]$updatedReceipt.version -ceq 'v1.1.0') -and ([IO.File]::ReadAllText((Join-Path $installPath 'portcve.exe')) -ceq 'version-two')) 'Update did not replace the executable and receipt together.'

    $lateAddedChild = Join-Path $installPath 'added-after-validation.txt'
    [IO.File]::WriteAllText($lateAddedChild, 'must block commit')
    Assert-Throws { Assert-InstallTargetReadyForCommit $installPath } 'A child added after initial validation was accepted at commit.'
    [IO.File]::Delete($lateAddedChild)
    $null = Assert-InstallTargetReadyForCommit $installPath

    $script:AuthenticodeFixtureValid = $false
    Assert-Throws { Assert-ManagedInstallation $installPath } 'Invalid installed signatures were accepted as managed.'
    $script:AuthenticodeFixtureValid = $true

    $installedExecutablePath = Join-Path $installPath 'portcve.exe'
    $installedInstallerPath = Join-Path $installPath 'install.ps1'
    $installedReceiptPath = Join-Path $installPath 'install-receipt.json'
    $originalExecutableBytes = [IO.File]::ReadAllBytes($installedExecutablePath)
    $originalInstallerBytes = [IO.File]::ReadAllBytes($installedInstallerPath)
    $originalReceiptBytes = [IO.File]::ReadAllBytes($installedReceiptPath)

    [IO.File]::WriteAllText($installedExecutablePath, 'tampered-executable')
    Assert-Throws { Assert-InstallTargetReadyForCommit $installPath } 'Executable tampering after initial validation was accepted at commit.'
    [IO.File]::WriteAllBytes($installedExecutablePath, $originalExecutableBytes)

    [IO.File]::WriteAllText($installedInstallerPath, '# tampered-installer')
    Assert-Throws { Assert-ManagedInstallation $installPath } 'Tampered installed maintenance script still matched the managed receipt.'
    [IO.File]::WriteAllBytes($installedInstallerPath, $originalInstallerBytes)

    $tamperedReceipt = [IO.File]::ReadAllText($installedReceiptPath) | ConvertFrom-Json
    $tamperedReceipt.executable_sha256 = 'b' * 64
    [IO.File]::WriteAllText($installedReceiptPath, ($tamperedReceipt | ConvertTo-Json) + "`r`n", [Text.UTF8Encoding]::new($false))
    Assert-Throws { Assert-ManagedInstallation $installPath } 'Forged executable hash in the managed receipt was accepted.'
    [IO.File]::WriteAllBytes($installedReceiptPath, $originalReceiptBytes)

    $tamperedReceipt = [IO.File]::ReadAllText($installedReceiptPath) | ConvertFrom-Json
    $tamperedReceipt.installer_sha256 = 'c' * 64
    [IO.File]::WriteAllText($installedReceiptPath, ($tamperedReceipt | ConvertTo-Json) + "`r`n", [Text.UTF8Encoding]::new($false))
    Assert-Throws { Assert-ManagedInstallation $installPath } 'Forged installer hash in the managed receipt was accepted.'
    [IO.File]::WriteAllBytes($installedReceiptPath, $originalReceiptBytes)

    $tamperedReceipt = [IO.File]::ReadAllText($installedReceiptPath) | ConvertFrom-Json
    $tamperedReceipt.signer_subject = 'CN=Unexpected Signer'
    [IO.File]::WriteAllText($installedReceiptPath, ($tamperedReceipt | ConvertTo-Json) + "`r`n", [Text.UTF8Encoding]::new($false))
    Assert-Throws { Assert-ManagedInstallation $installPath } 'Forged signer identity in the managed receipt was accepted.'
    [IO.File]::WriteAllBytes($installedReceiptPath, $originalReceiptBytes)
    $null = Assert-ManagedInstallation $installPath

    Push-Location $installPath
    try {
        Assert-Throws { Invoke-PortCVEUninstall $installPath } 'Uninstall was allowed while the current directory was inside the managed target.'
    }
    finally {
        Pop-Location
    }
    Assert-True (Test-Path -LiteralPath $installPath -PathType Container) 'Rejected in-directory uninstall changed the managed installation.'

    # A pre-commit update failure restores the complete prior installation.
    $rollbackToken = [Guid]::NewGuid().ToString('N')
    $missingStage = "$installPath.staging-$rollbackToken"
    Assert-Throws {
        Invoke-AtomicInstall -InstallPath $installPath -StagingPath $missingStage -Token $rollbackToken -OriginalUserPath 'unchanged' -UpdatedUserPath 'unchanged'
    } 'Failed update did not report an error.'
    $rollbackReceipt = Read-PortCVEInstallReceipt $installPath
    Assert-True (([string]$rollbackReceipt.version -ceq 'v1.1.0') -and ([IO.File]::ReadAllText((Join-Path $installPath 'portcve.exe')) -ceq 'version-two')) 'Failed update did not restore the prior installation.'
    Assert-True (-not (Test-Path -LiteralPath "$installPath.backup-$rollbackToken")) 'Failed update left its guarded backup behind.'

    # Uninstall removes the exact receipt-bound installation.
    $uninstallToken = [Guid]::NewGuid().ToString('N')
    Invoke-AtomicUninstall -InstallPath $installPath -Token $uninstallToken -OriginalUserPath 'unchanged' -UpdatedUserPath 'unchanged'
    Assert-True (-not (Test-Path -LiteralPath $installPath)) 'Uninstall left the managed installation in place.'
    Assert-True (-not (Test-Path -LiteralPath "$installPath.uninstall-$uninstallToken")) 'Uninstall left its quarantine directory behind.'

    Remove-Item Function:\Get-AuthenticodeSignature
    Set-Item Function:\Test-CertificateEku -Value $originalEkuFunction
    $script:ExpectedSignerSubject = $originalExpectedSignerSubject

    # Receipt validation prevents an identically named but unmanaged directory
    # from entering the update or uninstall lifecycle.
    [IO.Directory]::CreateDirectory($installPath) | Out-Null
    [IO.File]::WriteAllText((Join-Path $installPath 'portcve.exe'), 'not-managed')
    [IO.File]::WriteAllText((Join-Path $installPath 'install.ps1'), '# not-managed')
    [IO.File]::WriteAllText((Join-Path $installPath 'install-receipt.json'), '{}')
    Assert-Throws { Assert-ManagedInstallation $installPath } 'Invalid receipt was accepted as a managed installation.'
    [IO.Directory]::Delete($installPath, $true)

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
    Assert-Throws { & $finalizedPath -Uninstall -InstallDirectory $forbiddenInstallPath } 'Unsigned finalized uninstaller was accepted.'
    Assert-True (-not (Test-Path -LiteralPath $forbiddenInstallPath)) 'Unsigned uninstaller mutated the target before rejecting its own signature.'
}
finally {
    $resolved = [IO.Path]::GetFullPath($testRoot)
    if ((Split-Path -Parent $resolved) -ne $testParent -or (Split-Path -Leaf $resolved) -ne $testLeaf) {
        throw "Refusing test cleanup outside validated root '$testParent'."
    }
    if (Test-Path -LiteralPath $resolved) { Remove-Item -LiteralPath $resolved -Recurse -Force }
}

Assert-Throws { & $installerPath -Version 'v1.0.0' } 'Unfinalized template did not fail closed before network access.'
Assert-Throws { & $installerPath -Uninstall } 'Unfinalized template did not fail closed before uninstall activity.'

Write-Host "Installer offline checks passed: $script:Passed"

#requires -Version 5.1

<#
.SYNOPSIS
Installs a signed PortCVE release for the current Windows user.

.DESCRIPTION
Downloads a versioned ZIP and SHA256SUMS.txt from the official
Labeeb2339/PortCVE GitHub release, verifies the ZIP checksum, then requires a
trusted Authenticode signature, the release-bound signer subject, the Code
Signing EKU, and an RFC 3161 timestamp before installing portcve.exe.

This script has no unsigned, local-asset, or signature-bypass mode.
#>
[CmdletBinding()]
param(
    [string]$Version,
    [string]$InstallDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$script:Repository = 'Labeeb2339/PortCVE'
$script:ExpectedSignerSubject = '__PORTCVE_EXPECTED_SIGNER_SUBJECT__'
$script:InstallerUserAgent = 'PortCVE-Installer/1.0'
$script:ApiLimitBytes = 2MB
$script:ChecksumLimitBytes = 128KB
$script:ZipLimitBytes = 256MB
$script:ExecutableLimitBytes = 256MB
$script:MaximumArchiveEntries = 256
$script:MaximumExpandedBytes = 512MB
$script:ConnectTimeoutMilliseconds = 30000
$script:ReadTimeoutMilliseconds = 30000
$script:MaximumDownloadSeconds = 300

function Test-AllowedGitHubHost {
    param([Parameter(Mandatory = $true)][string]$HostName)

    return $HostName.Equals('github.com', [StringComparison]::OrdinalIgnoreCase) `
        -or $HostName.Equals('api.github.com', [StringComparison]::OrdinalIgnoreCase) `
        -or $HostName.EndsWith('.githubusercontent.com', [StringComparison]::OrdinalIgnoreCase)
}

function Save-BoundedHttpsFile {
    param(
        [Parameter(Mandatory = $true)][Uri]$Uri,
        [Parameter(Mandatory = $true)][string]$Destination,
        [Parameter(Mandatory = $true)][long]$MaximumBytes
    )

    if ($Uri.Scheme -cne 'https' -or -not (Test-AllowedGitHubHost $Uri.DnsSafeHost)) {
        throw "Refusing non-GitHub HTTPS download URI '$Uri'."
    }

    $request = [Net.HttpWebRequest]::Create($Uri)
    $request.Method = 'GET'
    $request.UserAgent = $script:InstallerUserAgent
    $request.Accept = 'application/vnd.github+json, application/octet-stream'
    $request.AllowAutoRedirect = $true
    $request.MaximumAutomaticRedirections = 5
    $request.Timeout = $script:ConnectTimeoutMilliseconds
    $request.ReadWriteTimeout = $script:ReadTimeoutMilliseconds

    $response = $null
    $inputStream = $null
    $outputStream = $null
    try {
        $response = [Net.HttpWebResponse]$request.GetResponse()
        if (-not (Test-AllowedGitHubHost $response.ResponseUri.DnsSafeHost)) {
            throw "GitHub redirected the download to an unapproved host '$($response.ResponseUri.DnsSafeHost)'."
        }

        if ($response.ContentLength -gt $MaximumBytes) {
            throw "Download '$Uri' declares $($response.ContentLength) bytes; limit is $MaximumBytes bytes."
        }

        $inputStream = $response.GetResponseStream()
        $outputStream = [IO.File]::Open($Destination, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        $buffer = New-Object byte[] 65536
        $total = 0L
        $timer = [Diagnostics.Stopwatch]::StartNew()
        while (($read = $inputStream.Read($buffer, 0, $buffer.Length)) -gt 0) {
            $total += $read
            if ($total -gt $MaximumBytes) {
                throw "Download '$Uri' exceeded the $MaximumBytes-byte limit."
            }
            if ($timer.Elapsed.TotalSeconds -gt $script:MaximumDownloadSeconds) {
                throw "Download '$Uri' exceeded the $($script:MaximumDownloadSeconds)-second limit."
            }
            $outputStream.Write($buffer, 0, $read)
        }
        $outputStream.Flush()
    }
    finally {
        if ($null -ne $outputStream) { $outputStream.Dispose() }
        if ($null -ne $inputStream) { $inputStream.Dispose() }
        if ($null -ne $response) { $response.Dispose() }
    }
}

function Read-BoundedUtf8File {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][long]$MaximumBytes
    )

    $file = Get-Item -LiteralPath $Path
    if ($file.Length -gt $MaximumBytes) {
        throw "File '$Path' exceeds the $MaximumBytes-byte limit."
    }
    return [IO.File]::ReadAllText($file.FullName, [Text.UTF8Encoding]::new($false, $true))
}

function Resolve-Release {
    param(
        [string]$RequestedVersion,
        [Parameter(Mandatory = $true)][string]$WorkingDirectory
    )

    $tag = $null
    if (-not [string]::IsNullOrWhiteSpace($RequestedVersion)) {
        $tag = $RequestedVersion.Trim()
        if (-not $tag.StartsWith('v', [StringComparison]::Ordinal)) { $tag = "v$tag" }
        if ($tag -cnotmatch '^v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z][0-9A-Za-z.-]*)?(?:\+[0-9A-Za-z][0-9A-Za-z.-]*)?$') {
            throw "Version '$RequestedVersion' is not a supported semantic release tag."
        }
        $apiUri = [Uri]("https://api.github.com/repos/{0}/releases/tags/{1}" -f $script:Repository, [Uri]::EscapeDataString($tag))
    }
    else {
        $apiUri = [Uri]("https://api.github.com/repos/{0}/releases/latest" -f $script:Repository)
    }

    $metadataPath = Join-Path $WorkingDirectory 'release.json'
    Save-BoundedHttpsFile -Uri $apiUri -Destination $metadataPath -MaximumBytes $script:ApiLimitBytes
    $release = Read-BoundedUtf8File -Path $metadataPath -MaximumBytes $script:ApiLimitBytes | ConvertFrom-Json
    $resolvedTag = [string]$release.tag_name
    if ($resolvedTag -cnotmatch '^v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z][0-9A-Za-z.-]*)?(?:\+[0-9A-Za-z][0-9A-Za-z.-]*)?$') {
        throw "GitHub returned unsupported release tag '$resolvedTag'."
    }
    if ($null -ne $tag -and $resolvedTag -cne $tag) {
        throw "GitHub returned tag '$resolvedTag' when '$tag' was requested."
    }
    if ([bool]$release.draft) { throw "Refusing draft release '$resolvedTag'." }

    $zipName = "portcve-$resolvedTag-win-x64.zip"
    $assets = @($release.assets)
    $zipAssets = @($assets | Where-Object { $null -ne $_ -and [string]::Equals([string]$_.name, $zipName, [StringComparison]::Ordinal) })
    $sumAssets = @($assets | Where-Object { $null -ne $_ -and [string]::Equals([string]$_.name, 'SHA256SUMS.txt', [StringComparison]::Ordinal) })
    if ($zipAssets.Count -ne 1 -or $sumAssets.Count -ne 1) {
        throw "Release '$resolvedTag' must contain exactly one '$zipName' and one 'SHA256SUMS.txt' asset."
    }
    if ([long]$zipAssets[0].size -le 0 -or [long]$zipAssets[0].size -gt $script:ZipLimitBytes) {
        throw "Release ZIP size is missing or exceeds the installer limit."
    }
    if ([long]$sumAssets[0].size -le 0 -or [long]$sumAssets[0].size -gt $script:ChecksumLimitBytes) {
        throw "Checksum asset size is missing or exceeds the installer limit."
    }

    return [pscustomobject]@{
        Tag = $resolvedTag
        ZipName = $zipName
        ZipUri = [Uri][string]$zipAssets[0].browser_download_url
        ChecksumUri = [Uri][string]$sumAssets[0].browser_download_url
    }
}

function Get-ExpectedChecksum {
    param(
        [Parameter(Mandatory = $true)][string]$ChecksumPath,
        [Parameter(Mandatory = $true)][string]$AssetName
    )

    $text = Read-BoundedUtf8File -Path $ChecksumPath -MaximumBytes $script:ChecksumLimitBytes
    $foundHashes = New-Object 'Collections.Generic.List[string]'
    foreach ($line in ($text -split "`r?`n")) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        if ($line -notmatch '^(?<hash>[0-9A-Fa-f]{64})[ \t]+\*?(?<name>[^\r\n]+)$') {
            throw "SHA256SUMS.txt contains a malformed non-empty line."
        }
        if ([string]::Equals($Matches.name, $AssetName, [StringComparison]::Ordinal)) {
            $foundHashes.Add($Matches.hash.ToLowerInvariant())
        }
    }
    if ($foundHashes.Count -ne 1) {
        throw "SHA256SUMS.txt must contain exactly one checksum for '$AssetName'."
    }
    return $foundHashes[0]
}

function Get-Sha256 {
    param([Parameter(Mandatory = $true)][string]$Path)

    $stream = [IO.File]::OpenRead($Path)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $sha.Dispose()
        $stream.Dispose()
    }
}

function Expand-PortCVEExecutable {
    param(
        [Parameter(Mandatory = $true)][string]$ZipPath,
        [Parameter(Mandatory = $true)][string]$DestinationDirectory
    )

    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [IO.Compression.ZipFile]::OpenRead($ZipPath)
    try {
        if ($archive.Entries.Count -gt $script:MaximumArchiveEntries) { throw 'Release ZIP has too many entries.' }
        $expanded = 0L
        $executableEntries = New-Object 'Collections.Generic.List[object]'
        foreach ($entry in $archive.Entries) {
            $name = $entry.FullName.Replace('\', '/')
            if ([string]::IsNullOrWhiteSpace($name) -or $name.Contains([char]0) -or $name.Contains(':') -or $name.StartsWith('/') -or $name -match '(^|/)\.\.(/|$)') {
                throw "Release ZIP contains unsafe entry '$name'."
            }
            $expanded += [long]$entry.Length
            if ($expanded -gt $script:MaximumExpandedBytes) { throw 'Release ZIP expands beyond the installer limit.' }
            if ([string]::Equals($name, 'portcve.exe', [StringComparison]::Ordinal)) { $executableEntries.Add($entry) }
        }
        if ($executableEntries.Count -ne 1) { throw "Release ZIP must contain exactly one root 'portcve.exe'." }
        $entry = $executableEntries[0]
        if ($entry.Length -le 0 -or $entry.Length -gt $script:ExecutableLimitBytes) { throw 'portcve.exe size is invalid.' }

        [IO.Directory]::CreateDirectory($DestinationDirectory) | Out-Null
        $destination = Join-Path $DestinationDirectory 'portcve.exe'
        $inputStream = $entry.Open()
        $outputStream = [IO.File]::Open($destination, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try {
            $buffer = New-Object byte[] 65536
            $total = 0L
            while (($read = $inputStream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                $total += $read
                if ($total -gt $script:ExecutableLimitBytes) { throw 'Expanded executable exceeded the installer limit.' }
                $outputStream.Write($buffer, 0, $read)
            }
            if ($total -ne [long]$entry.Length) { throw 'Expanded executable length did not match the ZIP entry.' }
        }
        finally {
            $outputStream.Dispose()
            $inputStream.Dispose()
        }
        return $destination
    }
    finally {
        $archive.Dispose()
    }
}

function Test-Rfc3161Timestamp {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ExpectedSignerSubject
    )

    Add-Type -AssemblyName System.Security
    $stream = [IO.File]::OpenRead($Path)
    $reader = New-Object IO.BinaryReader($stream)
    try {
        if ($stream.Length -gt $script:ExecutableLimitBytes -or $stream.Length -lt 512) { return $false }
        $stream.Position = 0x3c
        $peOffset = $reader.ReadInt32()
        if ($peOffset -lt 0x40 -or $peOffset -gt ($stream.Length - 256)) { return $false }
        $stream.Position = $peOffset
        if ($reader.ReadUInt32() -ne 0x00004550) { return $false }
        $optionalOffset = $peOffset + 24
        $stream.Position = $optionalOffset
        $magic = $reader.ReadUInt16()
        if ($magic -eq 0x10b) { $directoryOffset = $optionalOffset + 96 }
        elseif ($magic -eq 0x20b) { $directoryOffset = $optionalOffset + 112 }
        else { return $false }
        $stream.Position = $directoryOffset + (8 * 4)
        $certificateOffset = [long]$reader.ReadUInt32()
        $certificateSize = [long]$reader.ReadUInt32()
        if ($certificateOffset -le 0 -or $certificateSize -lt 8 -or ($certificateOffset + $certificateSize) -gt $stream.Length) { return $false }

        $position = $certificateOffset
        while ($position -lt ($certificateOffset + $certificateSize)) {
            $stream.Position = $position
            $length = [long]$reader.ReadUInt32()
            $null = $reader.ReadUInt16()
            $type = $reader.ReadUInt16()
            if ($length -lt 8 -or ($position + $length) -gt ($certificateOffset + $certificateSize)) { return $false }
            if ($type -eq 2) {
                $content = $reader.ReadBytes([int]($length - 8))
                $cms = New-Object System.Security.Cryptography.Pkcs.SignedCms
                $cms.Decode($content)
                foreach ($signer in $cms.SignerInfos) {
                    if ($null -ne $signer.Certificate `
                        -and [string]::Equals($signer.Certificate.Subject, $ExpectedSignerSubject, [StringComparison]::Ordinal)) {
                        foreach ($attribute in $signer.UnsignedAttributes) {
                            if ($attribute.Oid.Value -eq '1.3.6.1.4.1.311.3.3.1') { return $true }
                        }
                    }
                }
            }
            $position += (($length + 7) -band (-bnot 7))
        }
        return $false
    }
    catch {
        return $false
    }
    finally {
        $reader.Dispose()
        $stream.Dispose()
    }
}

function Test-CertificateEku {
    param(
        [Parameter(Mandatory = $true)][Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [Parameter(Mandatory = $true)][string]$RequiredOid
    )

    foreach ($extension in $Certificate.Extensions) {
        if ($extension.Oid.Value -eq '2.5.29.37') {
            $eku = New-Object Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension($extension, $extension.Critical)
            foreach ($usage in $eku.EnhancedKeyUsages) {
                if ($usage.Value -eq $RequiredOid) { return $true }
            }
        }
    }
    return $false
}

function Assert-TrustedReleaseExecutable {
    param([Parameter(Mandatory = $true)][string]$Path)

    if ([string]::IsNullOrWhiteSpace($script:ExpectedSignerSubject) -or $script:ExpectedSignerSubject.Contains('__PORTCVE_')) {
        throw 'This installer template was not finalized by the PortCVE release workflow. Refusing installation.'
    }
    $signature = Get-AuthenticodeSignature -FilePath $Path
    if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid -or $null -eq $signature.SignerCertificate) {
        throw "portcve.exe does not have a valid trusted Authenticode signature: $($signature.StatusMessage)"
    }
    if (-not [string]::Equals($signature.SignerCertificate.Subject, $script:ExpectedSignerSubject, [StringComparison]::Ordinal)) {
        throw "Signer subject mismatch. Expected '$script:ExpectedSignerSubject'; received '$($signature.SignerCertificate.Subject)'."
    }
    if (-not (Test-CertificateEku -Certificate $signature.SignerCertificate -RequiredOid '1.3.6.1.5.5.7.3.3')) {
        throw 'Signer certificate does not contain the Code Signing EKU.'
    }
    if ($null -eq $signature.TimeStamperCertificate) { throw 'Authenticode signature has no timestamp certificate.' }
    if (-not (Test-CertificateEku -Certificate $signature.TimeStamperCertificate -RequiredOid '1.3.6.1.5.5.7.3.8')) {
        throw 'Timestamp certificate does not contain the Time Stamping EKU.'
    }
    if (-not (Test-Rfc3161Timestamp -Path $Path -ExpectedSignerSubject $script:ExpectedSignerSubject)) { throw 'The expected Authenticode signer does not contain an RFC 3161 timestamp.' }
    return $signature
}

function Get-CanonicalPath {
    param([Parameter(Mandatory = $true)][string]$Path)
    return [IO.Path]::GetFullPath($Path).TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
}

function Assert-SafeInstallTarget {
    param([Parameter(Mandatory = $true)][string]$Path)

    $full = Get-CanonicalPath $Path
    $root = [IO.Path]::GetPathRoot($full).TrimEnd('\', '/')
    if ([string]::IsNullOrWhiteSpace($full) -or $full.TrimEnd('\', '/') -eq $root -or $full.Length -gt 220 `
        -or $full.Contains(';') -or $full.Contains('"')) {
        throw "Install directory '$full' is unsafe or too long."
    }
    if (Test-Path -LiteralPath $full -PathType Leaf) { throw "Install target '$full' is a file." }
    if (Test-Path -LiteralPath $full -PathType Container) {
        $item = Get-Item -LiteralPath $full -Force
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Install target must not be a reparse point.' }
        $allowed = @('portcve.exe', 'install-receipt.json')
        foreach ($child in Get-ChildItem -LiteralPath $full -Force) {
            if (($child.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or $child.PSIsContainer -or $allowed -cnotcontains $child.Name) {
                throw "Install target contains unmanaged entry '$($child.Name)'; refusing to replace or delete it."
            }
        }
    }
    return $full
}

function Get-UpdatedUserPath {
    param(
        [AllowNull()][string]$CurrentPath,
        [Parameter(Mandatory = $true)][string]$InstallPath
    )

    $canonicalInstall = Get-CanonicalPath $InstallPath
    foreach ($entry in @($CurrentPath -split ';')) {
        $candidate = $entry.Trim().Trim('"')
        if ([string]::IsNullOrWhiteSpace($candidate)) { continue }
        try { $candidate = Get-CanonicalPath ([Environment]::ExpandEnvironmentVariables($candidate)) } catch { continue }
        if ([string]::Equals($candidate, $canonicalInstall, [StringComparison]::OrdinalIgnoreCase)) { return $CurrentPath }
    }
    $updated = if ([string]::IsNullOrWhiteSpace($CurrentPath)) { $canonicalInstall } else { "$($CurrentPath.TrimEnd(';'));$canonicalInstall" }
    if ($updated.Length -gt 32760) { throw 'User PATH would exceed the Windows environment-variable limit.' }
    return $updated
}

function Assert-ManagedDirectory {
    param(
        [Parameter(Mandatory = $true)][string]$Candidate,
        [Parameter(Mandatory = $true)][string]$ExpectedParent,
        [Parameter(Mandatory = $true)][string]$ExpectedLeaf
    )

    $full = Get-CanonicalPath $Candidate
    $parent = Get-CanonicalPath (Split-Path -Parent $full)
    if (-not [string]::Equals($parent, (Get-CanonicalPath $ExpectedParent), [StringComparison]::OrdinalIgnoreCase) `
        -or -not [string]::Equals((Split-Path -Leaf $full), $ExpectedLeaf, [StringComparison]::Ordinal)) {
        throw "Refusing cleanup of unvalidated directory '$full'."
    }
    return $full
}

function Remove-ManagedDirectory {
    param(
        [Parameter(Mandatory = $true)][string]$Candidate,
        [Parameter(Mandatory = $true)][string]$ExpectedParent,
        [Parameter(Mandatory = $true)][string]$ExpectedLeaf
    )

    $full = Assert-ManagedDirectory -Candidate $Candidate -ExpectedParent $ExpectedParent -ExpectedLeaf $ExpectedLeaf
    if (Test-Path -LiteralPath $full) { Remove-Item -LiteralPath $full -Recurse -Force }
}

function Invoke-AtomicInstall {
    param(
        [Parameter(Mandatory = $true)][string]$InstallPath,
        [Parameter(Mandatory = $true)][string]$StagingPath,
        [Parameter(Mandatory = $true)][string]$Token,
        [Parameter(Mandatory = $true)][string]$OriginalUserPath,
        [Parameter(Mandatory = $true)][string]$UpdatedUserPath
    )

    $parent = Split-Path -Parent $InstallPath
    $leaf = Split-Path -Leaf $InstallPath
    $backupLeaf = "$leaf.backup-$Token"
    $failedLeaf = "$leaf.failed-$Token"
    $backup = Join-Path $parent $backupLeaf
    $failed = Join-Path $parent $failedLeaf
    $hadExisting = Test-Path -LiteralPath $InstallPath -PathType Container
    $newInstalled = $false
    $pathChanged = $false
    try {
        if ($hadExisting) { [IO.Directory]::Move($InstallPath, $backup) }
        [IO.Directory]::Move($StagingPath, $InstallPath)
        $newInstalled = $true
        if (-not [string]::Equals($OriginalUserPath, $UpdatedUserPath, [StringComparison]::Ordinal)) {
            [Environment]::SetEnvironmentVariable('Path', $UpdatedUserPath, [EnvironmentVariableTarget]::User)
            $pathChanged = $true
        }
        if ($hadExisting) { Remove-ManagedDirectory -Candidate $backup -ExpectedParent $parent -ExpectedLeaf $backupLeaf }
    }
    catch {
        $failure = $_
        $rollbackErrors = New-Object 'Collections.Generic.List[string]'
        if ($pathChanged) {
            try { [Environment]::SetEnvironmentVariable('Path', $OriginalUserPath, [EnvironmentVariableTarget]::User) }
            catch { $rollbackErrors.Add("PATH rollback failed: $($_.Exception.Message)") }
        }
        if ($newInstalled -and (Test-Path -LiteralPath $InstallPath -PathType Container)) {
            try { [IO.Directory]::Move($InstallPath, $failed) }
            catch { $rollbackErrors.Add("new installation isolation failed: $($_.Exception.Message)") }
        }
        if ($hadExisting -and (Test-Path -LiteralPath $backup -PathType Container) -and -not (Test-Path -LiteralPath $InstallPath)) {
            try { [IO.Directory]::Move($backup, $InstallPath) }
            catch { $rollbackErrors.Add("previous installation restore failed: $($_.Exception.Message)") }
        }
        if (Test-Path -LiteralPath $failed) {
            try { Remove-ManagedDirectory -Candidate $failed -ExpectedParent $parent -ExpectedLeaf $failedLeaf }
            catch { $rollbackErrors.Add("failed-install cleanup failed: $($_.Exception.Message)") }
        }
        if ($rollbackErrors.Count -gt 0) {
            throw "Installation failed: $($failure.Exception.Message). Rollback was incomplete: $($rollbackErrors -join '; ')"
        }
        throw $failure
    }
}

function Invoke-PortCVEInstall {
    param(
        [string]$Version,
        [string]$InstallDirectory
    )

    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT -or -not [Environment]::Is64BitOperatingSystem) {
        throw 'PortCVE installer supports 64-bit Windows only.'
    }
    if ([string]::IsNullOrWhiteSpace($script:ExpectedSignerSubject) -or $script:ExpectedSignerSubject.Contains('__PORTCVE_')) {
        throw 'This is an unfinalized installer template, not a production release asset.'
    }

    if ([string]::IsNullOrWhiteSpace($InstallDirectory)) {
        $localAppData = [Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)
        if ([string]::IsNullOrWhiteSpace($localAppData)) { throw 'LocalAppData could not be resolved.' }
        $InstallDirectory = Join-Path $localAppData 'Programs\PortCVE'
    }
    $installPath = Assert-SafeInstallTarget $InstallDirectory
    $installParent = Split-Path -Parent $installPath
    [IO.Directory]::CreateDirectory($installParent) | Out-Null

    $token = [Guid]::NewGuid().ToString('N')
    $tempParent = Get-CanonicalPath ([IO.Path]::GetTempPath())
    $workingLeaf = "portcve-install-$token"
    $working = Join-Path $tempParent $workingLeaf
    $installLeaf = Split-Path -Leaf $installPath
    $stagingLeaf = "$installLeaf.staging-$token"
    $staging = Join-Path $installParent $stagingLeaf
    [IO.Directory]::CreateDirectory($working) | Out-Null

    $previousProtocol = [Net.ServicePointManager]::SecurityProtocol
    try {
        [Net.ServicePointManager]::SecurityProtocol = $previousProtocol -bor [Net.SecurityProtocolType]::Tls12
        $release = Resolve-Release -RequestedVersion $Version -WorkingDirectory $working
        $zipPath = Join-Path $working $release.ZipName
        $checksumPath = Join-Path $working 'SHA256SUMS.txt'
        Save-BoundedHttpsFile -Uri $release.ChecksumUri -Destination $checksumPath -MaximumBytes $script:ChecksumLimitBytes
        Save-BoundedHttpsFile -Uri $release.ZipUri -Destination $zipPath -MaximumBytes $script:ZipLimitBytes

        $expectedHash = Get-ExpectedChecksum -ChecksumPath $checksumPath -AssetName $release.ZipName
        $actualHash = Get-Sha256 $zipPath
        if (-not [string]::Equals($expectedHash, $actualHash, [StringComparison]::Ordinal)) {
            throw "Checksum mismatch for '$($release.ZipName)'."
        }

        $extractedDirectory = Join-Path $working 'extracted'
        $executable = Expand-PortCVEExecutable -ZipPath $zipPath -DestinationDirectory $extractedDirectory
        $signature = Assert-TrustedReleaseExecutable $executable

        [IO.Directory]::CreateDirectory($staging) | Out-Null
        [IO.File]::Copy($executable, (Join-Path $staging 'portcve.exe'), $false)
        $null = Assert-TrustedReleaseExecutable (Join-Path $staging 'portcve.exe')
        $receipt = [ordered]@{
            product = 'PortCVE'
            version = $release.Tag
            repository = $script:Repository
            zip_asset = $release.ZipName
            zip_sha256 = $actualHash
            signer_subject = $signature.SignerCertificate.Subject
            timestamp_subject = $signature.TimeStamperCertificate.Subject
            installed_at_utc = [DateTime]::UtcNow.ToString('o')
        } | ConvertTo-Json
        [IO.File]::WriteAllText((Join-Path $staging 'install-receipt.json'), $receipt + "`r`n", [Text.UTF8Encoding]::new($false))

        $originalUserPath = [Environment]::GetEnvironmentVariable('Path', [EnvironmentVariableTarget]::User)
        if ($null -eq $originalUserPath) { $originalUserPath = '' }
        $updatedUserPath = Get-UpdatedUserPath -CurrentPath $originalUserPath -InstallPath $installPath
        Invoke-AtomicInstall -InstallPath $installPath -StagingPath $staging -Token $token -OriginalUserPath $originalUserPath -UpdatedUserPath $updatedUserPath

        Write-Host "PortCVE $($release.Tag) installed to '$installPath'."
        Write-Host 'Open a new terminal, then run: portcve --version'
    }
    finally {
        [Net.ServicePointManager]::SecurityProtocol = $previousProtocol
        if (Test-Path -LiteralPath $staging) {
            Remove-ManagedDirectory -Candidate $staging -ExpectedParent $installParent -ExpectedLeaf $stagingLeaf
        }
        if (Test-Path -LiteralPath $working) {
            Remove-ManagedDirectory -Candidate $working -ExpectedParent $tempParent -ExpectedLeaf $workingLeaf
        }
    }
}

# PORTCVE_INSTALLER_ENTRYPOINT
Invoke-PortCVEInstall @PSBoundParameters

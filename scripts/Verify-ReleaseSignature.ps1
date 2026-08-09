[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$Path,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$ExpectedSignerSubject,

    [Parameter()]
    [string]$SignToolPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Resolve-SignTool {
    param([string]$ExplicitPath)

    if (-not [string]::IsNullOrWhiteSpace($ExplicitPath)) {
        $resolvedExplicit = (Resolve-Path -LiteralPath $ExplicitPath -ErrorAction Stop).Path
        if (-not (Test-Path -LiteralPath $resolvedExplicit -PathType Leaf)) {
            throw "SignTool path is not a file: $resolvedExplicit"
        }
        return $resolvedExplicit
    }

    $command = Get-Command signtool.exe -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -ne $command) {
        return $command.Source
    }

    $candidateRoots = @()
    if (-not [string]::IsNullOrWhiteSpace(${env:ProgramFiles(x86)})) {
        $candidateRoots += Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin'
    }
    if (-not [string]::IsNullOrWhiteSpace($env:ProgramFiles)) {
        $candidateRoots += Join-Path $env:ProgramFiles 'Windows Kits\10\bin'
    }

    $candidates = foreach ($root in $candidateRoots | Select-Object -Unique) {
        if (-not (Test-Path -LiteralPath $root -PathType Container)) {
            continue
        }
        Get-ChildItem -Path (Join-Path $root '*\x64\signtool.exe') -File -ErrorAction SilentlyContinue |
            ForEach-Object {
                $version = [version]'0.0'
                [void][version]::TryParse($_.Directory.Parent.Name, [ref]$version)
                [pscustomobject]@{ Path = $_.FullName; Version = $version }
            }
    }

    $selected = $candidates | Sort-Object Version -Descending | Select-Object -First 1
    if ($null -eq $selected) {
        throw 'signtool.exe was not found. Install the Windows SDK before verifying a release signature.'
    }
    return $selected.Path
}

function Test-Rfc3161Timestamp {
    param([Parameter(Mandatory)][string]$ExecutablePath)

    # The Authenticode certificate table stores a PKCS#7 SignedCms blob. An
    # RFC 3161 timestamp is represented by Microsoft's timestamp-token
    # unauthenticated attribute OID, not the legacy PKCS#9 countersignature OID.
    $bytes = [IO.File]::ReadAllBytes($ExecutablePath)
    if ($bytes.Length -lt 256 -or $bytes[0] -ne 0x4d -or $bytes[1] -ne 0x5a) {
        throw 'Signed artifact is not a valid PE file.'
    }

    $peOffset = [BitConverter]::ToInt32($bytes, 0x3c)
    if ($peOffset -lt 0 -or $peOffset + 256 -gt $bytes.Length -or
        $bytes[$peOffset] -ne 0x50 -or $bytes[$peOffset + 1] -ne 0x45 -or
        $bytes[$peOffset + 2] -ne 0 -or $bytes[$peOffset + 3] -ne 0) {
        throw 'Signed artifact has an invalid PE header.'
    }

    $optionalHeaderOffset = $peOffset + 24
    $optionalMagic = [BitConverter]::ToUInt16($bytes, $optionalHeaderOffset)
    $dataDirectoryOffset = switch ($optionalMagic) {
        0x10b { 96 }
        0x20b { 112 }
        default { throw "Unsupported PE optional-header magic: 0x$($optionalMagic.ToString('x'))." }
    }

    $securityDirectoryOffset = $optionalHeaderOffset + $dataDirectoryOffset + (4 * 8)
    if ($securityDirectoryOffset + 8 -gt $bytes.Length) {
        throw 'PE security directory lies outside the artifact.'
    }

    # The security directory uses a file offset rather than a relative virtual address.
    $certificateOffset = [BitConverter]::ToUInt32($bytes, $securityDirectoryOffset)
    $certificateTableSize = [BitConverter]::ToUInt32($bytes, $securityDirectoryOffset + 4)
    if ($certificateOffset -eq 0 -or $certificateTableSize -lt 8 -or
        [uint64]$certificateOffset + [uint64]$certificateTableSize -gt [uint64]$bytes.Length) {
        throw 'PE security directory is missing or invalid.'
    }

    $winCertificateLength = [BitConverter]::ToUInt32($bytes, [int]$certificateOffset)
    $winCertificateRevision = [BitConverter]::ToUInt16($bytes, [int]$certificateOffset + 4)
    $winCertificateType = [BitConverter]::ToUInt16($bytes, [int]$certificateOffset + 6)
    if ($winCertificateRevision -ne 0x0200 -or $winCertificateType -ne 0x0002 -or
        $winCertificateLength -le 8 -or $winCertificateLength -gt $certificateTableSize) {
        throw 'PE certificate table does not contain a valid PKCS#7 WIN_CERTIFICATE entry.'
    }

    $cmsBytes = New-Object byte[] ([int]$winCertificateLength - 8)
    [Array]::Copy($bytes, [int]$certificateOffset + 8, $cmsBytes, 0, $cmsBytes.Length)

    if ($null -eq ('System.Security.Cryptography.Pkcs.SignedCms' -as [type])) {
        Add-Type -AssemblyName System.Security
    }
    $cms = New-Object System.Security.Cryptography.Pkcs.SignedCms
    $cms.Decode($cmsBytes)
    if ($cms.SignerInfos.Count -ne 1) {
        throw "Expected one Authenticode signer, found $($cms.SignerInfos.Count)."
    }

    $rfc3161Oid = '1.3.6.1.4.1.311.3.3.1'
    $hasRfc3161Timestamp = @($cms.SignerInfos[0].UnsignedAttributes | Where-Object {
        $_.Oid.Value -eq $rfc3161Oid
    }).Count -eq 1
    if (-not $hasRfc3161Timestamp) {
        throw 'Authenticode signature does not contain exactly one RFC 3161 timestamp token.'
    }
}

$resolvedArtifact = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
if (-not (Test-Path -LiteralPath $resolvedArtifact -PathType Leaf)) {
    throw "Release artifact is not a file: $resolvedArtifact"
}
if (-not [StringComparer]::Ordinal.Equals([IO.Path]::GetFileName($resolvedArtifact), 'portcve.exe')) {
    throw "Release signature verification is restricted to the exact file name 'portcve.exe'."
}
if ([string]::IsNullOrWhiteSpace($ExpectedSignerSubject) -or
    $ExpectedSignerSubject -ne $ExpectedSignerSubject.Trim() -or
    $ExpectedSignerSubject.Contains("`r") -or $ExpectedSignerSubject.Contains("`n")) {
    throw 'Expected signer subject is missing or malformed.'
}

$resolvedSignTool = Resolve-SignTool -ExplicitPath $SignToolPath
$signToolLines = @(& $resolvedSignTool verify /pa /all /v $resolvedArtifact 2>&1)
$signToolExitCode = $LASTEXITCODE
$signToolText = $signToolLines -join [Environment]::NewLine
$signToolText | Write-Host

if ($signToolExitCode -ne 0) {
    throw "signtool.exe rejected the Authenticode signature (exit $signToolExitCode)."
}
foreach ($requiredPattern in @(
    '(?im)^Hash of file \(sha256\):\s*[0-9A-F]{64}\s*$',
    '(?im)^The signature is timestamped:\s*.+$',
    '(?im)^Timestamp Verified by:\s*$',
    '(?im)^Successfully verified:\s*.+$',
    '(?im)^Number of signatures successfully Verified:\s*1\s*$',
    '(?im)^Number of warnings:\s*0\s*$',
    '(?im)^Number of errors:\s*0\s*$'
)) {
    if ($signToolText -notmatch $requiredPattern) {
        throw "signtool.exe output did not satisfy required verification pattern: $requiredPattern"
    }
}

$authenticode = Get-AuthenticodeSignature -LiteralPath $resolvedArtifact
if ($authenticode.Status -ne [Management.Automation.SignatureStatus]::Valid) {
    throw "Get-AuthenticodeSignature rejected the signature: $($authenticode.Status) - $($authenticode.StatusMessage)"
}
if ($null -eq $authenticode.SignerCertificate) {
    throw 'Authenticode signature has no signer certificate.'
}
if (-not [StringComparer]::Ordinal.Equals($authenticode.SignerCertificate.Subject, $ExpectedSignerSubject)) {
    throw "Signer subject does not exactly match EXPECTED_SIGNER_SUBJECT. Actual: '$($authenticode.SignerCertificate.Subject)'."
}

$ekuExtension = $authenticode.SignerCertificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.37' } | Select-Object -First 1
$hasCodeSigningEku = $null -ne $ekuExtension -and @($ekuExtension.EnhancedKeyUsages | Where-Object {
    $_.Value -eq '1.3.6.1.5.5.7.3.3'
}).Count -gt 0
if (-not $hasCodeSigningEku) {
    throw 'Signer certificate does not contain the Code Signing enhanced key usage OID.'
}
if ($null -eq $authenticode.TimeStamperCertificate) {
    throw 'Authenticode signature has no validated timestamp certificate.'
}

Test-Rfc3161Timestamp -ExecutablePath $resolvedArtifact

[pscustomobject]@{
    Path = $resolvedArtifact
    Sha256 = (Get-FileHash -LiteralPath $resolvedArtifact -Algorithm SHA256).Hash.ToLowerInvariant()
    SignerSubject = $authenticode.SignerCertificate.Subject
    SignerThumbprint = $authenticode.SignerCertificate.Thumbprint
    TimestampFormat = 'RFC3161'
    TimestampSignerSubject = $authenticode.TimeStamperCertificate.Subject
    Verification = 'Valid'
}

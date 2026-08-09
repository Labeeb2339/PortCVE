#requires -Version 7.2

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

. (Join-Path $PSScriptRoot 'Rfc3161TimestampValidation.ps1')

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

$resolvedArtifact = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
if (-not (Test-Path -LiteralPath $resolvedArtifact -PathType Leaf)) {
    throw "Release artifact is not a file: $resolvedArtifact"
}
$artifactName = [IO.Path]::GetFileName($resolvedArtifact)
if (-not [StringComparer]::Ordinal.Equals($artifactName, 'portcve.exe') -and
    -not [StringComparer]::Ordinal.Equals($artifactName, 'install.ps1')) {
    throw "Release signature verification is restricted to 'portcve.exe' and 'install.ps1'."
}
if ([string]::IsNullOrWhiteSpace($ExpectedSignerSubject) -or
    $ExpectedSignerSubject -ne $ExpectedSignerSubject.Trim() -or
    $ExpectedSignerSubject.Contains("`r") -or $ExpectedSignerSubject.Contains("`n")) {
    throw 'Expected signer subject is missing or malformed.'
}

if ([StringComparer]::Ordinal.Equals($artifactName, 'portcve.exe')) {
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
}

$authenticode = Get-AuthenticodeSignature -LiteralPath $resolvedArtifact
if ($authenticode.Status -ne [Management.Automation.SignatureStatus]::Valid) {
    throw "Get-AuthenticodeSignature rejected the signature: $($authenticode.Status) - $($authenticode.StatusMessage)"
}
if (-not [StringComparer]::Ordinal.Equals([string]$authenticode.SignatureType, 'Authenticode')) {
    throw "Expected an embedded Authenticode signature; Windows selected '$($authenticode.SignatureType)'."
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
$timestampEkuExtension = $authenticode.TimeStamperCertificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.37' } | Select-Object -First 1
$hasTimestampEku = $null -ne $timestampEkuExtension -and @($timestampEkuExtension.EnhancedKeyUsages | Where-Object {
    $_.Value -eq '1.3.6.1.5.5.7.3.8'
}).Count -gt 0
if (-not $hasTimestampEku) {
    throw 'Timestamp certificate does not contain the Time Stamping enhanced key usage OID.'
}

$rfc3161 = Assert-Rfc3161Timestamp `
    -ArtifactPath $resolvedArtifact `
    -ExpectedSubject $ExpectedSignerSubject `
    -ExpectedSignerCertificate $authenticode.SignerCertificate `
    -ExpectedTimestampCertificate $authenticode.TimeStamperCertificate

[pscustomobject]@{
    Path = $resolvedArtifact
    Sha256 = (Get-FileHash -LiteralPath $resolvedArtifact -Algorithm SHA256).Hash.ToLowerInvariant()
    SignerSubject = $authenticode.SignerCertificate.Subject
    SignerThumbprint = $authenticode.SignerCertificate.Thumbprint
    TimestampFormat = 'RFC3161'
    TimestampSignerSubject = $authenticode.TimeStamperCertificate.Subject
    TimestampUtc = $rfc3161.Timestamp.ToUniversalTime().ToString('o')
    TimestampBinding = 'Rfc3161TimestampToken.VerifySignatureForSignerInfo'
    Verification = 'Valid'
}

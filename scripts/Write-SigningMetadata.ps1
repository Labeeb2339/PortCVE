[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Path,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$OutputPath,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$ExpectedSignerSubject,
    [Parameter(Mandatory)][ValidatePattern('^[^/]+/[^/]+$')][string]$Repository,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{40}$')][string]$CommitSha,
    [Parameter(Mandatory)][ValidatePattern('^v.+$')][string]$Tag,
    [Parameter(Mandatory)][ValidatePattern('^\d+$')][string]$WorkflowRunId,
    [Parameter(Mandatory)][ValidatePattern('^\d+$')][string]$WorkflowRunAttempt,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{40}$')][string]$SigningActionCommit,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$CodeSignToolVersion,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$CodeSignToolArchiveSha256,
    [Parameter()][string]$SignToolPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-CertificateSha256 {
    param([Parameter(Mandatory)][Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)

    $sha256 = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha256.ComputeHash($Certificate.RawData))).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $sha256.Dispose()
    }
}

$resolvedArtifact = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
if (-not [StringComparer]::Ordinal.Equals([IO.Path]::GetFileName($resolvedArtifact), 'portcve.exe')) {
    throw "Signing metadata can be generated only for the exact file name 'portcve.exe'."
}

$verifyScript = Join-Path $PSScriptRoot 'Verify-ReleaseSignature.ps1'
$verificationParameters = @{
    Path = $resolvedArtifact
    ExpectedSignerSubject = $ExpectedSignerSubject
}
if (-not [string]::IsNullOrWhiteSpace($SignToolPath)) {
    $verificationParameters.SignToolPath = $SignToolPath
}
$verification = & $verifyScript @verificationParameters

$signature = Get-AuthenticodeSignature -LiteralPath $resolvedArtifact
$signer = $signature.SignerCertificate
$timestampSigner = $signature.TimeStamperCertificate
if ($null -eq $signer -or $null -eq $timestampSigner) {
    throw 'Verified signature certificates disappeared before metadata generation.'
}

$artifactInfo = Get-Item -LiteralPath $resolvedArtifact
$metadata = [ordered]@{
    schema_version = 1
    generated_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
    artifact = [ordered]@{
        name = $artifactInfo.Name
        size_bytes = $artifactInfo.Length
        sha256 = [string]$verification.Sha256
    }
    signature = [ordered]@{
        status = [string]$signature.Status
        type = [string]$signature.SignatureType
        file_digest_algorithm = 'SHA256'
        signer = [ordered]@{
            subject = $signer.Subject
            issuer = $signer.Issuer
            serial_number = $signer.SerialNumber
            thumbprint_sha1 = $signer.Thumbprint.ToLowerInvariant()
            certificate_sha256 = Get-CertificateSha256 -Certificate $signer
            not_before_utc = $signer.NotBefore.ToUniversalTime().ToString('o')
            not_after_utc = $signer.NotAfter.ToUniversalTime().ToString('o')
            code_signing_eku_oid = '1.3.6.1.5.5.7.3.3'
        }
        timestamp = [ordered]@{
            format = 'RFC3161'
            validated = $true
            subject = $timestampSigner.Subject
            issuer = $timestampSigner.Issuer
            serial_number = $timestampSigner.SerialNumber
            thumbprint_sha1 = $timestampSigner.Thumbprint.ToLowerInvariant()
            certificate_sha256 = Get-CertificateSha256 -Certificate $timestampSigner
            not_before_utc = $timestampSigner.NotBefore.ToUniversalTime().ToString('o')
            not_after_utc = $timestampSigner.NotAfter.ToUniversalTime().ToString('o')
        }
    }
    source = [ordered]@{
        repository = $Repository
        commit_sha = $CommitSha.ToLowerInvariant()
        tag = $Tag
    }
    workflow = [ordered]@{
        file = '.github/workflows/release.yml'
        run_id = $WorkflowRunId
        run_attempt = $WorkflowRunAttempt
    }
    signing_service = [ordered]@{
        provider = 'SSL.com eSigner'
        action = 'SSLcom/esigner-codesign'
        action_commit = $SigningActionCommit.ToLowerInvariant()
        codesign_tool_version = $CodeSignToolVersion
        codesign_tool_archive_sha256 = $CodeSignToolArchiveSha256.ToLowerInvariant()
    }
}

$outputParent = Split-Path -Parent $OutputPath
if ([string]::IsNullOrWhiteSpace($outputParent)) {
    $outputParent = $PWD.Path
}
if (-not (Test-Path -LiteralPath $outputParent -PathType Container)) {
    New-Item -ItemType Directory -Path $outputParent | Out-Null
}
$resolvedOutputParent = (Resolve-Path -LiteralPath $outputParent).Path
$resolvedOutput = Join-Path $resolvedOutputParent (Split-Path -Leaf $OutputPath)
[IO.File]::WriteAllText(
    $resolvedOutput,
    ($metadata | ConvertTo-Json -Depth 8),
    [Text.UTF8Encoding]::new($false)
)

Get-Item -LiteralPath $resolvedOutput

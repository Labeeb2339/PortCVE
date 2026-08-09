#requires -Version 7.2

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
. (Join-Path $repositoryRoot 'scripts\Rfc3161TimestampValidation.ps1')

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

$timestampType = 'System.Security.Cryptography.Pkcs.Rfc3161TimestampToken' -as [type]
Assert-True ($null -ne $timestampType -and $null -ne $timestampType.GetMethod('VerifySignatureForSignerInfo')) `
    'PowerShell 7 does not expose Rfc3161TimestampToken.VerifySignatureForSignerInfo.'

$gitCommand = Get-Command git.exe -CommandType Application -ErrorAction Stop | Select-Object -First 1
$primaryPath = $gitCommand.Source
$primaryAuthenticode = Get-AuthenticodeSignature -LiteralPath $primaryPath
Assert-True ($primaryAuthenticode.Status -eq [Management.Automation.SignatureStatus]::Valid -and
    $null -ne $primaryAuthenticode.SignerCertificate -and
    $null -ne $primaryAuthenticode.TimeStamperCertificate) `
    'Git for Windows is not a trusted timestamped Authenticode fixture on this runner.'

$primaryContent = Get-PeSignatureContent -ExecutablePath $primaryPath
$primaryCms = [Security.Cryptography.Pkcs.SignedCms]::new()
$primaryCms.Decode($primaryContent)
$primaryCms.CheckSignature($true)
$primarySigner = $primaryCms.SignerInfos[0]
$validResult = Assert-Rfc3161SignerInfo `
    -SignerInfo $primarySigner `
    -ExtraCandidates $primaryCms.Certificates `
    -ExpectedTimestampCertificate $primaryAuthenticode.TimeStamperCertificate
Assert-True ($null -ne $validResult.Timestamp -and
    [StringComparer]::Ordinal.Equals(
        $validResult.TimestampSignerCertificate.Thumbprint,
        $primaryAuthenticode.TimeStamperCertificate.Thumbprint)) `
    'Valid RFC 3161 fixture was not cryptographically bound to its primary SignerInfo and trusted TSA certificate.'

$timestampAttribute = @($primarySigner.UnsignedAttributes | Where-Object {
    [StringComparer]::Ordinal.Equals($_.Oid.Value, $script:Rfc3161TimestampTokenOid)
})
if ($timestampAttribute.Count -ne 1 -or $timestampAttribute[0].Values.Count -ne 1) {
    throw 'Valid fixture did not contain the expected single RFC 3161 token.'
}
$tokenBytes = [byte[]]$timestampAttribute[0].Values[0].RawData.Clone()

$decodedToken = $null
$decodedLength = 0
if (-not [Security.Cryptography.Pkcs.Rfc3161TimestampToken]::TryDecode(
        [ReadOnlyMemory[byte]]::new($tokenBytes),
        [ref]$decodedToken,
        [ref]$decodedLength) -or $decodedLength -ne $tokenBytes.Length) {
    throw 'Valid fixture token could not be decoded for the tamper regression.'
}
$timestampSignature = $decodedToken.AsSignedCms().SignerInfos[0].GetSignature()
$signatureOffset = -1
for ($candidateOffset = 0; $candidateOffset -le ($tokenBytes.Length - $timestampSignature.Length); $candidateOffset++) {
    $matches = $true
    for ($signatureIndex = 0; $signatureIndex -lt $timestampSignature.Length; $signatureIndex++) {
        if ($tokenBytes[$candidateOffset + $signatureIndex] -ne $timestampSignature[$signatureIndex]) {
            $matches = $false
            break
        }
    }
    if ($matches) {
        $signatureOffset = $candidateOffset
        break
    }
}
if ($signatureOffset -lt 0) { throw 'Could not locate the TSA signature bytes in the RFC 3161 token.' }
$tamperedToken = [byte[]]$tokenBytes.Clone()
$tamperIndex = $signatureOffset + [Math]::Floor($timestampSignature.Length / 2)
$tamperedToken[$tamperIndex] = $tamperedToken[$tamperIndex] -bxor 1
Assert-Throws {
    Assert-BoundRfc3161TimestampToken `
        -SignerInfo $primarySigner `
        -TokenBytes $tamperedToken `
        -ExtraCandidates $primaryCms.Certificates `
        -ExpectedTimestampCertificate $primaryAuthenticode.TimeStamperCertificate
} 'Tampered RFC 3161 token was accepted.'

$gitRoot = Split-Path -Parent (Split-Path -Parent $primaryPath)
$primarySignature = [Convert]::ToBase64String($primarySigner.GetSignature())
$differentSigner = $null
foreach ($candidate in Get-ChildItem -LiteralPath $gitRoot -Recurse -Filter *.exe -File -ErrorAction SilentlyContinue) {
    try {
        $candidateContent = Get-PeSignatureContent -ExecutablePath $candidate.FullName
        $candidateCms = [Security.Cryptography.Pkcs.SignedCms]::new()
        $candidateCms.Decode($candidateContent)
        $candidateCms.CheckSignature($true)
        if ($candidateCms.SignerInfos.Count -eq 1 -and
            -not [StringComparer]::Ordinal.Equals(
                [Convert]::ToBase64String($candidateCms.SignerInfos[0].GetSignature()),
                $primarySignature)) {
            $differentSigner = $candidateCms.SignerInfos[0]
            break
        }
    }
    catch {
        continue
    }
}
if ($null -eq $differentSigner) {
    throw 'Could not find a second embedded Authenticode SignerInfo for the unbound-token regression.'
}
Assert-Throws {
    Assert-BoundRfc3161TimestampToken `
        -SignerInfo $differentSigner `
        -TokenBytes $tokenBytes `
        -ExtraCandidates $primaryCms.Certificates `
        -ExpectedTimestampCertificate $primaryAuthenticode.TimeStamperCertificate
} 'RFC 3161 token was accepted for a different primary SignerInfo.'

$fakeKey = [Security.Cryptography.RSA]::Create(2048)
$fakeCertificate = $null
try {
    $fakeRequest = [Security.Cryptography.X509Certificates.CertificateRequest]::new(
        'CN=RFC3161 Fake OID Fixture',
        $fakeKey,
        [Security.Cryptography.HashAlgorithmName]::SHA256,
        [Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $fakeCertificate = $fakeRequest.CreateSelfSigned(
        [DateTimeOffset]::UtcNow.AddDays(-1),
        [DateTimeOffset]::UtcNow.AddDays(1))
    $fakeCms = [Security.Cryptography.Pkcs.SignedCms]::new(
        [Security.Cryptography.Pkcs.ContentInfo]::new([byte[]](1, 2, 3)),
        $false)
    $fakeCms.ComputeSignature([Security.Cryptography.Pkcs.CmsSigner]::new($fakeCertificate))
    $fakeCms.SignerInfos[0].AddUnsignedAttribute([Security.Cryptography.AsnEncodedData]::new(
            [Security.Cryptography.Oid]::new($script:Rfc3161TimestampTokenOid),
            [byte[]](0x30, 0x00)))
    $fakeEncoded = $fakeCms.Encode()
    $fakeCms = [Security.Cryptography.Pkcs.SignedCms]::new()
    $fakeCms.Decode($fakeEncoded)
    Assert-Throws {
        Assert-Rfc3161SignerInfo `
            -SignerInfo $fakeCms.SignerInfos[0] `
            -ExtraCandidates $fakeCms.Certificates `
            -ExpectedTimestampCertificate $fakeCertificate
    } 'Fake RFC 3161 OID payload was accepted without decoding and binding a timestamp token.'
}
finally {
    if ($null -ne $fakeCertificate) { $fakeCertificate.Dispose() }
    $fakeKey.Dispose()
}

$multipleCms = [Security.Cryptography.Pkcs.SignedCms]::new()
$multipleCms.Decode($primaryContent)
$multipleSigner = $multipleCms.SignerInfos[0]
$multipleSigner.AddUnsignedAttribute([Security.Cryptography.AsnEncodedData]::new(
        [Security.Cryptography.Oid]::new($script:Rfc3161TimestampTokenOid),
        $tokenBytes))
$multipleEncoded = $multipleCms.Encode()
$multipleCms = [Security.Cryptography.Pkcs.SignedCms]::new()
$multipleCms.Decode($multipleEncoded)
$multipleSigner = $multipleCms.SignerInfos[0]
Assert-Throws {
    Assert-Rfc3161SignerInfo `
        -SignerInfo $multipleSigner `
        -ExtraCandidates $multipleCms.Certificates `
        -ExpectedTimestampCertificate $primaryAuthenticode.TimeStamperCertificate
} 'Multiple RFC 3161 timestamp tokens were accepted.'

$legacyCms = [Security.Cryptography.Pkcs.SignedCms]::new()
$legacyCms.Decode($primaryContent)
$legacySigner = $legacyCms.SignerInfos[0]
$legacySigner.AddUnsignedAttribute([Security.Cryptography.AsnEncodedData]::new(
        [Security.Cryptography.Oid]::new($script:LegacyAuthenticodeTimestampOid),
        [byte[]](0x05, 0x00)))
$legacyEncoded = $legacyCms.Encode()
$legacyCms = [Security.Cryptography.Pkcs.SignedCms]::new()
$legacyCms.Decode($legacyEncoded)
$legacySigner = $legacyCms.SignerInfos[0]
Assert-Throws {
    Assert-Rfc3161SignerInfo `
        -SignerInfo $legacySigner `
        -ExtraCandidates $legacyCms.Certificates `
        -ExpectedTimestampCertificate $primaryAuthenticode.TimeStamperCertificate
} 'Legacy Authenticode countersignature was accepted alongside RFC 3161.'

Assert-Throws {
    Assert-Rfc3161SignerInfo `
        -SignerInfo $primarySigner `
        -ExtraCandidates $primaryCms.Certificates `
        -ExpectedTimestampCertificate $primaryAuthenticode.SignerCertificate
} 'Cryptographic timestamp signer was not required to match the platform-trusted timestamp certificate.'

Write-Host "RFC 3161 binding checks passed: $script:Passed"

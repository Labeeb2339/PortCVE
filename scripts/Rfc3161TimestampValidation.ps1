#requires -Version 7.2

Set-StrictMode -Version Latest

$script:Rfc3161TimestampTokenOid = '1.3.6.1.4.1.311.3.3.1'
$script:LegacyAuthenticodeTimestampOid = '1.2.840.113549.1.9.6'

function Get-PowerShellSignatureContent {
    param([Parameter(Mandatory)][string]$ScriptPath)

    $lines = [IO.File]::ReadAllLines($ScriptPath)
    $beginIndexes = @()
    $endIndexes = @()
    for ($index = 0; $index -lt $lines.Length; $index++) {
        if ([StringComparer]::Ordinal.Equals($lines[$index], '# SIG # Begin signature block')) { $beginIndexes += $index }
        if ([StringComparer]::Ordinal.Equals($lines[$index], '# SIG # End signature block')) { $endIndexes += $index }
    }
    if ($beginIndexes.Count -ne 1 -or $endIndexes.Count -ne 1 -or $endIndexes[0] -le ($beginIndexes[0] + 1)) {
        throw 'PowerShell Authenticode signature block is missing or ambiguous.'
    }

    $segments = New-Object 'Collections.Generic.List[string]'
    for ($index = $beginIndexes[0] + 1; $index -lt $endIndexes[0]; $index++) {
        if ($lines[$index] -notmatch '^# (?<data>[0-9A-Za-z+/=]+)$') {
            throw 'PowerShell Authenticode signature block contains a malformed line.'
        }
        $segments.Add($Matches.data)
    }
    return ,([Convert]::FromBase64String(($segments -join '')))
}

function Get-PeSignatureContent {
    param([Parameter(Mandatory)][string]$ExecutablePath)

    $bytes = [IO.File]::ReadAllBytes($ExecutablePath)
    if ($bytes.Length -lt 256 -or $bytes[0] -ne 0x4d -or $bytes[1] -ne 0x5a) {
        throw 'Signed executable is not a valid PE file.'
    }

    $peOffset = [BitConverter]::ToInt32($bytes, 0x3c)
    if ($peOffset -lt 0 -or $peOffset + 256 -gt $bytes.Length -or
        $bytes[$peOffset] -ne 0x50 -or $bytes[$peOffset + 1] -ne 0x45 -or
        $bytes[$peOffset + 2] -ne 0 -or $bytes[$peOffset + 3] -ne 0) {
        throw 'Signed executable has an invalid PE header.'
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
        throw 'PE security directory lies outside the executable.'
    }

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

    $content = New-Object byte[] ([int]$winCertificateLength - 8)
    [Array]::Copy($bytes, [int]$certificateOffset + 8, $content, 0, $content.Length)
    return ,$content
}

function Assert-BoundRfc3161TimestampToken {
    param(
        [Parameter(Mandatory)][Security.Cryptography.Pkcs.SignerInfo]$SignerInfo,
        [Parameter(Mandatory)][byte[]]$TokenBytes,
        [Parameter(Mandatory)][Security.Cryptography.X509Certificates.X509Certificate2Collection]$ExtraCandidates,
        [Parameter(Mandatory)][Security.Cryptography.X509Certificates.X509Certificate2]$ExpectedTimestampCertificate
    )

    $timestampType = 'System.Security.Cryptography.Pkcs.Rfc3161TimestampToken' -as [type]
    if ($null -eq $timestampType -or
        $null -eq $timestampType.GetMethod('VerifySignatureForSignerInfo')) {
        throw 'The required Rfc3161TimestampToken.VerifySignatureForSignerInfo platform primitive is unavailable. Run release verification with supported PowerShell 7.'
    }
    if ($TokenBytes.Length -eq 0) {
        throw 'RFC 3161 timestamp token is empty.'
    }

    [Security.Cryptography.Pkcs.Rfc3161TimestampToken]$timestampToken = $null
    $bytesConsumed = 0
    $memory = [ReadOnlyMemory[byte]]::new($TokenBytes)
    try {
        $decoded = [Security.Cryptography.Pkcs.Rfc3161TimestampToken]::TryDecode(
            $memory,
            [ref]$timestampToken,
            [ref]$bytesConsumed)
    }
    catch {
        throw "RFC 3161 timestamp token decoding failed: $($_.Exception.Message)"
    }
    if (-not $decoded -or $null -eq $timestampToken -or $bytesConsumed -ne $TokenBytes.Length) {
        throw 'RFC 3161 timestamp token is malformed or contains trailing data.'
    }

    $tokenCms = $timestampToken.AsSignedCms()
    if ($tokenCms.SignerInfos.Count -ne 1) {
        throw "RFC 3161 timestamp token must contain exactly one signer; found $($tokenCms.SignerInfos.Count)."
    }

    [Security.Cryptography.X509Certificates.X509Certificate2]$timestampSigner = $null
    try {
        $isBound = $timestampToken.VerifySignatureForSignerInfo(
            $SignerInfo,
            [ref]$timestampSigner,
            $ExtraCandidates)
    }
    catch {
        throw "RFC 3161 timestamp token verification failed: $($_.Exception.Message)"
    }
    if (-not $isBound -or $null -eq $timestampSigner) {
        throw 'RFC 3161 timestamp token is not cryptographically valid and bound to the primary Authenticode SignerInfo.'
    }

    $actualCertificate = [Convert]::ToBase64String($timestampSigner.RawData)
    $expectedCertificate = [Convert]::ToBase64String($ExpectedTimestampCertificate.RawData)
    if (-not [StringComparer]::Ordinal.Equals($actualCertificate, $expectedCertificate)) {
        throw 'Cryptographically verified RFC 3161 signer does not match the trusted Authenticode timestamp certificate.'
    }

    return [pscustomobject]@{
        Token = $timestampToken
        TimestampSignerCertificate = $timestampSigner
        Timestamp = $timestampToken.TokenInfo.Timestamp
    }
}

function Assert-Rfc3161SignerInfo {
    param(
        [Parameter(Mandatory)][Security.Cryptography.Pkcs.SignerInfo]$SignerInfo,
        [Parameter(Mandatory)][Security.Cryptography.X509Certificates.X509Certificate2Collection]$ExtraCandidates,
        [Parameter(Mandatory)][Security.Cryptography.X509Certificates.X509Certificate2]$ExpectedTimestampCertificate
    )

    $rfc3161Attributes = @($SignerInfo.UnsignedAttributes | Where-Object {
        [StringComparer]::Ordinal.Equals($_.Oid.Value, $script:Rfc3161TimestampTokenOid)
    })
    $legacyAttributes = @($SignerInfo.UnsignedAttributes | Where-Object {
        [StringComparer]::Ordinal.Equals($_.Oid.Value, $script:LegacyAuthenticodeTimestampOid)
    })
    if ($legacyAttributes.Count -ne 0) {
        throw 'Legacy Authenticode countersignatures are not accepted as an RFC 3161 timestamp.'
    }
    if ($rfc3161Attributes.Count -ne 1 -or $rfc3161Attributes[0].Values.Count -ne 1) {
        throw 'Authenticode SignerInfo must contain exactly one RFC 3161 timestamp attribute with exactly one token.'
    }

    return Assert-BoundRfc3161TimestampToken `
        -SignerInfo $SignerInfo `
        -TokenBytes $rfc3161Attributes[0].Values[0].RawData `
        -ExtraCandidates $ExtraCandidates `
        -ExpectedTimestampCertificate $ExpectedTimestampCertificate
}

function Assert-Rfc3161TimestampContent {
    param(
        [Parameter(Mandatory)][byte[]]$Content,
        [Parameter(Mandatory)][string]$ExpectedSubject,
        [Parameter(Mandatory)][Security.Cryptography.X509Certificates.X509Certificate2]$ExpectedSignerCertificate,
        [Parameter(Mandatory)][Security.Cryptography.X509Certificates.X509Certificate2]$ExpectedTimestampCertificate
    )

    if ($null -eq ('System.Security.Cryptography.Pkcs.SignedCms' -as [type])) {
        throw 'System.Security.Cryptography.Pkcs is unavailable. Run release verification with supported PowerShell 7.'
    }

    $cms = [Security.Cryptography.Pkcs.SignedCms]::new()
    $cms.Decode($Content)
    $cms.CheckSignature($true)
    if ($cms.SignerInfos.Count -ne 1 -or $null -eq $cms.SignerInfos[0].Certificate) {
        throw "Expected exactly one embedded Authenticode signer, found $($cms.SignerInfos.Count)."
    }
    if (-not [StringComparer]::Ordinal.Equals($cms.SignerInfos[0].Certificate.Subject, $ExpectedSubject)) {
        throw "Embedded Authenticode signer subject does not match EXPECTED_SIGNER_SUBJECT. Actual: '$($cms.SignerInfos[0].Certificate.Subject)'."
    }
    if (-not [StringComparer]::Ordinal.Equals(
            [Convert]::ToBase64String($cms.SignerInfos[0].Certificate.RawData),
            [Convert]::ToBase64String($ExpectedSignerCertificate.RawData))) {
        throw 'Embedded Authenticode signer certificate does not match the Windows-trusted signer certificate.'
    }

    return Assert-Rfc3161SignerInfo `
        -SignerInfo $cms.SignerInfos[0] `
        -ExtraCandidates $cms.Certificates `
        -ExpectedTimestampCertificate $ExpectedTimestampCertificate
}

function Assert-Rfc3161Timestamp {
    param(
        [Parameter(Mandatory)][string]$ArtifactPath,
        [Parameter(Mandatory)][string]$ExpectedSubject,
        [Parameter(Mandatory)][Security.Cryptography.X509Certificates.X509Certificate2]$ExpectedSignerCertificate,
        [Parameter(Mandatory)][Security.Cryptography.X509Certificates.X509Certificate2]$ExpectedTimestampCertificate
    )

    $extension = [IO.Path]::GetExtension($ArtifactPath)
    $cmsBytes = if ([StringComparer]::OrdinalIgnoreCase.Equals($extension, '.exe')) {
        Get-PeSignatureContent -ExecutablePath $ArtifactPath
    }
    elseif ([StringComparer]::OrdinalIgnoreCase.Equals($extension, '.ps1')) {
        Get-PowerShellSignatureContent -ScriptPath $ArtifactPath
    }
    else {
        throw "Unsupported signed release artifact extension '$extension'."
    }

    return Assert-Rfc3161TimestampContent `
        -Content $cmsBytes `
        -ExpectedSubject $ExpectedSubject `
        -ExpectedSignerCertificate $ExpectedSignerCertificate `
        -ExpectedTimestampCertificate $ExpectedTimestampCertificate
}

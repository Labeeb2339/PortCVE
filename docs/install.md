# Installing PortCVE on Windows

The production installer requires 64-bit Windows and PowerShell 5.1 or newer. It is itself Authenticode-signed, must run from a downloaded `install.ps1` file, installs for the current user at `%LOCALAPPDATA%\Programs\PortCVE`, and adds that directory to the user `PATH`; administrator rights are not required.

The checked-in [`scripts/install.ps1`](../scripts/install.ps1) file is a release template. It deliberately refuses to run until the trusted release workflow embeds the exact expected Authenticode signer subject. Download `install.ps1` from a signed GitHub Release, not from the repository source tree.

## Recommended: download, verify, inspect, then run

This example downloads the latest stable installer and its checksum with `curl.exe`, verifies the exact `install.ps1` entry and Windows trust result, leaves the script available for inspection, and then runs that file:

```powershell
$base = 'https://github.com/Labeeb2339/PortCVE/releases/latest/download'
$dir = Join-Path $env:TEMP 'portcve-installer'
New-Item -ItemType Directory -Force $dir | Out-Null

curl.exe --fail --location --proto '=https' --tlsv1.2 "$base/install.ps1" --output "$dir/install.ps1"
curl.exe --fail --location --proto '=https' --tlsv1.2 "$base/SHA256SUMS.txt" --output "$dir/SHA256SUMS.txt"

$lines = Get-Content "$dir/SHA256SUMS.txt"
$entry = @($lines | Where-Object { $_ -match '^(?<hash>[0-9a-fA-F]{64})\s+\*?install\.ps1$' })
if ($entry.Count -ne 1) { throw 'Expected exactly one install.ps1 checksum.' }
$entry[0] -match '^(?<hash>[0-9a-fA-F]{64})' | Out-Null
$expected = $Matches.hash.ToLowerInvariant()
$actual = (Get-FileHash "$dir/install.ps1" -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actual -cne $expected) { throw 'Installer checksum mismatch.' }

$signature = Get-AuthenticodeSignature -LiteralPath "$dir/install.ps1"
if ($signature.Status -ne 'Valid' -or $null -eq $signature.SignerCertificate -or $null -eq $signature.TimeStamperCertificate) {
    throw "Installer Authenticode verification failed: $($signature.StatusMessage)"
}
$signature.SignerCertificate.Subject  # compare with the documented PortCVE publisher

Get-Content "$dir/install.ps1"  # inspect before execution
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$dir/install.ps1"
```

The no-argument installer selects GitHub's latest stable release. To install an explicit release, including a release candidate, pass its exact tag:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$dir/install.ps1" -Version v1.0.0
```

An optional per-user destination can be selected with `-InstallDirectory`. The installer refuses dangerous roots, reparse-point targets, and directories containing files it does not manage. Piped, dot-generated, or other in-memory installation is not supported: download and invoke the signed file.

## What the installer verifies

The installer has no unsigned or signature-bypass mode. Before changing the installation it:

1. requires file-backed execution and requires Windows to report its own Authenticode signature and timestamp as trusted, with the exact embedded signer subject plus the Code Signing and Time Stamping EKUs, before any network or install-directory mutation;
2. resolves only `Labeeb2339/PortCVE` through GitHub's HTTPS API;
3. downloads the exact versioned Windows x64 ZIP and `SHA256SUMS.txt` with fixed size and timeout limits;
4. requires one exact checksum entry and verifies the complete ZIP with SHA-256;
5. extracts only the root `portcve.exe` through traversal-safe ZIP handling;
6. requires Windows to report a valid trusted Authenticode signature chain;
7. compares the executable's full signer certificate subject exactly with the same release-embedded identity;
8. requires the Code Signing EKU and a Windows-validated timestamp certificate with the Time Stamping EKU; and
9. verifies the copied executable again before installation.

Files are prepared in bounded, uniquely named staging directories on the target volume. Updates move the prior installation to a guarded backup, atomically move the staged directory into place, update only the user `PATH`, and restore the prior directory and `PATH` if a later step fails. Cleanup is limited to validated installer-owned temporary, staging, backup, or failed-install paths.

The installer sends no telemetry. Its only network requests are release metadata and assets from GitHub. An installation receipt records the release tag, ZIP checksum, signer subject, timestamp subject, and installation time locally.

Windows PowerShell 5.1 does not expose .NET's `Rfc3161TimestampToken.VerifySignatureForSignerInfo` primitive. The installer therefore relies on Windows Authenticode trust for its timestamp and does not claim to independently prove RFC 3161 message-imprint binding. The release workflow performs that separate proof for both published signed files under PowerShell 7 and refuses publication if decoding, signature binding, or trusted TSA matching fails.

## Current unsigned alpha

`v0.1.0-alpha.1` was published before code signing was configured. The production installer intentionally cannot install that unsigned artifact. Build it from source or manually verify the historical checksum only if you explicitly accept that alpha's unsigned status.

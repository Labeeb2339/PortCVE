# Installing PortCVE on Windows

The managed installer supports 64-bit Windows and Windows PowerShell 5.1 or newer. It installs for the current user at `%LOCALAPPDATA%\Programs\PortCVE`, so administrator rights are not required.

The checked-in [`scripts/install.ps1`](../scripts/install.ps1) file is an unsigned release template. It deliberately refuses to install or uninstall anything until the protected release workflow embeds the exact publisher subject and signs it. Use the `install.ps1` asset from a finalized [PortCVE GitHub Release](https://github.com/Labeeb2339/PortCVE/releases), not the source-tree template.

## Download, verify, inspect, then run

Do not pipe the installer into `iex`, `Invoke-Expression`, or another in-memory execution method. File-backed execution lets Windows and the installer verify the exact script before it performs network or filesystem activity.

This example downloads the latest stable installer, checks its exact release checksum entry, requires a trusted Authenticode signer and timestamp, leaves it available for inspection, and then runs it under `AllSigned` policy:

```powershell
$base = 'https://github.com/Labeeb2339/PortCVE/releases/latest/download'
$dir = Join-Path $env:TEMP 'portcve-installer'
New-Item -ItemType Directory -Force $dir | Out-Null

curl.exe --fail --location --proto '=https' --tlsv1.2 "$base/install.ps1" --output "$dir/install.ps1"
curl.exe --fail --location --proto '=https' --tlsv1.2 "$base/SHA256SUMS.txt" --output "$dir/SHA256SUMS.txt"

$lines = Get-Content -LiteralPath "$dir/SHA256SUMS.txt"
$entry = @($lines | Where-Object { $_ -cmatch '^(?<hash>[0-9a-f]{64})  install\.ps1$' })
if ($entry.Count -ne 1) { throw 'Expected exactly one canonical install.ps1 checksum.' }
$entry[0] -cmatch '^(?<hash>[0-9a-f]{64})' | Out-Null
$expected = $Matches.hash
$actual = (Get-FileHash -LiteralPath "$dir/install.ps1" -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actual -cne $expected) { throw 'Installer checksum mismatch.' }

$signature = Get-AuthenticodeSignature -LiteralPath "$dir/install.ps1"
if ($signature.Status -ne 'Valid' -or
    $null -eq $signature.SignerCertificate -or
    $null -eq $signature.TimeStamperCertificate) {
    throw "Installer Authenticode verification failed: $($signature.StatusMessage)"
}
$signature.SignerCertificate.Subject  # compare with the publisher stated by the release

Get-Content -LiteralPath "$dir/install.ps1"  # inspect before execution
powershell.exe -NoProfile -ExecutionPolicy AllSigned -File "$dir/install.ps1"
```

If `curl.exe` is unavailable, use file-backed PowerShell downloads in place of the two `curl.exe` lines; do not append `| iex`:

```powershell
Invoke-WebRequest -UseBasicParsing -Uri "$base/install.ps1" -OutFile "$dir/install.ps1"
Invoke-WebRequest -UseBasicParsing -Uri "$base/SHA256SUMS.txt" -OutFile "$dir/SHA256SUMS.txt"
```

GitHub's `releases/latest` endpoint selects the latest stable release, not a prerelease. To install a prerelease or another exact version, download `install.ps1` and `SHA256SUMS.txt` from that release page and pass its exact tag:

```powershell
powershell.exe -NoProfile -ExecutionPolicy AllSigned -File "$dir/install.ps1" -Version v1.0.0-rc.1
```

An optional destination on a fixed local Windows drive can be selected with `-InstallDirectory`. UNC, mapped network, removable-drive, root, and existing reparse-point paths are refused. Repeat the exact same path for later updates, rollback, or uninstall.

## Update and rollback

The managed installation keeps the exact verified signed installer as `%LOCALAPPDATA%\Programs\PortCVE\install.ps1`. Run that file to update to the latest stable release:

```powershell
powershell.exe -NoProfile -ExecutionPolicy AllSigned `
    -File "$env:LOCALAPPDATA\Programs\PortCVE\install.ps1"
```

An update is staged on the target volume. Before commit, the existing receipt-bound installation is moved to a guarded backup. If staging, replacement, or the user `PATH` update fails, the previous directory and `PATH` are restored. A backup-cleanup failure is reported separately after the new version is already committed; it is never misreported as a successful rollback.

To deliberately roll back after a successful update, invoke a verified signed installer with the exact earlier signed release tag:

```powershell
powershell.exe -NoProfile -ExecutionPolicy AllSigned -File "$dir/install.ps1" -Version v1.0.0
```

The selected release must still exist, contain the exact PortCVE asset names, and carry the same release-bound signer identity expected by that installer. Unsigned historical builds cannot be selected as rollback targets.

## Uninstall

Use the signed copy kept in the managed installation from a working directory outside the PortCVE install directory. Uninstall verifies that file's own signature first, makes no network request, validates the managed receipt and exact directory contents, removes only the exact PortCVE user `PATH` entry, and deletes the guarded installation directory:

```powershell
powershell.exe -NoProfile -ExecutionPolicy AllSigned `
    -File "$env:LOCALAPPDATA\Programs\PortCVE\install.ps1" `
    -Uninstall
```

For a custom location:

```powershell
powershell.exe -NoProfile -ExecutionPolicy AllSigned -File "$dir/install.ps1" `
    -Uninstall `
    -InstallDirectory 'C:\Users\you\Tools\PortCVE'
```

If the installed script or executable is missing, damaged, or no longer matches its receipt, every signed installer deliberately refuses automatic deletion. Inspect the exact directory and receipt, then remove the confirmed damaged directory manually; after it is absent, a newly downloaded and verified signed installer invoked with `-Uninstall` can remove only the exact stale user `PATH` entry. `-Version` and `-Uninstall` cannot be combined. A target with an invalid receipt, extra file, directory, reparse point, hash mismatch, or invalid signature never enters the automatic deletion path.

Open a new terminal after install or uninstall so it receives the updated user `PATH`.

## Portable ZIP

Each finalized release also contains `portcve-<tag>-win-x64.zip`. This is the right option for an engagement folder, disposable VM, or environment where `PATH` should not be changed:

1. Download the exact ZIP and `SHA256SUMS.txt` from the same PortCVE release.
2. Require one canonical checksum entry for the ZIP and compare its complete SHA-256 hash.
3. Extract to a new directory.
4. Require `Get-AuthenticodeSignature .\portcve.exe` to report `Valid` with the expected publisher and timestamp.
5. Run `.\portcve.exe --version` before use.

The portable ZIP contains the same signed executable as the managed installer plus release documentation and schemas. It does not create an installation receipt, change `PATH`, update itself, or provide managed uninstall behavior. Delete the directory yourself when finished.

## What the managed installer verifies

The installer has no unsigned or signature-bypass mode. Before installing or updating it:

1. requires file-backed execution and requires Windows to report its own Authenticode signature and timestamp as trusted, with the exact embedded signer subject plus the Code Signing and Time Stamping EKUs, before any network or install-directory mutation;
2. resolves only `Labeeb2339/PortCVE` through GitHub's HTTPS API;
3. downloads the exact versioned `portcve-<tag>-win-x64.zip` and `SHA256SUMS.txt` with fixed size and timeout limits;
4. requires one exact checksum entry and verifies the complete ZIP with SHA-256;
5. extracts only the root `portcve.exe` through traversal-safe ZIP handling;
6. requires Windows to report a valid trusted Authenticode signature chain;
7. compares the executable's full signer certificate subject exactly with the same release-embedded identity;
8. requires the Code Signing EKU and a Windows-validated timestamp certificate with the Time Stamping EKU; and
9. verifies both the copied executable and copied signed maintenance installer again before installation.

The versioned receipt records schema version, product and repository identity, canonical install path, release tag, exact ZIP asset, ZIP, executable, and installer SHA-256 hashes, signer and timestamp subjects, and installation time. Existing non-empty directories must have exactly `portcve.exe`, signed `install.ps1`, and `install-receipt.json`; the actual executable and installer hashes, trusted Authenticode state, exact release-bound signer, executable timestamp, and required EKUs must still pass before update or uninstall.

Use the default per-user directory or another parent writable only by the same trusted user. The receipt and hash checks catch damage, partial replacement, and mixed installation state; the receipt is not itself a signed authorization object. The installer checks fixed-local-drive, component, ancestor, reparse-point, receipt, hash, signature, and managed-child boundaries initially and again immediately before commit. These checks cannot create an isolation boundary against another process already running as the same user that replaces both files and receipt or wins the residual race after the final check.

The installer sends no telemetry. Its only network requests are release metadata and assets from GitHub, and uninstall makes no network request.

Windows PowerShell 5.1 does not expose .NET's `Rfc3161TimestampToken.VerifySignatureForSignerInfo` primitive. The installer therefore relies on Windows Authenticode trust for its timestamp and does not claim to independently prove RFC 3161 message-imprint binding. The release workflow performs that separate proof for both published signed files under PowerShell 7 and refuses publication if decoding, signature binding, or trusted TSA matching fails.

## Historical unsigned alpha

`v0.1.0-alpha.1` was published under the former BindWitness name before code signing was configured. Its ZIP and executable are unsigned, its assets use historical names, and it has no production signed installer asset. The PortCVE installer intentionally rejects it; it is not a valid daily-use installation or rollback target.

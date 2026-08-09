# Installing PortCVE on Windows

The production installer requires 64-bit Windows and PowerShell 5.1 or newer. It installs for the current user at `%LOCALAPPDATA%\Programs\PortCVE` and adds that directory to the user `PATH`; administrator rights are not required.

The checked-in [`scripts/install.ps1`](../scripts/install.ps1) file is a release template. It deliberately refuses to run until the trusted release workflow embeds the exact expected Authenticode signer subject. Download `install.ps1` from a signed GitHub Release, not from the repository source tree.

## Recommended: download, verify, inspect, then run

This example downloads the latest stable installer and its checksum with `curl.exe`, verifies the exact `install.ps1` entry, leaves the script available for inspection, and then runs it:

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

Get-Content "$dir/install.ps1"  # inspect before execution
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$dir/install.ps1"
```

The no-argument installer selects GitHub's latest stable release. To install an explicit release, including a release candidate, pass its exact tag:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$dir/install.ps1" -Version v1.0.0
```

An optional per-user destination can be selected with `-InstallDirectory`. The installer refuses dangerous roots, reparse-point targets, and directories containing files it does not manage.

## Quick command

```powershell
irm https://github.com/Labeeb2339/PortCVE/releases/latest/download/install.ps1 | iex
```

Security warning: `irm ... | iex` executes remote text immediately. It prevents you from inspecting or independently checksum-verifying the installer first. The installer still verifies the downloaded PortCVE release, but the download-and-inspect method above is the safer default.

## What the installer verifies

The installer has no unsigned or signature-bypass mode. Before changing the installation it:

1. resolves only `Labeeb2339/PortCVE` through GitHub's HTTPS API;
2. downloads the exact versioned Windows x64 ZIP and `SHA256SUMS.txt` with fixed size and timeout limits;
3. requires one exact checksum entry and verifies the complete ZIP with SHA-256;
4. extracts only the root `portcve.exe` through traversal-safe ZIP handling;
5. requires Windows to report a valid trusted Authenticode signature chain;
6. compares the full signer certificate subject exactly with the value embedded by the release workflow;
7. requires the Code Signing EKU, a timestamp certificate with the Time Stamping EKU, and an RFC 3161 timestamp; and
8. verifies the copied executable again before installation.

Files are prepared in bounded, uniquely named staging directories on the target volume. Updates move the prior installation to a guarded backup, atomically move the staged directory into place, update only the user `PATH`, and restore the prior directory and `PATH` if a later step fails. Cleanup is limited to validated installer-owned temporary, staging, backup, or failed-install paths.

The installer sends no telemetry. Its only network requests are release metadata and assets from GitHub. An installation receipt records the release tag, ZIP checksum, signer subject, timestamp subject, and installation time locally.

## Current unsigned alpha

`v0.1.0-alpha.1` was published before code signing was configured. The production installer intentionally cannot install that unsigned artifact. Build it from source or manually verify the historical checksum only if you explicitly accept that alpha's unsigned status.

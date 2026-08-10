# Release signing

This is the maintainer runbook for Windows releases. The workflow is fail-closed: it cannot publish a PortCVE release unless both `portcve.exe` and `install.ps1` pass the configured signing and verification checks.

No signed PortCVE release exists yet. The workflow remains blocked until a verified publisher certificate and production eSigner credentials are configured.

## Prerequisites

The current workflow uses [SSL.com eSigner](https://www.ssl.com/products/software-integrity/signing-service/). The certificate subject becomes the publisher shown by Windows, so use the exact validated subject rather than a project nickname.

Configure the `release-signing` GitHub environment with these secrets:

- `ES_USERNAME`
- `ES_PASSWORD`
- `CREDENTIAL_ID`
- `ES_TOTP_SECRET`

Set the repository variable `EXPECTED_SIGNER_SUBJECT` to the complete X.500 subject returned by a controlled test signature:

```powershell
(Get-AuthenticodeSignature -LiteralPath .\portcve.exe).SignerCertificate.Subject
```

The value must match Windows output exactly, including ordering, punctuation, and whitespace.

Required repository controls:

- `main` changes go through a pull request and required CI checks;
- tags matching `v*` are protected;
- releases are immutable;
- GitHub Actions are pinned to full commit SHAs; and
- `release-signing` is limited to the release-tag policy, has a wait timer and approval gate, and does not allow administrator bypass.

The current solo-maintainer approval is a manual checkpoint, not separation of duties. Add a second trusted reviewer and enable prevent-self-review before describing the release process as independently approved.

## Workflow

`.github/workflows/release.yml` has three jobs:

1. `build` restores locked dependencies, checks formatting, builds and tests, runs the installer harness, publishes one unsigned executable, and smoke-tests it. This job has no signing secrets.
2. `sign` runs behind the protected environment. It finalizes the installer, signs the executable and installer separately, and verifies both files.
3. `package_publish` repeats verification, packages the signed executable, writes checksums and signing metadata, creates provenance attestations, uploads a draft release, verifies GitHub's asset digests, and then publishes it.

Signing secrets are exposed only to the configuration check and the two pinned eSigner steps.

Verification requires:

- `signtool verify /pa /all /v` to accept the executable;
- `Get-AuthenticodeSignature` to report `Valid`;
- an exact match with `EXPECTED_SIGNER_SUBJECT`;
- the Code Signing and Time Stamping EKUs;
- one SHA-256 Authenticode signature and one timestamp; and
- PowerShell 7.2 or newer to decode the RFC 3161 token, bind it to the primary signature with `VerifySignatureForSignerInfo`, and match the returned TSA certificate to the Windows-trusted timestamp certificate.

Malformed, duplicated, unbound, legacy, or mismatched timestamp data stops the release. There is no unsigned fallback.

## Release procedure

1. Merge the intended version change to `main` and wait for CI and CodeQL.
2. Confirm the worktree is clean and the project version matches the intended tag.
3. Review changes to action pins, signing tools, or release scripts separately.
4. Create an annotated tag at the reviewed `main` commit. Use a signed Git tag when a maintainer signing key is configured:

   ```powershell
   git switch main
   git pull --ff-only
   git tag -s v1.0.0 -m "PortCVE v1.0.0"
   git push origin v1.0.0
   ```

5. Approve the `release-signing` deployment only after checking the tag, commit, workflow diff, and expected publisher subject.
6. Confirm signature verification, signed smoke tests, checksums, provenance, and asset-digest checks all passed.
7. Download the release on a clean Windows machine and test the portable ZIP plus managed install, update, rollback, and uninstall paths.

Stable tags use `vMAJOR.MINOR.PATCH`. Prereleases use forms such as `v1.0.0-rc.1`. The workflow and installer share the same tag parser.

## Verify downloaded assets

From a clean checkout of the release tag, place the downloaded assets in the repository root and run:

```powershell
$expected = Get-Content -LiteralPath .\SHA256SUMS.txt | ForEach-Object {
    $hash, $name = $_ -split '\s+', 2
    [pscustomobject]@{ Hash = $hash; Name = $name }
}

foreach ($entry in $expected) {
    $path = Join-Path $PWD $entry.Name
    $actual = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -cne $entry.Hash) { throw "Checksum mismatch: $($entry.Name)" }
}

pwsh -NoProfile -File .\scripts\Verify-ReleaseSignature.ps1 `
    -Path .\portcve.exe `
    -ExpectedSignerSubject 'PASTE THE PUBLISHED FULL X.500 SUBJECT'

pwsh -NoProfile -File .\scripts\Verify-ReleaseSignature.ps1 `
    -Path .\install.ps1 `
    -ExpectedSignerSubject 'PASTE THE PUBLISHED FULL X.500 SUBJECT'
```

If GitHub CLI is available, verify provenance as well:

```powershell
gh attestation verify .\portcve.exe --repo Labeeb2339/PortCVE
gh attestation verify .\portcve-v1.0.0-win-x64.zip --repo Labeeb2339/PortCVE
```

Then exercise the signed installer on a clean machine as described in [install.md](install.md).

## Before 1.0

Do not publish `v1.0.0` until all of these are true:

- the publisher certificate and production eSigner credential are active;
- a controlled test signature established the reviewed full signer subject;
- the complete production workflow passed on a prerelease tag;
- both downloaded files passed SignTool, Authenticode, EKU, and RFC 3161 binding checks;
- the portable ZIP and standalone executable contain the same signed binary recorded in `SIGNING-METADATA.json`;
- checksums and GitHub provenance verify after download;
- a clean Windows machine completed install, update, rollback, and receipt-bound uninstall testing; and
- release notes describe SmartScreen and vulnerability results without promising warning-free execution or exploitability.

Record the release URL, workflow run, executable SHA-256, signer subject, and verification-machine details. Never record signing secrets or authentication logs.

The old `v0.1.0-alpha.1` BindWitness release is historical and unsigned. It is not accepted by the PortCVE installer; see [CHANGELOG.md](../CHANGELOG.md).

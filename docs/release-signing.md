# PortCVE release signing

PortCVE's public Windows releases are fail-closed: the release workflow cannot publish an unsigned executable or production installer. A candidate is built and tested without signing credentials, the installer is finalized as UTF-8 with BOM, both files are approved through the protected `release-signing` environment and signed by SSL.com eSigner, independently verified, packaged, checksummed, attested, uploaded as a draft, and published only after GitHub reports matching SHA-256 asset digests.

This document is an operator runbook, not evidence that the current repository or certificate account is already configured. The repository cannot create a trusted publisher identity by itself. Before the first signed release, Labeeb must complete external certificate-provider identity validation, activate the signing credential, and configure the protected GitHub environment and secrets. Until those external steps are evidenced, the workflow must fail closed and no build should be described as signed or daily-ready.

## Malaysia signing route

For a maintainer or organization based in Malaysia, SSL.com eSigner is the practical route currently wired into the workflow. The certificate holder must complete SSL.com's identity validation and obtain a code-signing credential that can be used with eSigner automation. The Windows publisher shown to users will be the validated legal subject in the certificate; it cannot honestly be made an arbitrary project nickname.

SSL.com currently lists an Individual Validation Authenticode certificate from USD 129 per year and eSigner Tier 1 at USD 15 per month for 240 signings, before tax. The validated personal or organization name becomes the Windows publisher and the signing key remains in SSL.com's cloud HSM. Pricing, quotas, and eligibility can change, so confirm them before purchase:

- [SSL.com Individual Validation code signing](https://www.ssl.com/products/software-integrity/code-signing/iv/)
- [SSL.com eSigner pricing](https://www.ssl.com/guide/esigner-pricing-for-code-signing/)
- [SSL.com eSigner automation setup](https://www.ssl.com/how-to/automate-esigner-ev-code-signing/)

Expect government-ID, address, and liveness checks for an individual, or company-registration and authorized-representative checks for an organization. Keep the eSigner automation credential dedicated to PortCVE releases and grant only the access it needs.

Microsoft Artifact Signing Public Trust is not currently a fallback for a Malaysian individual or Malaysia-incorporated organization. Microsoft's published eligibility limits individuals to the United States and Canada and organizations to the United States, Canada, the European Union, and the United Kingdom. Recheck the official [Artifact Signing prerequisites](https://learn.microsoft.com/en-us/azure/artifact-signing/quickstart) if Microsoft expands availability.

An OV or EV certificate does not guarantee an immediate Microsoft Defender SmartScreen reputation. Microsoft describes reputation as based on signals including download history and antivirus results; do not promise that EV automatically removes warnings. See [Microsoft Defender SmartScreen and app reputation](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/smartscreen-reputation).

## Required GitHub configuration

Configure these controls before creating a release tag:

1. Create an environment named exactly `release-signing`.
2. The current solo-maintainer environment has a five-minute wait timer, requires approval from `Labeeb2339`, and restricts deployments with the custom `v*` tag policy. This is an explicit manual gate, not separation of duties: with Labeeb as the sole reviewer, prevent-self-review cannot be enabled, and administrators can currently bypass the environment. When another trusted maintainer is available, require that independent reviewer, enable prevent-self-review, and remove administrator bypass before making a stable high-assurance release claim. GitHub documents these controls under [deployment environments](https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments).
3. Store these four values as environment secrets, never repository files or ordinary variables:
   - `ES_USERNAME`
   - `ES_PASSWORD`
   - `CREDENTIAL_ID`
   - `ES_TOTP_SECRET`
4. Create the repository variable `EXPECTED_SIGNER_SUBJECT`. Its value must be the complete X.500 subject returned by `Get-AuthenticodeSignature`, with exact spelling, ordering, punctuation, and whitespace. A simple common name is insufficient. For example, capture it from a controlled SSL.com test-signed executable:

   ```powershell
   (Get-AuthenticodeSignature -LiteralPath .\portcve.exe).SignerCertificate.Subject
   ```

5. Enable [immutable releases](https://docs.github.com/en/code-security/concepts/supply-chain-security/immutable-releases). The workflow queries the repository setting and fails before creating a draft if it is disabled.
6. Protect `main` with a ruleset requiring reviews and passing CI. Restrict who can create tags matching `v*`. If available for the repository, require actions to be pinned to full commit SHAs.

GitHub should also limit the `release-signing` environment's deployment tag pattern to the narrowest pattern the UI supports. The workflow still performs its own exact SemVer, annotated-tag, project-version, and `origin/main` ancestry checks because an environment pattern alone is not sufficient.

## What the workflow enforces

The workflow in `.github/workflows/release.yml` has three security boundaries:

- `build` has read-only repository access and no signing secrets. It restores locked dependencies, checks formatting, builds, tests, runs the clean install/update/failed-update rollback/uninstall fixture under Windows PowerShell 5.1, publishes exactly one unsigned `portcve.exe`, and smoke-tests it.
- `sign` runs only after approval in `release-signing`. It fails if any secret or the expected full signer subject is missing. It finalizes `install.ps1` with a UTF-8 BOM, verifies the exact SHA-256 of SSL.com CodeSignTool 1.3.0, and invokes the pinned SSL.com action separately for the exact `portcve.exe` and `install.ps1` paths.
- `package_publish` has the release and attestation permissions. It downloads only the two verified signed files, repeats signature verification, creates `portcve-<tag>-win-x64.zip`, proves that the ZIP, standalone executable, and signing metadata contain the exact same signed executable hash, writes a checksum for every public asset other than the checksum file itself, generates GitHub provenance attestations, creates a draft, checks GitHub's recorded asset digests, and only then publishes it.

Signature verification requires all of the following:

- for `portcve.exe`, `signtool verify /pa /all /v` succeeds with exactly one SHA-256 signature, one validated timestamp, zero warnings, and zero errors;
- `Get-AuthenticodeSignature` reports `Valid`;
- the signer's full subject is an ordinal, exact match for `EXPECTED_SIGNER_SUBJECT`;
- the signer certificate contains Code Signing EKU `1.3.6.1.5.5.7.3.3`;
- a timestamp certificate containing Time Stamping EKU `1.3.6.1.5.5.7.3.8` is present; and
- under PowerShell 7.2 or newer, the PE certificate table or PowerShell signature block contains exactly one RFC 3161 token, with no legacy countersignature; `Rfc3161TimestampToken.TryDecode` consumes the complete token, `VerifySignatureForSignerInfo` cryptographically binds its message imprint to the primary Authenticode `SignerInfo`, and the returned TSA certificate exactly matches the Windows-trusted timestamp certificate.

The release verifier fails if the PowerShell 7 platform primitive is unavailable, or if a token is malformed, has trailing data, is unbound, has an invalid signature, uses a different TSA certificate, is duplicated, or is accompanied by a legacy countersignature. Windows PowerShell 5.1 cannot access this .NET primitive. The production installer therefore makes the narrower claim that Windows reports the Authenticode signature and timestamp as trusted and that both required EKUs are present; it does not perform or claim an independent RFC 3161 binding proof.

There is no unsigned fallback. Missing credentials, a changed action/tool download, unexpected files, a wrong subject, a missing timestamp, a failed smoke test, a checksum mismatch, failed provenance, or a release API error stops publication.

## Release procedure

1. Confirm CI is green on `main` and the worktree is clean.
2. Update `<Version>` in `src/PortCVE/PortCVE.csproj` to the exact intended SemVer and merge it to `main`.
3. Review every third-party action commit and the CodeSignTool archive hash. Update pins only in a dedicated reviewed change.
4. Create an annotated tag at the reviewed `main` commit. A maintainer with a configured signing key should prefer a cryptographically signed annotated tag:

   ```powershell
   git switch main
   git pull --ff-only
   git tag -s v1.0.0 -m "PortCVE v1.0.0"
   git push origin v1.0.0
   ```

   If signed Git tags are not yet configured, `git tag -a` satisfies the workflow's annotated-tag check, but the binary-signing and release controls remain the security boundary.

5. Review and approve the `release-signing` environment deployment only after confirming the tag, commit SHA, workflow diff, and expected publisher subject.
6. Confirm the workflow's signature verification, signed smoke test, metadata validation, provenance attestation, draft digest verification, and final publish steps all passed.
7. Download the published assets on a clean separate Windows machine and run the checksum, signature, portable ZIP, and managed lifecycle checks below. Record install, update, explicit rollback, and uninstall results.

Stable tags such as `v1.0.0` publish as the latest stable release. Policy-compatible prerelease tags such as `v1.0.0-rc.1` publish as prereleases. Numeric identifiers with leading zeroes, prerelease identifiers beginning with a hyphen, and build metadata such as `+build.5` are intentionally rejected by the same rule in the workflow and installer.

## Consumer verification

From a clean checkout of the exact release tag, with the downloaded release assets placed at the repository root:

```powershell
$expected = (Get-Content -LiteralPath .\SHA256SUMS.txt | ForEach-Object {
    $hash, $name = $_ -split '\s+', 2
    [pscustomobject]@{ Hash = $hash; Name = $name }
})
foreach ($entry in $expected) {
    $actual = (Get-FileHash -LiteralPath (Join-Path $PWD $entry.Name) -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -cne $entry.Hash) { throw "Checksum mismatch: $($entry.Name)" }
}

pwsh -NoProfile -File .\scripts\Verify-ReleaseSignature.ps1 `
    -Path .\portcve.exe `
    -ExpectedSignerSubject 'PASTE THE EXACT PUBLISHED FULL X.500 SUBJECT'

pwsh -NoProfile -File .\scripts\Verify-ReleaseSignature.ps1 `
    -Path .\install.ps1 `
    -ExpectedSignerSubject 'PASTE THE EXACT PUBLISHED FULL X.500 SUBJECT'
```

GitHub provenance can also be verified with GitHub CLI after authenticating:

```powershell
gh attestation verify .\portcve.exe --repo Labeeb2339/PortCVE
gh attestation verify .\portcve-v1.0.0-win-x64.zip --repo Labeeb2339/PortCVE
```

On the clean verification machine, exercise the supported lifecycle with the downloaded, checksum-verified, Authenticode-valid `install.ps1`:

```powershell
# Clean install of the candidate.
powershell.exe -NoProfile -ExecutionPolicy AllSigned -File .\install.ps1 -Version v1.1.0
portcve --version

# Update or deliberate rollback use the same signed installer and exact tags.
powershell.exe -NoProfile -ExecutionPolicy AllSigned -File .\install.ps1 -Version v1.0.0
portcve --version
powershell.exe -NoProfile -ExecutionPolicy AllSigned -File .\install.ps1 -Version v1.1.0
portcve --version

# Uninstall is offline and must remove the exact managed directory and PATH entry.
powershell.exe -NoProfile -ExecutionPolicy AllSigned -File .\install.ps1 -Uninstall
if (Test-Path "$env:LOCALAPPDATA\Programs\PortCVE") { throw 'PortCVE uninstall left its managed directory.' }
```

Replace the example tags with two actual compatible signed releases. For the first signed release, the offline Windows PowerShell fixture is the rollback evidence until a second signed release exists; do not invent an end-to-end cross-release result. Repeat the lifecycle with `-InstallDirectory` for the supported custom-path case. Open a new terminal before each `portcve --version` check so it receives the current user `PATH`.

## Pre-1.0 release gate

Do not call a build `1.0.0` until every item is evidenced:

- SSL.com validation and the production eSigner credential are active.
- `EXPECTED_SIGNER_SUBJECT` was copied from a controlled test signature and independently reviewed.
- `release-signing` has the recorded wait timer, explicit approval, and release-tag restriction. Before a stable high-assurance claim, an independent trusted reviewer is required and prevent-self-review plus no-administrator-bypass are enabled; the current solo-maintainer approval alone does not satisfy separation of duties.
- `main` and `v*` tags are protected, immutable releases are enabled, and action SHA pinning is enforced where available.
- A prerelease completed the entire production signing workflow without manual artifact substitution.
- The PowerShell 7 release verifier accepted both downloaded signed files with the exact subject, Code Signing and Time Stamping EKUs, and a `VerifySignatureForSignerInfo` RFC 3161 binding proof; SignTool also accepted the executable's SHA-256 signature.
- Windows PowerShell 5.1 parsed the finalized UTF-8 BOM installer with the exact non-ASCII test subject, and the installer rejected unsigned or in-memory execution before network or install-directory mutation.
- The Windows PowerShell 5.1 offline lifecycle fixture passed clean install, managed update, invalid installed-signature rejection, executable/installer/receipt tamper rejection, pre-commit failed-update rollback, exact PATH removal, receipt rejection, and guarded uninstall checks without adding a production bypass or trusting a test root CA.
- `portcve.exe --version` and a no-firewall snapshot smoke test passed after signing and after download.
- Every file in `SHA256SUMS.txt` matched, the installer rejected a tampered ZIP/executable, and GitHub provenance verification passed.
- The portable ZIP, standalone `portcve.exe`, and `SIGNING-METADATA.json` contain the same signed executable hash.
- A clean Windows machine completed managed install, update, explicit signed-version rollback, and receipt-bound offline uninstall; if only one signed release exists, record that cross-release rollback remains pending instead of claiming it passed.
- Release notes, license, security policy, schema files, and vulnerability-data limitations are accurate for 1.0.
- Defender/SmartScreen behavior was observed on a clean Windows machine and described honestly, without promising reputation or warning-free execution.

Record the test tag, release URL, workflow run ID, executable SHA-256, signer subject, and verification machine details in the release evidence. Never record the four eSigner secrets or authentication logs.

## Historical BindWitness-era release

The public `v0.1.0-alpha.1` prerelease was created before the repository was renamed. Its description now identifies it as historical and unsigned and uses the current PortCVE changelog URL. Its two historical assets remain `bindwitness-v0.1.0-alpha.1-win-x64.zip` and `SHA256SUMS.txt`; they must not be presented as current PortCVE artifacts.

If the release description is ever repaired again, change only its explanatory text and keep this claim boundary:

```markdown
Historical unsigned BindWitness-era prerelease. This artifact is not accepted by the PortCVE signed installer and is not recommended for daily use.

Full Changelog: https://github.com/Labeeb2339/PortCVE/commits/v0.1.0-alpha.1
```

Do not rename, replace, or re-upload the historical assets as PortCVE binaries. Future workflow-generated releases use the current `Labeeb2339/PortCVE` repository and exact `portcve.exe`, `install.ps1`, `portcve-<tag>-win-x64.zip`, `SHA256SUMS.txt`, and `SIGNING-METADATA.json` asset names.

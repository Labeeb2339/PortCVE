# PortCVE release signing

PortCVE's public Windows releases are fail-closed: the release workflow cannot publish an unsigned executable. A candidate is built and tested without signing credentials, approved through the protected `release-signing` environment, signed by SSL.com eSigner, independently verified, packaged, checksummed, attested, uploaded as a draft, and published only after GitHub reports matching SHA-256 asset digests.

This document is an operator runbook, not evidence that the current repository or certificate account is already configured. Repository settings and SSL.com identity validation must be completed by a maintainer before the first signed release.

## Malaysia signing route

For a maintainer or organization based in Malaysia, SSL.com eSigner is the practical route currently wired into the workflow. The certificate holder must complete SSL.com's identity validation and obtain a code-signing credential that can be used with eSigner automation. The Windows publisher shown to users will be the validated legal subject in the certificate; it cannot honestly be made an arbitrary project nickname.

SSL.com currently lists an Individual Validation code-signing certificate from USD 129 per year and eSigner Tier 1 from USD 180 per year, before tax, with the first 30 days of eSigner included for new code-signing orders. Pricing and eligibility can change, so confirm them before purchase:

- [SSL.com Individual Validation code signing](https://www.ssl.com/products/software-integrity/code-signing/iv/)
- [SSL.com eSigner pricing](https://www.ssl.com/guide/esigner-pricing-for-code-signing/)
- [SSL.com eSigner automation setup](https://www.ssl.com/how-to/automate-esigner-ev-code-signing/)

Expect government-ID, address, and liveness checks for an individual, or company-registration and authorized-representative checks for an organization. Keep the eSigner automation credential dedicated to PortCVE releases and grant only the access it needs.

Azure Artifact Signing is not a fallback for a Malaysian individual or Malaysia-incorporated organization under Microsoft's current country eligibility. Microsoft currently supports individual accounts only in the United States and Canada, and its organization-country list does not include Malaysia. Recheck the official [Artifact Signing prerequisites](https://learn.microsoft.com/en-us/azure/artifact-signing/quickstart) if Microsoft expands availability.

An OV or EV certificate does not guarantee an immediate Microsoft Defender SmartScreen reputation. Microsoft describes reputation as based on signals including download history and antivirus results; do not promise that EV automatically removes warnings. See [Microsoft Defender SmartScreen and app reputation](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/smartscreen-reputation).

## Required GitHub configuration

Configure these controls before creating a release tag:

1. Create an environment named exactly `release-signing`.
2. Add required reviewers, prevent self-review, restrict deployments to release tags, and do not allow administrators to bypass the protection. GitHub documents these controls under [deployment environments](https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments).
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

- `build` has read-only repository access and no signing secrets. It restores locked dependencies, checks formatting, builds, tests, publishes exactly one unsigned `portcve.exe`, and smoke-tests it.
- `sign` runs only after approval in `release-signing`. It fails if any secret or the expected full signer subject is missing. It verifies the exact SHA-256 of SSL.com CodeSignTool 1.3.0 before the pinned SSL.com action signs only `portcve.exe`.
- `package_publish` has the release and attestation permissions. It downloads only the verified signed artifact, repeats signature verification, creates the ZIP and installer, writes a checksum for every public asset other than the checksum file itself, generates GitHub provenance attestations, creates a draft, checks GitHub's recorded asset digests, and only then publishes it.

Signature verification requires all of the following:

- `signtool verify /pa /all /v` succeeds with exactly one SHA-256 signature, one validated timestamp, zero warnings, and zero errors;
- `Get-AuthenticodeSignature` reports `Valid`;
- the signer's full subject is an ordinal, exact match for `EXPECTED_SIGNER_SUBJECT`;
- the signer certificate contains Code Signing EKU `1.3.6.1.5.5.7.3.3`;
- a timestamp certificate is present; and
- the PE's PKCS#7 signature contains the RFC 3161 timestamp-token OID rather than only a legacy countersignature.

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
7. Download the published assets on a separate Windows machine and run the consumer checks below.

Stable tags such as `v1.0.0` publish as the latest stable release. Valid prerelease tags such as `v1.0.0-rc.1` publish as prereleases. Build metadata such as `+build.5` is intentionally rejected.

## Consumer verification

From a clean directory containing the release assets:

```powershell
$expected = (Get-Content -LiteralPath .\SHA256SUMS.txt | ForEach-Object {
    $hash, $name = $_ -split '\s+', 2
    [pscustomobject]@{ Hash = $hash; Name = $name }
})
foreach ($entry in $expected) {
    $actual = (Get-FileHash -LiteralPath (Join-Path $PWD $entry.Name) -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -cne $entry.Hash) { throw "Checksum mismatch: $($entry.Name)" }
}

.\scripts\Verify-ReleaseSignature.ps1 `
    -Path .\portcve.exe `
    -ExpectedSignerSubject 'PASTE THE EXACT PUBLISHED FULL X.500 SUBJECT'
```

GitHub provenance can also be verified with GitHub CLI after authenticating:

```powershell
gh attestation verify .\portcve.exe --repo Labeeb2339/PortCVE
gh attestation verify .\portcve-v1.0.0-win-x64.zip --repo Labeeb2339/PortCVE
```

## Pre-1.0 release gate

Do not call a build `1.0.0` until every item is evidenced:

- SSL.com validation and the production eSigner credential are active.
- `EXPECTED_SIGNER_SUBJECT` was copied from a controlled test signature and independently reviewed.
- `release-signing` has required reviewers, self-review prevention, and release-tag restrictions.
- `main` and `v*` tags are protected, immutable releases are enabled, and action SHA pinning is enforced where available.
- A prerelease completed the entire production signing workflow without manual artifact substitution.
- Both verification engines accepted the downloaded release executable, including SHA-256, Code Signing EKU, and RFC 3161 timestamp checks.
- `portcve.exe --version` and a no-firewall snapshot smoke test passed after signing and after download.
- Every file in `SHA256SUMS.txt` matched, the installer rejected a tampered ZIP/executable, and GitHub provenance verification passed.
- The ZIP contains the same signed executable hash recorded in `SIGNING-METADATA.json`.
- Release notes, license, security policy, schema files, and vulnerability-data limitations are accurate for 1.0.
- Defender/SmartScreen behavior was observed on a clean Windows machine and described honestly, without promising reputation or warning-free execution.

Record the test tag, release URL, workflow run ID, executable SHA-256, signer subject, and verification machine details in the release evidence. Never record the four eSigner secrets or authentication logs.

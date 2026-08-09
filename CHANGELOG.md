# Changelog

All notable changes will be documented here. The project follows semantic versioning after `1.0`; alpha schemas may still change with an explicit version bump.

## Unreleased

- Renamed the project, executable, namespaces, schemas, scripts, and release artifacts from BindWitness (`bindwitness`) to PortCVE (`portcve`); no behavior changed as part of the rename.
- Added `scan` for offline known-advisory matching against immutable local Docker image IDs and explicit local SBOMs, with a versioned JSON schema, redaction, database-freshness evidence, and `--strict`/`--fail-on` exit gates.
- Hardened the Trivy boundary with local non-reparse cache/SBOM/temp validation, inherited environment scrubbing, strict result parsing, bounded process termination, and guarded cleanup.
- Added a file-backed, self-verifying PowerShell installer template and a fail-closed release workflow that signs and independently verifies both `portcve.exe` and `install.ps1`.
- Added cryptographic RFC 3161 token decoding, signer-info imprint binding, trusted TSA matching, full-SHA GitHub Actions pinning, release checksums, metadata, and provenance attestation.
- Live-validated Docker TCP/UDP correlation and the offline vulnerability path; see `docs/validation.md` for dated evidence and claim boundaries.

## 0.1.0-alpha.1 - 2026-08-09

- Native Windows TCP/UDP endpoint collection with IPv4 and IPv6 ownership
- Process, parent, account, and Windows service attribution
- Local Docker Engine named-pipe collection with conservative, unique-best-match published-port correlation and partial evidence on ambiguous/unmatched mappings
- Reproducible Docker Desktop 28.3.2 TCP/UDP echo, CIM tuple, redaction, container-lock, unchanged-check, and owner-replacement drift validation
- Bind-scope and active-interface classification
- Effective Windows Firewall evidence with explicit confidence and limitations
- Human-readable, JSON, and JSONL output
- Deterministic, privacy-reduced listener lockfiles with explicit owner, policy, and container evidence completeness, including normalized container image-set identity
- Default JSON redaction for container IDs, names, images, image IDs, host addresses, and free-form correlation details
- Multiset-aware listener and evidence-dimension diff, CI check, watch, snapshot, and doctor workflows
- Initial schemas, tests, documentation, deterministic dependency locks, CI, and release packaging

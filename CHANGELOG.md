# Changelog

All notable changes will be documented here. The project follows semantic versioning after `1.0`; alpha schemas may still change with an explicit version bump.

## Unreleased

- Renamed the project, executable, namespaces, schemas, scripts, and release artifacts from BindWitness (`bindwitness`) to PortCVE (`portcve`); no behavior changed as part of the rename.
- Added `scan` for offline known-advisory matching against immutable local Docker image IDs and explicit local SBOMs, with a versioned JSON schema, redaction, database-freshness evidence, and `--strict`/`--fail-on` exit gates.
- Added explicit `db status` and `db update` commands for an externally installed, locally validated Trivy executable; scans remain offline and never install or update the engine or advisory database implicitly.
- Hardened the Trivy boundary with local non-reparse cache/SBOM/temp validation, inherited environment scrubbing, strict result parsing, bounded process termination, and guarded cleanup.
- Added `scan-host` for explicitly authorized, rate-limited TCP host/CIDR discovery, protocol-bound greeting/HTTP/TLS fingerprinting, privacy-reduced remote JSON, and bounded safe-active HTTP/TLS posture checks.
- Added exact catalog-backed banner identities for Dropbear SSH, ProFTPD, vsftpd, and Exim, while retaining unresolved results for headers, ports, ambiguous banners, and unsupported versions.
- Added explicit-online, catalog-backed NVD correlation with provenance-bound identities, preserved applicability conditions and enrichment status, candidate-only wording, and process-wide rate limiting.
- Added import-only Nmap XML and Nuclei JSONL normalization with local non-reparse inputs, bounded parsers, source hashing, versioned JSON, and no scanner/template execution.
- Added a file-backed, self-verifying PowerShell installer template and a fail-closed release workflow that signs and independently verifies both `portcve.exe` and `install.ps1`.
- Added receipt-bound managed update, exact-version rollback, offline uninstall, guarded user-`PATH` changes, and transactional restoration tests; portable release ZIPs remain side-effect free.
- Added cryptographic RFC 3161 token decoding, signer-info imprint binding, trusted TSA matching, full-SHA GitHub Actions pinning, release checksums, metadata, and provenance attestation.
- Expanded CI to fresh Windows Server 2022 and 2025 runners with live loopback remote-assessment and enforceable performance budgets, plus local socket-churn and Docker-forwarding validation.
- Live-validated Docker TCP/UDP correlation, the offline vulnerability path, and authorized adaptive HTTP discovery on a random loopback port; see `docs/validation.md` and `docs/remote-live-validation.md` for the dated results and limits.

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

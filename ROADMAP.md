# Roadmap

Correctness comes before more platforms or a GUI.

## Before 1.0

- Windows 10 compatibility validation and broader supported Windows 11 builds
- Broader Docker Desktop version, permission, absent-Engine, and published-port coverage beyond the validated 28.3.2 TCP/UDP fixture
- Standard-user and administrator comparison tests
- Disposable-VM firewall rule matrix
- A public-trust Authenticode release after publisher identity validation and protected signing credentials are configured

## Workload attribution

- Best-effort WSL correlation without starting stopped distributions
- Kubernetes workload attribution with an explicit context and consent boundary
- Binary hashing as an explicit opt-in baseline field
- Better protected-service owner-module enrichment when elevated

## Remote assessment

- More protocol negotiation without authentication: SMB, RDP, database greetings, SMTP STARTTLS, and curated UDP probes with honest `open|filtered` semantics
- Targets/exclusions files, engagement manifests, resumable/sharded scans, JSONL streaming, and remote baseline/diff
- Nuclei target export and a carefully allowlisted external runner that never enables code, headless, fuzz, brute-force, or denial-of-service templates
- Persistent NVD cache/delta updates and CISA KEV enrichment with source freshness
- More certificate, HTTP-header, cookie, SSH-algorithm, and TLS-posture observations without turning configuration absence into exploit claims

## Policy and output

- Source-IP-aware firewall explanation
- SARIF output for CI findings
- Policy configuration beyond a single listener lockfile
- Optional external verifier with a separate trust and consent model

## Later

- Linux collector backend using native socket/process and nftables evidence
- Event-driven collectors where the platform offers reliable ownership events
- CycloneDX SBOM generation for release artifacts

## Explicitly not planned for v1

- Packet capture
- Process killing
- Automatic firewall modification
- Cloud dashboards or telemetry
- Generic risk scoring
- Exploit execution, credential attacks, brute force, fuzzing, denial of service, stealth/evasion, or arbitrary remote template/code execution

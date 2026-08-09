# Roadmap

The order matters: correctness and evidence quality come before more platforms or a GUI.

## 0.1 stabilization

- Golden JSON and lockfile compatibility fixtures, including container publications and image-set identity
- More Windows 10, Windows 11, and Server integration coverage
- Broader Docker Desktop version, permission, absent-Engine, and published-port integration coverage beyond the validated 28.3.2 TCP/UDP fixture
- Standard-user and administrator comparison tests
- Disposable-VM firewall rule matrix
- Socket/process churn soak tests and performance budgets
- Signed Windows releases when signing infrastructure is available

## 0.2 guest and workload attribution

- Best-effort WSL correlation without starting stopped distributions
- Kubernetes workload attribution with an explicit context and consent boundary
- Binary hashing as an explicit opt-in baseline field
- Better protected-service owner-module enrichment when elevated

## 0.3 remote assessment hardening

- More protocol negotiation without authentication: SMB, RDP, database greetings, SMTP STARTTLS, and curated UDP probes with honest `open|filtered` semantics
- Targets/exclusions files, engagement manifests, resumable/sharded scans, JSONL streaming, and remote baseline/diff
- Nuclei target export and a carefully allowlisted external runner that never enables code, headless, fuzz, brute-force, or denial-of-service templates
- Persistent NVD cache/delta updates and CISA KEV enrichment with source freshness
- More certificate, HTTP-header, cookie, SSH-algorithm, and TLS-posture observations without turning configuration absence into exploit claims

## 0.4 policy workflows

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
- AI-generated risk scores
- Exploit execution, credential attacks, brute force, fuzzing, denial of service, stealth/evasion, or arbitrary remote template/code execution

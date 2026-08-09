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

## 0.3 policy workflows

- Source-IP-aware firewall explanation
- SARIF output for CI findings
- Policy configuration beyond a single listener lockfile
- Optional external verifier with a separate trust and consent model

## Later

- Linux collector backend using native socket/process and nftables evidence
- Event-driven collectors where the platform offers reliable ownership events
- CycloneDX SBOM generation for release artifacts

## Explicitly not planned for v1

- Remote network scanning
- Packet capture
- Process killing
- Automatic firewall modification
- Cloud dashboards or telemetry
- AI-generated risk scores

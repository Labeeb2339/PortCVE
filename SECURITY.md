# Security policy

## Supported versions

PortCVE is currently alpha software and has no finalized signed PortCVE release yet. The historical unsigned `v0.1.0-alpha.1` BindWitness-era artifact is not a supported daily-use distribution. Once signed PortCVE releases begin, only the latest release line will receive security fixes unless a release note says otherwise.

## Report a vulnerability

Please use the repository's private **Security > Advisories > New draft security advisory** flow. Do not open a public issue for a vulnerability that could expose users or their local machine data.

Include the affected version, Windows version, privilege level, reproduction steps, impact, and the smallest safe proof of concept. Redact usernames, hostnames, internal addresses, tokens, proprietary rule names, and unrelated local process data.

## Security boundaries

PortCVE parses local OS, container, scanner-import, package, and network observations that may be partial or change while they are being read. Its output is evidence, not an authorization decision, exploitability proof, or general guarantee of network reachability.

The current development line:

- does not close ports, kill processes, change firewall policy, install security updates, exploit services, submit credentials, brute-force, fuzz, or perform denial-of-service checks;
- requires an explicit `--authorized` assertion before `scan-host` makes bounded TCP, greeting, HTTP, or TLS identification connections;
- permits third-party network access only through explicit commands/options: `db update` downloads Trivy advisory data, and `scan-host --online-advisories` sends only a reviewed catalog-backed CPE to the NVD API;
- does not send target addresses, hostnames, banners, credentials, or process inventory to NVD;
- disables Trivy telemetry/version checks and keeps local vulnerability scans offline;
- does not read process environment variables or command lines;
- invokes Windows PowerShell only with bundled constant scripts and no user-controlled script interpolation; and
- may return partial metadata for protected or rapidly exiting processes, inconclusive network states, unresolved software identities, or provider evidence that cannot be safely matched.

Do not run a binary from an untrusted source merely to inspect it. PortCVE inspects running local endpoints; it is not a malware sandbox.

Remote connections are observable and can create application, firewall, IDS, or rate-limit logs. Only assess systems within a scope you are authorized to test. Import files and JSON reports can still contain sensitive assessment metadata after default reduction; review them before sharing.

# PortCVE

[![CI](https://github.com/Labeeb2339/PortCVE/actions/workflows/ci.yml/badge.svg)](https://github.com/Labeeb2339/PortCVE/actions/workflows/ci.yml)
[![CodeQL](https://github.com/Labeeb2339/PortCVE/actions/workflows/codeql.yml/badge.svg)](https://github.com/Labeeb2339/PortCVE/actions/workflows/codeql.yml)

PortCVE is a Windows CLI for answering four practical questions:

1. What is listening?
2. Which process, service, or container owns it?
3. Has the local attack surface changed?
4. Do identified packages or authorized remote service fingerprints match known CVEs?

The current version is `0.2.0-alpha.1`. Windows x64 is the only supported target. There is no signed PortCVE release yet, so current users must build from source.

## Features

- Lists native IPv4/IPv6 TCP listeners and UDP endpoints.
- Maps binds to processes, Windows services, interfaces, network profiles, and static Windows Firewall rules.
- Correlates Docker published ports with observed host binds.
- Creates reviewable listener baselines and fails CI when exposure widens or ownership changes.
- Uses a local Trivy database to check exact Docker images or an explicitly supplied SBOM.
- Fingerprints TCP services on hosts or IPv4 CIDRs you are authorized to assess.
- Maps a small reviewed set of strong service banners to NVD CVE candidates.
- Imports existing Nmap XML and Nuclei JSONL without launching either scanner.
- Emits text, versioned JSON, JSONL, and stable exit codes for automation.

PortCVE is not an exploit framework. It does not brute-force credentials, send exploit payloads, close ports, edit firewall rules, or claim that a CVE match is exploitable.

## Build from source

Install the [.NET 10 SDK](https://dotnet.microsoft.com/download/dotnet/10.0), then run:

```powershell
git clone https://github.com/Labeeb2339/PortCVE.git
cd PortCVE
dotnet restore PortCVE.sln --locked-mode
dotnet test PortCVE.sln -c Release --no-restore
dotnet publish src\PortCVE\PortCVE.csproj `
    -c Release -r win-x64 --self-contained true --no-restore `
    -o artifacts\win-x64
```

Start with:

```powershell
.\artifacts\win-x64\portcve.exe version
.\artifacts\win-x64\portcve.exe doctor
.\artifacts\win-x64\portcve.exe list
```

Administrator rights are not required for basic inventory. Protected processes and some firewall or owner details may remain unavailable; `doctor` reports those gaps.

## Common workflows

### Inspect local listeners

```powershell
portcve list
portcve list --scope non-loopback
portcve tcp:8080 --evidence
```

Firewall conclusions describe the Windows policy PortCVE could read. They do not prove LAN or Internet reachability.

### Track drift

Create a baseline after reviewing the machine as known-good:

```powershell
portcve lock -o listeners.lock.json
portcve diff listeners.lock.json
portcve check listeners.lock.json --strict
```

`check` fails on new listeners, owner changes, wider binds, or more-permissive host-policy results. Incomplete evidence returns exit code `3` rather than a clean pass.

### Check known advisories

PortCVE uses Trivy as an optional external scanner. Install Trivy separately, verify its published checksum, set `PORTCVE_TRIVY_PATH`, and initialize a dedicated local cache:

```powershell
portcve db update
portcve db status
portcve scan tcp:8080 --strict
portcve scan --all --fail-on high
```

For an explicit CycloneDX or SPDX SBOM:

```powershell
portcve scan tcp:8080 --sbom .\app.cdx.json --strict
```

Local scans do not update the database, pull images, or upload package data. Setup details are in [docs/daily-use.md](docs/daily-use.md).

### Assess an authorized host

Remote scanning only runs when you pass `--authorized`:

```powershell
portcve scan-host 10.20.30.40 --ports 22,80,443 --authorized
portcve scan-host 10.20.30.40 --ports 22,80,443 --authorized --active
```

Online NVD enrichment is separate and opt-in:

```powershell
portcve scan-host 10.20.30.40 --ports 22,443 `
    --authorized --online-advisories --strict --fail-on high
```

`--authorized` records the operator's assertion; PortCVE cannot verify permission. Connections and probes can appear in server, firewall, IDS, and rate-limit logs.

### Reuse scanner output

```powershell
portcve import nmap .\scan.xml -o .\scan.portcve.json --strict
portcve import nuclei .\findings.jsonl -o .\findings.portcve.json --strict
```

The importers are streaming and size-limited. They remove raw response and extracted-value fields, but the normalized report can still contain sensitive assessment metadata.

## Output and privacy

Default JSON is privacy-reduced, not anonymous. It removes or aliases PIDs, local paths, interface addresses, account details, container identifiers, and free-form diagnostic text where the command supports reduction. Ports, process or service names, package versions, CVE identifiers, and policy results may remain.

Use `--include-private` only for reports that stay in a controlled location:

```powershell
portcve snapshot --json -o host.portcve.json
portcve snapshot --json --include-private -o host.private.portcve.json
```

Review every report before sharing it.

Versioned schemas live in [`schema/`](schema/):

- [snapshot](schema/portcve.snapshot.v1.schema.json)
- [listener lockfile](schema/portcve.lock.v1.schema.json)
- [Trivy database status](schema/portcve.database.v1.schema.json)
- [local vulnerability report](schema/portcve.vulnerability.v1.schema.json)
- [remote assessment](schema/portcve.remote.v1.schema.json)
- [external evidence import](schema/portcve.import.v1.schema.json)

## Install and release status

The checked-in `scripts/install.ps1` is a release template, not a bootstrap installer. It refuses to run until the release workflow has finalized and signed it.

When signed releases become available, the installer will verify its own Authenticode signature, the release checksum, and the signed executable before changing the per-user installation. It supports update, exact-version rollback, and uninstall. See [docs/install.md](docs/install.md).

PortCVE intentionally does not support `irm ... | iex`. Piped script text starts executing before a downloaded file can be inspected and Authenticode-verified.

## Limits

- Alpha CLI and schemas may change before `1.0`.
- Windows x64 only; no Linux host or WSL guest-process attribution yet.
- Native Windows software is not assigned a CPE from a filename or port guess.
- Remote CVE results are candidates based on observed banner data, not proof of applicability or exploitability.
- Windows Firewall analysis is static configuration review, not live packet-path testing.
- Dynamic collection can miss short-lived endpoints or lose metadata during process churn.
The full security model is in [docs/threat-model.md](docs/threat-model.md), and implementation details are in [docs/architecture.md](docs/architecture.md).

## Validation

CI runs the test suite on Windows Server 2022 and 2025, builds the self-contained executable, checks formatting, exercises the installer and RFC 3161 verification harnesses, runs an authorized loopback scan, checks performance budgets, and performs CodeQL analysis.

Live Docker, Trivy, corruption-handling, privacy, remote-loopback, and performance results are recorded in [docs/validation.md](docs/validation.md) and [docs/remote-live-validation.md](docs/remote-live-validation.md).

## Development

```powershell
dotnet restore PortCVE.sln --locked-mode
dotnet format PortCVE.sln --verify-no-changes --no-restore
dotnet build PortCVE.sln -c Release --no-restore
dotnet test PortCVE.sln -c Release --no-build --no-restore
```

See [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request. Report security issues privately as described in [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)

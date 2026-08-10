# Daily use

PortCVE is designed for three repeatable jobs on Windows: explain what is bound locally, detect exposure drift, and collect bounded vulnerability evidence for exact local artifacts or explicitly authorized remote services.

It is non-destructive and does not change local security state. It does not close ports, change firewall rules, install updates, exploit services, brute-force credentials, or make a remote target safe to test. `scan-host` does make observable network connections and safe identification requests; use it only for systems you are authorized to assess.

## Set up once

1. Install a finalized signed release using the file-backed PowerShell procedure in [install.md](install.md), or use its portable ZIP in a controlled engagement directory.
2. Open a new terminal and verify the installation:

   ```powershell
   portcve version
   portcve doctor
   ```

   Review any partial collector evidence. Protected Windows processes can legitimately hide some owner metadata from a standard-user session; use `portcve doctor --strict` when an automated workflow must reject any incomplete core evidence.

3. If Docker or SBOM vulnerability checks are needed, install a trusted Windows x64 Trivy release from the official Aqua Security release page and verify its published checksum. PortCVE does not silently install or update Trivy. Point PortCVE at the verified executable and a dedicated local cache:

   ```powershell
   [Environment]::SetEnvironmentVariable(
       'PORTCVE_TRIVY_PATH',
       'C:\Tools\trivy\trivy.exe',
       'User')
   [Environment]::SetEnvironmentVariable(
       'PORTCVE_TRIVY_CACHE_DIR',
       "$env:LOCALAPPDATA\PortCVE\trivy-cache",
       'User')
   ```

4. Open another terminal, explicitly fetch the advisory database, then verify readiness without network access:

   ```powershell
   portcve db update
   portcve db status --json
   ```

`scan`, local inventory, baselines, and `db status` never update the database implicitly. Repeat `db update` when `db status` reports stale evidence.

## Five-minute host review

Start with a fast inventory, then inspect only the endpoints that need explanation:

```powershell
portcve list
portcve list --scope non-loopback
portcve tcp:8080 --evidence
```

The first command answers what is bound. The scoped list highlights interface and wildcard binds. Exact inspection adds process, service, bind scope, interface, and static Windows Firewall evidence where it is available. A wildcard bind or static allow rule is not proof of Internet reachability.

Use private JSON only when the output will remain controlled:

```powershell
portcve snapshot --json -o .\host.portcve.json
portcve snapshot --json --include-private -o .\host.private.portcve.json
```

Default JSON is privacy-reduced, not anonymous. Review every report before sharing it.

## Baseline and drift

Create a baseline only after reviewing the current machine as known-good:

```powershell
portcve lock -o .\listeners.lock.json
```

Review drift manually:

```powershell
portcve diff .\listeners.lock.json
```

Use the same file as a CI or workstation gate:

```powershell
portcve check .\listeners.lock.json --strict
if ($LASTEXITCODE -ne 0) { throw "PortCVE check failed with exit $LASTEXITCODE" }
```

Commit a reviewed privacy-reduced lockfile when it belongs to a repository policy. Do not create a baseline with `--allow-incomplete` and then treat it as a passing security control. Include UDP only when its extra churn is operationally useful.

For interactive change observation:

```powershell
portcve watch --json --interval 1s
```

## Known-advisory checks for local listeners

Docker-published listeners can be mapped to immutable local image IDs and scanned against the local Trivy database without pulling an image:

```powershell
portcve db status
portcve scan tcp:8080 --strict
portcve scan --all --fail-on high
```

An explicit local CycloneDX or SPDX SBOM can be associated with one selected listener:

```powershell
portcve scan tcp:8080 --sbom .\app.cdx.json --strict
```

Results mean a known advisory matched an observed package identity. They do not prove the listening service is reachable, affected in its runtime configuration, or exploitable. Native Windows binaries are left unresolved unless exact supported evidence exists; PortCVE does not invent a product or CPE from a filename.

## Authorized remote assessment

Keep the target and port scope explicit. Begin passive, then use `--active` only when the safe probe set is appropriate for the engagement:

```powershell
portcve scan-host 10.20.30.40 --ports 22,80,443 --authorized -o .\host.remote.json
portcve scan-host 10.20.30.40 --ports 22,80,443 --authorized --active -o .\host.active.json
```

For reviewed strong banner identities, online NVD enrichment must be explicitly enabled:

```powershell
portcve scan-host 10.20.30.40 --ports 22,443 `
    --authorized --online-advisories --strict --fail-on high `
    -o .\host.advisories.json
```

`--authorized` records the operator's assertion; PortCVE cannot verify authority. Connections and safe probes can appear in server, firewall, IDS, and rate-limit logs. Online enrichment sends only a reviewed catalog-backed CPE to NVD, not the target address, hostname, banner, or credentials. Findings remain candidates with exploitability not assessed.

For larger approved scopes, split work into bounded runs. PortCVE intentionally has host, endpoint, concurrency, rate, timeout, evidence, and advisory-identity caps instead of an unlimited mode.

## Reuse Nmap and Nuclei evidence

PortCVE can normalize existing local outputs without launching those tools or contacting their targets:

```powershell
portcve import nmap .\scan.xml -o .\scan.portcve.json --strict
portcve import nuclei .\findings.jsonl -o .\findings.portcve.json --strict
```

The importers are bounded and discard sensitive raw request, response, script-output, and extracted-value fields. Normalized output still contains assessment metadata and must be reviewed before publication.

## Exit codes for automation

Treat exit codes as part of the command contract:

| Code | Meaning |
| ---: | --- |
| `0` | The requested operation completed and its configured gate passed. |
| `1` | No exact endpoint matched, drift failed, or the configured finding threshold matched. |
| `2` | Usage, schema, input, or overwrite policy was invalid. |
| `3` | Required evidence was incomplete; do not treat this as a clean result. |
| `4` | A required collector or runtime operation failed. |
| `130` | The operation was interrupted. |

Use `--strict` for automation. A finding gate such as `--fail-on high` also fails closed when the evidence needed to evaluate that gate is incomplete.

## Update, rollback, and uninstall

The managed install keeps a verified signed installer copy. Run it to update to the latest stable release, or provide an exact signed tag to roll back:

```powershell
powershell.exe -NoProfile -ExecutionPolicy AllSigned `
    -File "$env:LOCALAPPDATA\Programs\PortCVE\install.ps1"

powershell.exe -NoProfile -ExecutionPolicy AllSigned `
    -File "$env:LOCALAPPDATA\Programs\PortCVE\install.ps1" `
    -Version v1.0.0
```

Uninstall is local and removes only a receipt-bound managed installation and its exact user `PATH` entry:

```powershell
powershell.exe -NoProfile -ExecutionPolicy AllSigned `
    -File "$env:LOCALAPPDATA\Programs\PortCVE\install.ps1" `
    -Uninstall
```

See [install.md](install.md) for signature, checksum, rollback, custom-directory, and portable-ZIP details. See [cli.md](cli.md) for the complete command, JSON, and exit-code reference.

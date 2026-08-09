# CLI reference

PortCVE is read-only. Commands observe local Windows state, write JSON or a lockfile when requested, and never kill a process, close a socket, edit firewall policy, or probe a remote host.

## Commands

```text
portcve                              List all collected TCP listeners and UDP binds
portcve <port>                       Inspect TCP and UDP binds on a port
portcve <tcp|udp>:<port>             Inspect one protocol on a port
portcve list                         List and filter current endpoints
portcve snapshot [--output <path>]   Emit a versioned snapshot
portcve lock [--output <path>]       Write a normalized baseline
portcve diff <lockfile>              Show current drift from a baseline
portcve check <lockfile>             Gate security-relevant drift
portcve scan <tcp:port>              Check exact subjects for one TCP listener
portcve scan --all                   Check exact Docker image IDs for all TCP listeners
portcve watch                        Poll and report endpoint changes
portcve doctor                       Report collector coverage
portcve help                         Show the concise built-in reference
portcve version                      Print the tool version
```

Direct inspection and `doctor` collect Windows Firewall evidence unless `--no-firewall` is supplied. `list`, `snapshot`, `lock`, and `watch` skip that slower collector unless `--firewall` is supplied.

Every live collection also performs a bounded probe of the local Docker Engine named pipe (`\\.\pipe\docker_engine`). When Docker is running, PortCVE reads running-container published ports and correlates them to observed Windows endpoints by protocol, host address, and host port. The result is medium-confidence runtime correlation, not direct guest-process ownership. An absent pipe is recorded as `docker: unavailable` and returns quickly without starting Docker Desktop, pulling an image, or starting a container. There is no Docker enablement flag.

## Offline vulnerability scans

`scan` maps selected TCP listeners only to immutable Docker `sha256:` image IDs. Native Windows process names and paths are not guessed into products or CPEs. For one exact TCP port, `--sbom <path>` adds an explicitly declared local SBOM subject; it cannot be combined with `--all`.

The scanner launches a separately installed Trivy executable without a shell, selects the local Docker daemon only, and supplies update, telemetry, version-check, VEX-update, and online dependency-resolution disable flags. It never downloads Trivy or a database. Set `PORTCVE_TRIVY_PATH` for a non-default executable and `PORTCVE_TRIVY_CACHE_DIR` for a non-default cache. The expected database metadata is `<cache>\db\metadata.json`; a missing or invalid database makes the subject unavailable, while a database older than 72 hours makes evidence partial.

| Option | Behavior |
| --- | --- |
| `--all` | Select every observed TCP listener and deduplicate exact Docker subjects by immutable image ID. |
| `--sbom <path>` | Add one explicit SBOM subject to an exact-port scan. The file is hashed before and after scanning; changed input findings are discarded. |
| `--fail-on high` | Exit `1` for a high or critical known-advisory match. |
| `--fail-on critical` | Exit `1` for a critical known-advisory match. |
| `--strict` | Exit `3` if any selected subject is unsupported, unavailable, failed, or partial. |

Human output and vulnerability JSON say `known_advisory_match`: they do not claim the package is reachable or exploitable. JSON uses `schema/portcve.vulnerability.v1.schema.json` and is redacted unless `--include-private` is supplied. If Trivy cannot run or no subject produces scan evidence, `scan` exits `3`; a selector with no matching TCP listener exits `1`.

## Filters and collection

| Option | Behavior |
| --- | --- |
| `-p, --port <1-65535>` | Filter by local port. |
| `--proto, --protocol <tcp\|udp>` | Filter by transport protocol. |
| `--scope <loopback\|interface\|wildcard\|non-loopback>` | Filter by classified bind scope. |
| `--process <name>` | Filter by process image or attributed service name. Lockfiles currently reject process selectors. |
| `--firewall` | Collect network profiles and perform a static assessment of merged Windows Firewall `ActiveStore` configuration. It does not observe live WFP packet classification. |
| `--no-firewall` | Skip host-policy collection, including for commands that enable it by default. |
| `--evidence` | Enable firewall collection and show supporting evidence in human-readable inspection. |
| `--resolve-accounts` | Resolve token SIDs to account names. Windows may contact a domain controller or global catalog; this is the only current opt-in that can cause a network account lookup. |
| `--strict`, `--require-complete` | Return exit code `3` when required core collection evidence is incomplete. An absent optional Docker Engine does not fail general strict mode; container-aware lockfiles have a separate completeness gate. `check` already refuses to pass on incomplete baseline/current evidence. |

`diff` and `check` use the selector and UDP choice stored in the lockfile. They do not accept new port, protocol, process, or scope filters.

## Baselines

| Option | Behavior |
| --- | --- |
| `--include-udp` | Include UDP in `lock` and `watch`. TCP-only is the default because connectionless, duplicate, and short-lived UDP binds can create noisy baseline churn. A protocol-specific UDP lock also records `includes_udp: true`. |
| `--allow-incomplete` | Permit `lock` to write a baseline with incomplete ownership, bind-scope, requested host-policy, or requested container evidence. Such a file is useful for manual diffing but cannot make `check` pass while evidence remains incomplete. |
| `-o, --output <path>` | Write a lockfile or snapshot to a path. The default lockfile is `listeners.lock.json`. |
| `--force` | Replace an existing lockfile or snapshot instead of failing with exit code `2`. |

Lockfiles omit PIDs, timestamps, command lines, environment variables, account names, full paths, container IDs, container names, and raw image references. They store normalized owner identity strength, host-policy confidence, evidence-completeness metadata, the selector, and whether UDP was included.

`evidence.containers` is `complete` when the Docker Engine answered successfully, including when it reported no running published ports. A normally absent Docker pipe is `not_collected`, so non-Docker hosts do not need `--allow-incomplete`. Access denial, timeout, malformed response, or collector failure is `partial` for a container-aware capture. Correlated endpoints use `container_image` owner strength and a deterministic `container-image-set:<sha256>` identity when every correlated publication supplies an image ID; otherwise owner identity falls back to the observed host process/service rules. `diff` and `check` recollect Docker evidence when the baseline's container evidence was collected.

An Engine publication that cannot be matched to a Windows endpoint is reported as a diagnostic, makes Docker evidence `partial`, and is not added to the lockfile as a synthetic listener. A later loss of an evidence dimension required by the baseline appears in `diff` as `evidence_regressed`; `diff --strict` and `check` return exit code `3`.

## JSON and privacy

| Option | Behavior |
| --- | --- |
| `--json`, `--format json` | Emit versioned JSON. `watch --json` emits one compact JSON object per line. |
| `--format jsonl` | Select machine-readable output; JSONL is meaningful for streaming `watch`. |
| `--format table`, `--format text` | Select human-readable output. |
| `--include-private` | Disable default JSON/snapshot redaction and include collected local addresses, interface details, owner paths/identity, container IDs/names/image references, firewall-rule details, and raw evidence/diagnostics. It never enables command-line or environment-variable collection. |

Default JSON is redacted and privacy-reduced, not anonymous. It replaces owner PIDs with `0` and removes creation time. For Docker correlations it replaces container IDs, names, and image references, omits image IDs, and normalizes host addresses; the existence of a mapping, host/container ports, protocol, runtime, and medium confidence remain visible. The output also contains bind scopes, process/service names, profile labels, policy verdicts, and collection metadata. Review it before publishing. Human-readable inspection is intended for local use and can show private host and container details.

## Watch

| Option | Behavior |
| --- | --- |
| `--interval <duration>` | Polling interval such as `500ms`, `2s`, or `1m`; values below 250 ms are rejected. |
| `--iterations <count>` | Stop after a positive number of completed polling iterations. |

Watch is TCP-only unless `--include-udp` or a UDP protocol filter is supplied. If the previous sample contained a correlated container publication, Docker becomes required evidence for that comparison. If required evidence degrades, watch reports the degradation and does not advance its comparison baseline from that sample.

## Exit codes

| Code | Meaning |
| ---: | --- |
| `0` | Success, matching inspection, or passing check. An empty unfiltered list is still successful. |
| `1` | No matching inspected endpoint or a failed security drift check. |
| `2` | Invalid usage, schema, lockfile, or non-overwrite request. |
| `3` | Evidence is incomplete for the requested strict or gating operation, or no vulnerability subject could be scanned. |
| `4` | Required collection or runtime operation failed. |
| `130` | Interrupted. |

Diagnostics are written to stderr so JSON stdout remains parseable.

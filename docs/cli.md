# CLI reference

PortCVE never changes local firewall/process state and never exploits a remote service. Local commands are offline except for explicitly documented account resolution and the explicit `db update` command. `scan-host` performs authorized, rate-limited TCP connections and safe identification probes only when the operator supplies `--authorized`.

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
portcve scan --all                   Check all mapped Docker image IDs
portcve db status                    Inspect local Trivy and database freshness offline
portcve db update                    Explicitly download and validate the Trivy database
portcve scan-host <target> --authorized  Scan an authorized host or IPv4 CIDR
portcve import nmap <scan.xml>       Normalize an existing Nmap XML file
portcve import nuclei <results.jsonl> Normalize existing Nuclei JSONL findings
portcve import nessus <report.nessus> Normalize an existing Nessus report
portcve verify <scan.xml> --target <host> Correlate scanner evidence with this Windows host
portcve watch                        Poll and report endpoint changes
portcve doctor                       Report collector coverage
portcve help                         Show the concise built-in reference
portcve version                      Print the tool version
```

Direct inspection and `doctor` collect Windows Firewall evidence unless `--no-firewall` is supplied. `list`, `snapshot`, `lock`, and `watch` skip that slower collector unless `--firewall` is supplied.

Every live collection also performs a bounded probe of the local Docker Engine named pipe (`\\.\pipe\docker_engine`). When Docker is running, PortCVE reads running-container published ports and correlates them to observed Windows endpoints by protocol, host address, and host port. The result is medium-confidence runtime correlation, not direct guest-process ownership. An absent pipe is recorded as `docker: unavailable` and returns quickly without starting Docker Desktop, pulling an image, or starting a container. There is no Docker enablement flag.

## Offline vulnerability scans

`scan` maps selected TCP listeners only to immutable Docker `sha256:` image IDs. Native Windows process names and paths are not guessed into products or CPEs. For one exact TCP port, `--sbom <path>` adds an explicitly declared local SBOM subject; it cannot be combined with `--all`.

The scanner launches a separately installed Trivy executable without a shell, selects the local Docker daemon only, and supplies update, telemetry, version-check, VEX-update, and online dependency-resolution disable flags. A `scan` never downloads Trivy or a database. Set `PORTCVE_TRIVY_PATH` to the absolute path of a trusted local non-default executable and `PORTCVE_TRIVY_CACHE_DIR` for a non-default cache. The executable and cache must be on an allowed local drive without reparse traversal. The expected database metadata is `<cache>\db\metadata.json`; a missing or invalid database makes the subject unavailable, while a database older than 72 hours makes evidence partial.

| Option | Behavior |
| --- | --- |
| `--all` | Inspect every observed TCP listener, then scan each distinct immutable Docker image ID that can be mapped. Unrelated native listeners are not guessed into subjects. No eligible image returns exit `3`. |
| `--sbom <path>` | Add one explicit SBOM subject to an exact-port scan. UNC paths, mapped network drives, and paths traversing reparse points are rejected before collection. The file is hashed before and after scanning; changed input findings are discarded and cannot produce a successful scan. |
| `--fail-on high` | Exit `1` for a high or critical known-advisory match. |
| `--fail-on critical` | Exit `1` for a critical known-advisory match. |
| `--strict` | Exit `3` if any selected subject is unsupported, unavailable, failed, or partial. |

Human output and vulnerability JSON say `known_advisory_match`: they do not claim the package is reachable or exploitable. JSON uses `schema/portcve.vulnerability.v1.schema.json` and is redacted unless `--include-private` is supplied. If Trivy cannot run or no subject produces scan evidence, `scan` exits `3`; a selector with no matching TCP listener exits `1`.

`--fail-on` is a security gate, not a best-effort filter. It returns `3` instead of passing when the vulnerability database or selected scan evidence is incomplete, even without a separate `--strict` flag.

### Trivy database lifecycle

PortCVE never updates vulnerability data implicitly. Database maintenance is split into two explicit commands:

```powershell
portcve db status
portcve db status --json
portcve db update
```

Trivy is an optional external dependency; PortCVE neither bundles nor installs it. For first-time setup, download the Windows x64 archive and its checksum file from the [official Trivy GitHub release](https://github.com/aquasecurity/trivy/releases), verify the archive's SHA-256 before extracting it to a protected local directory, set `PORTCVE_TRIVY_PATH` to the absolute `trivy.exe` path, and optionally set `PORTCVE_TRIVY_CACHE_DIR` to a protected local cache. Then run `portcve db update` followed by `portcve db status`. PortCVE does not use Winget/Scoop, a piped `irm | iex` installer, or an automatic download hidden inside `scan`.

`db status` performs no network request. It resolves Trivy to a validated local `.exe`, runs a bounded offline `--version` check, and verifies the configured cache, database metadata schema, `trivy.db` file, update time, next-update time, and 72-hour freshness limit. Before reporting ready, it also makes Trivy open that database in a bounded offline vulnerability scan of a newly created empty private directory. This validation scans no user files, executes no target code, disables every update path, and rejects a corrupt/truncated database even when its metadata is fresh. Human output reports the executable path, Trivy version, cache directory, database schema version, timestamps, age, and a stable result code. JSON follows `schema/portcve.database.v1.schema.json` with `schema_version: 1` and `tool_version`. By default its `privacy_mode` is `reduced`, `executable_path` is `local-trivy-executable`, and `cache_directory` is `local-trivy-cache`; `--json --include-private` emits the exact validated paths with `privacy_mode: private`. A missing, stale, future-dated, malformed, unreadable, unsafe, or unavailable database returns exit code `3` instead of reporting readiness.

`db update` is the only local vulnerability workflow that permits a database download. It invokes the validated Trivy executable directly without a shell and runs `trivy image --download-db-only` against the configured cache. The operation has a ten-minute timeout, bounded stdout/stderr, no progress output, a private per-invocation temporary directory, and post-update path, metadata, database-file, schema, and freshness validation. Trivy configuration, registry/cloud credentials, Docker endpoints, telemetry, version checks, proxy variables, and alternate-update environment variables are removed from the child environment; neither child output nor environment values are copied into PortCVE diagnostics. The command uses Trivy's built-in public database source and may require a direct outbound HTTPS path because ambient proxy configuration is intentionally not inherited. PortCVE's post-update check validates the local structure and freshness; it is not an independent cryptographic attestation of Trivy's database contents.

When `PORTCVE_TRIVY_PATH` is unset, the database commands search absolute entries in the caller's `PATH` for `trivy.exe`, resolve the match to an absolute path, and reject UNC/device paths, mapped network drives, and reparse traversal before launch. If `PORTCVE_TRIVY_PATH` is set, it must itself be an absolute local `.exe` path. PortCVE does not download or install Trivy.

These checks are path-based and repeated immediately before launch and verification. They do not claim to defeat a malicious same-user process that can replace a validated path during the remaining check/use window. Keep the Trivy executable and cache in directories that are not writable by untrusted local users, and do not run database maintenance concurrently with hostile local processes.

## Authorized remote assessment

`scan-host` is a separate evidence path from the local `scan` command. It accepts one hostname, IP address, or IPv4 CIDR, freezes DNS results once per target, and performs TCP connect discovery. The default `common` set is PortCVE's deterministic curated service-port list; it is not advertised as an industry top-N ranking.

```powershell
portcve scan-host 10.20.30.40 --authorized
portcve scan-host 10.20.30.0/24 --ports 22,80,443,8000-8100 --authorized --max-hosts 256
portcve scan-host app.example.test --ports all --authorized --active --rate 250 --concurrency 64
portcve scan-host app.example.test --ports 22,443 --authorized --online-advisories --strict
```

`--authorized` records the operator's assertion that the selected scope may be tested. PortCVE cannot verify legal authority; it refuses to start without the assertion. CIDR expansion defaults to 256 addresses and has an explicit maximum of 65,536. A single in-memory report is limited to 1,000,000 planned target/port pairs; split larger engagements into runs instead of risking an out-of-memory failure. Connection rate, concurrency, connect timeout, read timeout, frozen address/port expansion, stored evidence, and response parsing are bounded. There is no unlimited-rate switch.

Discovery performs a full TCP connection and then protocol-specific, non-authenticated identification where applicable: SSH/FTP/SMTP/POP3/IMAP greetings, HTTP `HEAD /`, TLS negotiation, certificate observation, and HTTPS `HEAD /`. `--active` adds only bounded `OPTIONS /`, `HEAD /robots.txt`, `HEAD /.well-known/security.txt`, and separate TLS 1.2/1.3 handshakes. For a silent service on a nonstandard port, active mode also tries a fresh `HEAD /` connection followed by a TLS ClientHello only when HTTP was not confirmed; HTTPS is attempted only after TLS explicitly negotiates HTTP/1.1 through ALPN. Any greeting suppresses the adaptive probes. PortCVE does not follow redirects, retain response bodies, submit credentials, crawl, upload, mutate application state, brute-force, fuzz, execute an exploit, or run denial-of-service checks.

These connections are observable and can create server, firewall, IDS, or rate-limit logs. `HEAD` and `OPTIONS` are selected as non-mutating methods, but PortCVE cannot guarantee that a broken or unusual target implements them without side effects; authorization and operator judgment still matter.

`--online-advisories` is the only remote-assessment option that contacts a third-party service. It sends a verified catalog-backed CPE—not the target IP, hostname, banner, or credentials—to the [NVD CVE API 2.0](https://nvd.nist.gov/developers/vulnerabilities). Only strong protocol-banner product/version evidence can enter the small built-in CPE catalog; HTTP `Server` headers, port numbers, and guesses cannot. NVD configuration trees and enrichment status are preserved so compound platform requirements are reported as conditional or inconclusive rather than flattened into a direct candidate. Requests share a non-bypassable process-wide six-second minimum interval and honor bounded `Retry-After` cooldowns. Set `PORTCVE_NVD_API_KEY` to use an NVD key without placing it in arguments or output.

One run queries at most 64 unique catalog-backed CPE identities. Repeated endpoint observations of the same identity share one `advisory_results` record and retain endpoint association through `advisory_result_id`; CVE/configuration payloads are not copied into every assessment. The summary and `--fail-on` evaluate the shared direct matches. Additional unique identities are not queried, receive an `nvd_identity_cap_exceeded` endpoint diagnostic, and make the aggregate advisory status `partial`; `--strict` or `--fail-on` therefore returns incomplete-evidence exit code `3` instead of treating the bounded result as complete.

The provenance-bound catalog intentionally resolves only reviewed, protocol-bound identities: OpenSSH portable releases, Apache HTTP Server/httpd, Dropbear SSH, ProFTPD, vsftpd, and Exim. A product is eligible only when its version and canonical protocol greeting match the reviewed grammar for that mapping. Other parsed products, ambiguous/custom banners, HTTP `Server` headers, release-candidate versions, and port-only observations remain useful fingerprint evidence but are `cpe_unresolved`; PortCVE never guesses a vendor/product CPE to increase finding count.

Remote findings use `candidate`, `conditional_candidate`, or `inconclusive`; all retain `exploitability: not_assessed`. Remote `--fail-on` requires `--online-advisories`, applies only to direct high/critical candidates, and returns `3` rather than passing if advisory evidence is partial. Conditional or inconclusive records never trigger exit `1`. Default JSON aliases targets/addresses and removes raw banners/certificate identity; `--include-private` retains them. `-o` writes a redacted versioned JSON report unless `--include-private` is supplied and refuses to replace an existing file.

NVD notice: This product uses data from the NVD API but is not endorsed or certified by the NVD.

## Scanner-to-owner verification

`verify` performs no remote traffic. It imports one Nmap XML report, selects exactly one imported host, and joins those outside observations to a fresh local Windows collection. Optional Nuclei JSONL and Nessus reports add finding provenance.

```powershell
portcve verify .\edge-nmap.xml `
  --target 203.0.113.10 `
  --nuclei .\findings.jsonl `
  --nessus .\assessment.nessus `
  --vantage internet `
  --port-map tcp/443=tcp/8443 `
  --strict `
  -o .\verification.json
```

`--target` is required and asserts that the chosen imported host represents the Windows machine running PortCVE. Prefer an exact imported IP address. When an IP is selected, Nmap hostname aliases are not used to attach supplemental findings; the Nmap import model does not preserve hostname-only hosts that have no explicit port rows. Selection by hostname is accepted only when its retained endpoint rows map to one imported address, and any attached finding remains `owner_ambiguous` rather than exact owner corroboration. Ambiguous or missing targets return exit code `2`. `--vantage` is an operator label and defaults to `imported_scan`; PortCVE does not independently verify where the scanner ran.

External and local ports map identically by default. `--port-map tcp/443=tcp/8443,udp/53=udp/5353` records explicit NAT or forwarding knowledge. Cross-protocol, duplicate, malformed, and out-of-range mappings are rejected.

Endpoint results remain deliberately narrow:

- `correlated_open`: Nmap reported `open` and a current non-loopback listener matches the mapped local endpoint.
- `outside_only`: Nmap reported `open`, but no matching live listener was observed.
- `loopback_mismatch`: the outside-open endpoint maps only to a loopback bind.
- `outside_negative_local_present`: a live listener exists while the imported state was closed or non-open.
- `consistent_absent`: an explicit imported closed state has no live match.
- `inconclusive`: input, collector, state, or correlation evidence is incomplete or conflicting.

All matching listeners are retained. PortCVE does not select one owner when wildcard, interface, IPv4, IPv6, reused UDP, or multiple-process binds coexist. Nuclei and Nessus findings are grouped by endpoint and CVE while retaining scanner provenance. Exact input and source-record hashes remain available only with `--include-private`; default JSON sets `privacy_mode: reduced` and replaces them with a schema-valid zero digest because target-bearing evidence hashes can otherwise be enumerated. Private JSON sets `privacy_mode: private`. Portless findings, findings for a port absent from Nmap, and findings without a defensible transport protocol remain target-level rather than being forced onto a socket. Finding correlation says whether a local owner was corroborated; `exploitability` always remains `not_assessed`.

Firewall evidence is collected by default and can be disabled with `--no-firewall`. `--strict` requires a complete socket table plus strong owner identity, known bind scope, and sufficient requested firewall evidence for every selected matching listener. Unrelated protected-process owner gaps remain visible diagnostics but do not invalidate strong selected evidence. Verification is capped at 65,536 selected Nmap endpoint groups, 25,000 selected findings, and 25,000 finding-to-advisory memberships; larger engagements must be split. Output follows `schema/portcve.verify.v1.schema.json`; default JSON aliases the selected target, vantage, local addresses, hashes, container identities, diagnostic details, and matching target/address text embedded in retained scanner labels. Use `--include-private` only for a controlled report.

Imported scan time and live collection time are generally different. A matching listener supports plausible local owner attribution, but does not prove the imported packet reached that socket, that the path remains reachable, or that a finding applies to the loaded code.

## External evidence imports

`import` normalizes an existing local scanner result without launching that scanner, fetching templates, following links, resolving targets, or sending network traffic:

```powershell
portcve import nmap .\scan.xml -o .\scan.portcve.json
portcve import nuclei .\findings.jsonl -o .\findings.portcve.json
portcve import nessus .\assessment.nessus -o .\assessment.portcve.json
```

The input must be an existing regular file on a local drive. UNC paths, mapped network drives, device paths, symbolic links, junctions, mount points, and cloud placeholders are rejected before the file is opened. Nmap XML is capped at 64 MiB. Nuclei JSONL and Nessus XML are capped at 256 MiB and have format-specific host, item, line, depth, and retained-text limits. Every importer enforces a bounded retained-character budget before JSON serialization. The report records only the input leaf name, byte length, and SHA-256—not its full local path.

Nessus import accepts canonical `NessusClientData_v2/Report/ReportHost/ReportItem` structure, normalizes plugin ID, title, severity, target, endpoint, service name, and CVE identifiers, and discards raw `plugin_output`, credentials, and unrelated host properties. DTDs and external entities are prohibited. Dropped or malformed evidence makes the normalized result incomplete.

Path validation is repeated close to file I/O, but it is path-based. It does not claim to defeat a malicious same-user process that can rename an ancestor and replace it with a junction in the validation/open race window. Use assessment input/output directories that are not writable by untrusted local users.

Nmap XML is parsed forward-only; PortCVE never builds a DOM for the whole file. DTDs and external entities are prohibited, element depth and cardinality are bounded, and only the canonical unqualified `nmaprun/host/hostnames/hostname`, `nmaprun/host/ports/port`, direct port child, and `nmaprun/runstats/finished` paths count. PortCVE imports fields from [Nmap's documented XML format](https://nmap.org/book/output-formats-xml-output.html), maps `method=probed` confidence 8–10 to `strong`, confidence 5–7 to `moderate`, and port-table identity to `weak`. A safe NSE script identifier remains an `imported_match` with `unresolved` evidence strength, but raw NSE output and nested script content are discarded. A missing, misplaced, namespaced, or unsuccessful Nmap `finished` state marks the document incomplete.

PortCVE does not bundle, download, or execute Nmap. Import-only keeps the tools operationally independent and avoids presenting Nmap's [separate licensing terms](https://nmap.org/book/man-legal.html) as PortCVE's MIT-licensed code.

Nuclei JSONL is read in fixed-size byte chunks; an oversized strict record is rejected without first materializing the rest of a potentially 256 MiB line. PortCVE normalizes a safe template identifier, severity, sanitized target origin, matcher, canonical advisory references, and CVE identifiers; records explicitly carrying `matcher-status: false` are ignored. URL userinfo, query strings, fragments, and opaque token-like path segments are not republished. Extracted results—including possible credentials—raw requests, responses, curl commands, templates, encoded templates, and template URLs are discarded rather than copied into the normalized report. Imported matches require independent validation before reporting. Without `--strict`, malformed or oversized lines become diagnostics and valid later lines are retained in an incomplete report; `--strict` rejects the first malformed or oversized line.

Import output always follows `schema/portcve.import.v1.schema.json`. Use `-o, --output` to write it to a file and `--force` to replace an existing output. The normalized report still contains target and scanner-result metadata and is not anonymous; review it before sharing.

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
| `--strict`, `--require-complete` | Return exit code `3` when required evidence is incomplete. For `scan-host --online-advisories`, unresolved strong identities, the 64-identity query cap, partial NVD status/applicability, or failed provider evidence are incomplete. An absent optional Docker Engine does not fail general local strict mode; container-aware lockfiles have a separate completeness gate. |

`diff` and `check` use the selector and UDP choice stored in the lockfile. They do not accept new port, protocol, process, or scope filters.

## Baselines

| Option | Behavior |
| --- | --- |
| `--include-udp` | Include UDP in `lock` and `watch`. TCP-only is the default because connectionless, duplicate, and short-lived UDP binds can create noisy baseline churn. A protocol-specific UDP lock also records `includes_udp: true`. |
| `--allow-incomplete` | Permit `lock` to write a baseline with incomplete ownership, bind-scope, requested host-policy, or requested container evidence. Such a file is useful for manual diffing but cannot make `check` pass while evidence remains incomplete. |
| `--allow-weak-owner` | At `lock` creation only, store an explicit policy that permits `name_only` owner identity to support `diff` and `check`. The flag is not accepted by `diff` or `check`; those commands inherit the stored policy. `unknown` owners remain incomplete. |
| `-o, --output <path>` | Write a lockfile or snapshot to a path. The default lockfile is `listeners.lock.json`. |
| `--force` | Replace an existing lockfile or snapshot instead of failing with exit code `2`. |

Lockfiles omit PIDs, timestamps, command lines, environment variables, account names, full paths, container IDs, container names, and raw image references. They store normalized owner identity strength, host-policy confidence, evidence-completeness metadata, the selector, the weak-owner policy, and whether UDP was included. Lockfile input is limited to 16 MiB and 50,000 listener records before it can be used by `diff` or `check`; exceeding either limit is an invalid-lockfile/schema error with exit code `2`.

By default, a passing baseline requires every selected listener to have `sha256`, `container_image`, exact `service`, or `kernel` owner identity. `--allow-weak-owner` is a narrower alternative to `--allow-incomplete`: it can make a baseline/check decision-capable when every selected listener has at least a stable process image name and every bind-scope, requested firewall, and requested container evidence dimension is sufficient. The lockfile still records `evidence.ownership: partial`; it also records `allow_weak_owner: true`, so the weaker decision policy is visible and inherited. Human and JSON `diff`/`check` output identify the stored policy. A missing policy field means `false`, and ordinary strong lockfiles omit it.

The weak policy never accepts `unknown`, never converts `name_only` into strong evidence, and never masks a later strong-to-weak, bind-scope, firewall, or container regression. A current SHA-256/service/kernel identity with the same observed process name is reported as improved evidence rather than a false owner change, but it does not ratchet the stored baseline; review and recreate the lockfile to adopt stronger evidence. A newly correlated `container_image` identity remains an owner change. Most importantly, a name-only baseline cannot distinguish a different binary using the same image name. Prefer an elevated strong baseline when that replacement threat matters.

`evidence.containers` is `complete` when the Docker Engine answered successfully, including when it reported no running published ports. A normally absent Docker pipe is `not_collected`, so non-Docker hosts do not need `--allow-incomplete`. Access denial, timeout, malformed response, or collector failure is `partial` for a container-aware capture. Correlated endpoints use `container_image` owner strength and a deterministic `container-image-set:<sha256>` identity when every correlated publication supplies an image ID; otherwise owner identity falls back to the observed host process/service rules. `diff` and `check` recollect Docker evidence when the baseline's container evidence was collected.

An Engine publication that cannot be matched to a Windows endpoint is reported as a diagnostic, makes Docker evidence `partial`, and is not added to the lockfile as a synthetic listener. A later loss of an evidence dimension required by the baseline appears in `diff` as `evidence_regressed`; `diff --strict` and `check` return exit code `3`.

## JSON and privacy

| Option | Behavior |
| --- | --- |
| `--json`, `--format json` | Emit versioned JSON. `watch --json` emits one compact JSON object per line. |
| `--format jsonl` | Select machine-readable output; JSONL is meaningful for streaming `watch`. |
| `--format table`, `--format text` | Select human-readable output. |
| `--include-private` | Disable default JSON/snapshot redaction and include collected local or remote addresses, target names, interface details, owner paths/identity, container IDs/names/image references, firewall-rule details, and raw bounded evidence/diagnostics. It never enables command-line or environment-variable collection. |

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
| `3` | Evidence is incomplete for the requested strict or gating operation, no vulnerability subject could be scanned, no remote target resolved, or requested online advisory evidence failed. |
| `4` | Required collection or runtime operation failed. |
| `130` | Interrupted. |

Diagnostics are written to stderr so JSON stdout remains parseable.

# Threat model and claim boundaries

## Assets

- Accurate local endpoint inventory
- Correct owner and bind-scope attribution
- Privacy of local process and network metadata
- Integrity and portability of baseline files
- Honest confidence and limitation reporting
- Authorized remote target scope, rate limits, and evidence provenance
- Prevention of remote CVE false positives from banners, headers, or conditional applicability

## Trusted inputs

Windows kernel and service APIs, local adapter state, local Docker Engine responses, and merged Windows Firewall CIM objects are treated as evidence sources. They are not assumed immutable during collection. Docker responses describe runtime-declared publications and are not treated as direct Windows socket ownership. Firewall CIM objects describe configuration; they are not treated as a live packet-classification oracle.

Lockfiles are user-provided data. Their schema is validated before comparison, but they are not signed in the current release.

## In scope

- Buffer-size races while native endpoint tables change
- Processes exiting or PIDs being reused during collection
- Access denied for protected processes or policy data
- Duplicate/reused UDP binds
- Conflicting allow and block rules
- Conditional firewall rules and unsupported tokens
- Docker Engine absence, access denial, timeout, invalid response, or API failure
- Ambiguous or unmatched Docker publication-to-host-socket tuples
- JSON stdout contamination
- Accidental storage of PIDs, timestamps, usernames, paths, or arguments in privacy-reduced lockfiles
- Accidental disclosure of local addresses, process/container identities, image references, paths, firewall-rule details, or diagnostic text in redacted snapshots
- Unexpected domain/network lookup when resolving account SIDs
- Argument injection, hangs, unbounded output, or child-process escape in the external vulnerability scanner
- Stale, missing, malformed, or changing local vulnerability evidence
- DNS rebinding, oversized CIDR/port expansion, slow services, control characters, and cross-protocol banner spoofing
- Misleading or conditional NVD configuration trees, incomplete enrichment status, rate-limit responses, and identity/CPE mismatch
- Malformed or oversized Nmap XML and Nuclei JSONL, including XXE and secret-bearing raw request/response fields

## Out of scope

- A compromised Windows kernel or administrator falsifying local evidence
- Malware evading observation or changing behavior after collection
- Third-party WFP filters not represented by Windows Firewall rules
- Proving that a correlated Docker publication owns the Windows socket or identifying the process inside the guest
- WSL guest-process or Kubernetes workload attribution
- Router, NAT, VPN gateway, cloud security group, or remote-host behavior
- Proving that a port is reachable from the Internet
- Safely executing an untrusted binary
- Proving a known advisory is exploitable, reachable through the selected port, or applicable to code loaded at runtime
- Proving that a version-bearing greeting was not deliberately spoofed or rewritten by an intermediary
- Inferring a product or CPE from a native process name, executable metadata, port number, generic header, or unverified banner
- Downloading or updating Trivy or its vulnerability database
- Legal authorization for a remote target; `--authorized` records the operator's assertion but cannot verify permission
- Exploit success, authentication, application state changes, crawling, brute force, fuzzing, denial of service, stealth, or evasion
- Defending path-based import/output validation against a malicious same-user process that can concurrently replace a writable ancestor with a junction between validation and file I/O

## Safe failure rules

- Missing evidence produces `partial`, `not_collected`, `unknown`, or `mixed`; never an invented clean result.
- UDP is called `bound`, not necessarily listening for incoming datagrams.
- Static firewall reasoning says `static host policy indicates allow` or `static host policy indicates block`, not `Internet reachable`.
- Static firewall results always carry confidence and limitations and do not claim that WFP or a remote path accepted a packet.
- Docker publication correlation is always medium confidence. An unmatched publication produces a diagnostic and never a synthetic listener.
- An absent Docker pipe degrades quickly to optional `unavailable` evidence and never starts Docker Desktop or a container. Access denial, timeout, or failed Engine collection cannot become complete container baseline evidence.
- Watch does not report removals from a failed endpoint snapshot.
- V1 never kills a process, closes a local socket, changes a firewall rule, executes an exploit, submits credentials, or sends state-changing remote requests.
- Vulnerability subjects are limited to exact immutable Docker image IDs and explicitly supplied SBOMs. Unresolved native processes are `not_supported`, never silently clean.
- Trivy is launched directly with an argument list, bounded time and output, process-tree termination on cancellation or limits, and offline/update/telemetry flags. Post-kill waiting also has a fixed grace period, so failed termination cannot hang PortCVE indefinitely. PortCVE does not invoke a shell or fall back from the local Docker image source to a registry.
- Every inherited `TRIVY_*` variable is removed case-insensitively before PortCVE sets its small offline allowlist. Each scan gets a validated local temp directory through `TMP` and `TEMP`; cleanup is limited to the exact generated child and runs for success, failure, timeout, output overflow, or cancellation.
- The Trivy executable is an explicit user trust boundary: PortCVE executes `PORTCVE_TRIVY_PATH`, or `trivy.exe` as resolved by the caller's `PATH`. Operators must provide a trusted local executable and must not point either setting at a UNC path or reparse point; the offline flags cannot make an untrusted executable safe.
- Missing or invalid database metadata is `unavailable`. A database older than 72 hours is `partial`; `--strict` returns exit code `3`.
- SBOMs must be local regular files. UNC paths, mapped network drives, and reparse-point traversal are rejected before collection. Files are hashed before and after scanning; changed input findings are discarded and the scan cannot become successful partial evidence.
- A zero-match result is qualified by database date and completeness. A finding is a package/advisory match, not proof of exploitability or reachability.
- Remote scans require `--authorized`, freeze DNS once, use explicit bounded ports/targets/concurrency/rate/timeouts, and retain distinct connection states. Active mode is limited to non-authenticated HTTP `OPTIONS`/`HEAD` and TLS handshakes.
- Remote TCP, HTTP, and TLS activity is observable and can create logs or rate-limit state. The selected HTTP methods are intended to be non-mutating, but a target with non-compliant method handling may still have side effects.
- Remote product/version evidence is protocol-bound. HTTP headers remain ineligible for automatic NVD correlation. Only a strong banner plus a provenance-bound catalog resolution may trigger an explicit-online NVD query.
- Catalog-eligible greetings use anchored, product-specific grammar over a complete first protocol line. Unsupported release, distribution, and custom suffixes stay unresolved; PortCVE does not truncate them into a different upstream version. Modern versionless ProFTPD greetings remain FTP evidence only.
- Banner identities remain self-reported candidates even when their syntax matches an upstream default. The static catalog proves only the reviewed NVD vendor/product namespace mapping and a lossless version representation; it does not authenticate the remote binary or guarantee that NVD already contains that exact release.
- NVD output preserves configuration/applicability and enrichment status. Compound cofactors are conditional, negated or insufficient applicability is inconclusive, and every result keeps `exploitability: not_assessed`. At most 64 unique catalog-backed identities are queried per run, and repeated endpoint observations reference one normalized provider result instead of duplicating attacker-amplifiable CVE payloads.
- Default remote JSON replaces diagnostic messages with scope-specific safe text while retaining diagnostic codes; raw endpoint-formatted exception text and remote-controlled `Allow` header values remain private-only.
- Nmap and Nuclei support is import-only. Their files are untrusted local inputs, cannot traverse network/reparse paths, are size/count/depth/retained-output bounded, and never cause PortCVE to execute scanners, templates, URLs, requests, responses, or curl commands. XML structure is matched by canonical unqualified parent paths so nested lookalike elements cannot forge endpoints or successful completion. Default normalized output removes URL credentials/query/fragment/token-like components and does not retain NSE output, extracted results, raw requests/responses, curl commands, or template content.

## Privacy modes

Lockfiles are normalized, privacy-reduced baselines and never contain PIDs, timestamps, account names, command lines, environment variables, full executable paths, raw container IDs/names, or raw image references. When complete Docker image IDs are available, a lockfile can contain a deterministic hash of the correlated image-ID set as owner identity. That hash can still fingerprint a software/image set. Lockfiles also reveal ports, protocols, bind scopes, other owner identities, and policy/completeness metadata. Review them before sharing or publishing.

JSON snapshots are redacted by default, but they are not anonymous. Ports, scopes, process and service names, network profile labels, policy results, and collection metadata remain useful—and potentially sensitive—host facts. The redactor replaces the owning PID with `0` and omits creation time. For Docker publications it replaces container IDs, names, and image references, omits image IDs, and normalizes the host address, while preserving mapping ports, protocol, runtime, confidence, and the fact that a correlation exists. `--include-private` additionally permits collected PIDs/times, interface identities and addresses, paths, parent/account identity, container identifiers/images, firewall rule details, evidence, and diagnostic text to be serialized.

Docker collection uses the local `\\.\pipe\docker_engine` IPC endpoint. It does not contact a TCP Docker endpoint, pull an image, start a container, or execute inside one.

The dated live fixture described in the README validated TCP and UDP echo, independent host-tuple observation, correlation by the then-named BindWitness build, complete container-image lock evidence, an unchanged pass, and `owner_changed` after host-owner replacement. That evidence supports the local integration path only; it does not reduce the external-reachability, guest-ownership, WSL/Kubernetes, or cross-version boundaries above.

Account-name resolution is off by default. `--resolve-accounts` uses Windows `LookupAccountSid`, which can contact a domain controller or global catalog when data is not available locally. This opt-in weakens the otherwise local/offline collection boundary and is documented separately from `--include-private`.

Vulnerability JSON is redacted by default. It retains advisory IDs, package names and versions, severities, fix metadata, selected ports, bind scope, and database freshness because those are the report's operational content. It replaces Docker image references and SBOM names, omits artifact IDs/hashes, normalizes listener keys, and sanitizes free-form limitations and diagnostics. `--include-private` can expose local SBOM paths, immutable image IDs, image references, and detailed scanner diagnostics; review it before sharing.

Remote JSON is also redacted by default. It replaces selector/target/address values with run-local aliases, clears raw greeting and HTTP/TLS evidence, and drops identity-bearing fingerprint attributes while retaining ports, protocol/service categories, parsed product/version candidates, CPEs, advisory IDs, severity, applicability, and limitations. `--include-private` retains frozen addresses, hostnames, raw bounded evidence, certificate identity, and other potentially sensitive assessment metadata.

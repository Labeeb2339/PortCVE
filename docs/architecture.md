# Architecture

PortCVE is a collection-and-correlation CLI. It does not sniff packets, execute untrusted code, or run exploit payloads. Its remote path makes bounded TCP/application connections only after an authorization assertion.

## Pipeline

1. The Windows endpoint collector calls native `GetExtendedTcpTable` and `GetExtendedUdpTable` for IPv4 and IPv6 owner-PID tables.
2. The owner collector enriches unique PIDs with image path, creation time, token identity, parent snapshot, and active Windows services.
3. The interface collector maps local addresses to active adapters and, when requested, Windows network profiles.
4. The bind classifier labels each endpoint `loopback`, `interface`, `wildcard`, or `unknown`.
5. The Docker collector probes the local `\\.\pipe\docker_engine` named pipe, negotiates the Engine API version, reads running-container publications, and correlates them to observed endpoints by protocol, host address, and host port.
6. The optional firewall collector reads the merged `ActiveStore` through structured NetSecurity CIM objects and joins rule filters by stable rule ID.
7. The evaluator separates exact matches from conditional or unsupported rules. Unresolved predicates lower confidence and can produce `mixed` or `unknown`.
8. For `scan`, the vulnerability layer selects only immutable correlated Docker image IDs or an explicitly supplied local SBOM, invokes a separately installed Trivy process in offline mode, and records database freshness and provider completeness.
9. For `scan-host`, the planner bounds target/port expansion, freezes DNS once, and runs TCP discovery plus protocol-specific greeting, HTTP, and TLS probes through a shared rate limiter.
10. Strong protocol-banner product/version identities may enter the small verified CPE catalog. Explicit-online NVD requests preserve CVE applicability/configuration conditions; headers and port-number guesses never enter that path.
11. Forward-only, cardinality-bounded Nmap XML and byte-streamed Nuclei JSONL importers normalize already-produced evidence without launching either external scanner or fetching templates/links. Normalization retains safe endpoint and finding identifiers while discarding raw NSE output, extracted values, requests, responses, curl commands, and template content.
12. Renderers emit human text, versioned JSON, JSONL events, normalized lockfiles, vulnerability reports, remote reports, or import documents.

Native socket collection and a bounded Docker named-pipe probe run for every live collection. If the pipe is absent, the Docker collector returns `unavailable` quickly and does not start Docker Desktop or any container. Windows Firewall collection is intentionally opt-in for inventory, lock, and watch because effective rule enumeration is much slower.

## Evidence sources

PortCVE labels evidence by source because the sources have different semantics:

| Evidence | Source | Limits |
| --- | --- | --- |
| TCP/UDP endpoint and PID | Native IP Helper owner-PID tables | Direct point-in-time host observation; still vulnerable to collection races and PID reuse. |
| Process path/time/SID, parent and service candidates | Native process/token, Toolhelp, and Service Control Manager APIs | Best-effort enrichment after the socket sample; access denial and process churn are explicit limitations. |
| Adapter address and state | Local .NET network-interface APIs | Local adapter configuration observed during the collection window. |
| Network profile | Local `Get-NetConnectionProfile` | Structured CIM configuration used to map an adapter to a Windows profile. |
| Docker published-port metadata | Local Docker Engine `/version` and negotiated `/containers/json` over `\\.\pipe\docker_engine` | Runtime-declared mapping for a running container; correlated to a host socket by tuple with medium confidence, not proof that the container owns the Windows socket. |
| Firewall profile/rules/filters | Local NetSecurity commands against `ActiveStore` | Static configuration evidence consumed by PortCVE's evaluator, not a live WFP packet-classification result. |
| Package advisory matches | Separately installed Trivy, immutable local Docker image ID or explicit local SBOM, and pre-populated local database | Known-advisory match for an observed package version; not proof of reachability, exploitability, or compromise. |
| Remote TCP/protocol evidence | Direct TCP connection, bounded greeting/HTTP response, or TLS handshake after `--authorized` | Observed network behavior at that time; not proof of every path, product installation, vulnerability, or exploitability. |
| Remote CVE candidates | Strong banner identity, provenance-bound CPE catalog mapping, and explicit-online NVD CVE/configuration data | Candidate only. Compound cofactors stay conditional; insufficient or negated applicability stays inconclusive. |
| Imported Nmap/Nuclei evidence | Existing local files supplied by the operator | External scanner claims retained with source/confidence; never promoted to verified PortCVE observations automatically. |

The PowerShell scripts are bundled constants and do not interpolate CLI input. They run locally, but `--resolve-accounts` separately calls Windows account lookup APIs; Windows can contact domain services when a SID is not local or cached.

## Data boundaries

The core model contains platform-neutral listeners, owners, interfaces, container publications, policy evidence, vulnerability subjects/findings/provider runs, remote observations/applicability, imported evidence, diagnostics, and evidence status. Win32, Docker transport, Trivy, remote protocol, NVD, Nmap, and Nuclei parser structures remain in their collection layers.

## Authorized remote assessment

The planner accepts one hostname/IP or IPv4 CIDR, rejects URL/path syntax, defaults to at most 256 expanded addresses, and requires `--authorized`. DNS names are resolved once and every later connection uses the frozen numeric set. A scanner instance owns one monotonic connection-rate limiter shared across all targets in the run; overall host and per-host concurrency stay within the CLI bound. Each frozen address/port set and each stored response has a hard cap.

Discovery never depends on ICMP. TCP refusal, timeout, unreachable, error, and successful connection are different states; timeout is not relabeled `filtered`. Passive identification reads bounded greetings or issues `HEAD /` on configured HTTP ports and performs TLS/HTTPS negotiation on configured TLS ports. Safe-active mode adds only `OPTIONS`/`HEAD` requests and separate TLS version handshakes. A silent nonstandard port may receive a fresh adaptive `HEAD /` and then a TLS ClientHello; valid HTTP framing or a completed TLS handshake is required, and HTTPS requires HTTP/1.1 ALPN. Cross-host redirects are recorded as headers and never followed.

Product extraction is protocol-bound. A strong product/version pattern in a protocol greeting may be submitted to the provenance-bearing catalog as `strong`; an HTTP `Server`/`X-Powered-By` self-report remains review-only. The NVD client is disabled unless explicitly requested, sends only the selected CPE, rate-limits requests process-wide, honors server cooldown, and never records the optional API key. A run queries at most 64 unique catalog-backed identities. Provider findings are normalized once in `advisory_results`; endpoint assessments reference them by `advisory_result_id`, preventing repeated services from multiplying full CVE/configuration payloads. Applicability trees, vulnerability status, source timestamps, and limitations are retained. Direct candidates, conditional candidates, and inconclusive records are separate output states; exploitability is always `not_assessed`.

Catalog eligibility is deliberately narrower than product-name recognition. The complete first greeting line must match an anchored vendor form and the observed version must be dotted numeric. OpenSSH portable `p` levels are losslessly split into the CPE update component; ProFTPD additionally permits one stable patch letter because the Official CPE Dictionary represents releases such as `1.3.8a` in the version component itself. Release-candidate, distribution, and custom suffixes remain unresolved rather than being truncated. The supported strong greeting mappings are:

| Protocol-bound greeting form | Catalog identity | CPE vendor/product | Primary basis |
| --- | --- | --- | --- |
| SSH software field `OpenSSH_<version>p<level>` | OpenSSH portable | `openbsd:openssh` | [RFC 4253 identification field](https://www.rfc-editor.org/rfc/rfc4253.html#section-4.2) and [OpenSSH portable version definition](https://github.com/openssh/openssh-portable/blob/master/version.h) |
| SSH software field `dropbear_<version>` | Dropbear SSH | `dropbear_ssh_project:dropbear_ssh` | [Dropbear upstream identification definition](https://github.com/mkj/dropbear/blob/1442f00d3f0d755d9f8ba83c5edcd893aa4d71db/src/sysoptions.h#L6-L14) |
| FTP `220 ProFTPD <stable-version> Server (...) [...]` | ProFTPD | `proftpd:proftpd` | [Historical upstream greeting implementation](https://github.com/proftpd/proftpd/blob/v1.3.5a/src/session.c#L301-L316); [current ServerIdent documentation](https://www.proftpd.org/docs/modules/mod_core.html#ServerIdent) confirms that modern defaults omit the version |
| FTP `220 (vsFTPd <version>)` | vsftpd | `vsftpd_project:vsftpd` | [Official vsftpd 3.0.5 source archive](https://security.appspot.com/downloads/vsftpd-3.0.5.tar.gz), `prelogin.c` and `vsftpver.h` |
| SMTP `220 <domain> ESMTP Exim <version> ...` | Exim | `exim:exim` | [RFC 5321 greeting grammar](https://www.rfc-editor.org/rfc/rfc5321.html#section-4.2) and [Exim's default `smtp_banner`](https://www.exim.org/exim-html-current/doc/html/spec_html/ch-main_configuration.html) |

The vendor/product pairs above were checked on 2026-08-10 through the [NVD CPE API 2.0](https://nvd.nist.gov/developers/products) against the Official CPE Dictionary. This is provenance for the static namespace mapping, not a claim that every newly observed version already has a dictionary record. A successful zero-result NVD response remains a qualified zero candidate result for that query; it is not proof that the service is vulnerability-free.

## Offline vulnerability assessment

`scan` begins from the same point-in-time listener snapshot used by the rest of the CLI. It never guesses a product from a native process name, executable metadata, banner, or port number. Automatic Docker association requires a correlated immutable `sha256:` image ID; an SBOM association exists only when the user supplies that local file for an exact TCP-port query.

Before Trivy starts, PortCVE validates the cache, database, SBOM, and per-invocation temp paths as local-drive paths without reparse traversal. It removes every inherited `TRIVY_*` setting case-insensitively, then sets a small offline allowlist. The child process runs without a shell, with bounded stdout/stderr, a timeout, bounded post-kill waiting, and guarded temp cleanup. Missing or malformed evidence is unavailable, stale evidence is partial, and malformed Trivy result structures fail closed.

Findings retain the advisory ID, package/version, fixes, source severity, aliases, references, database time, and subject identity confidence. The report explicitly sets exploitability and network reachability to `not_assessed`. A zero-finding result means only that no known matches were present in the named database snapshot.

Each collector reports:

- `complete`, `partial`, `unavailable`, or `failed`;
- observation time and duration; and
- structured diagnostics.

Access denied and process churn are represented, not swallowed. A failed endpoint collector never becomes an empty healthy snapshot.

## Docker publication correlation

The Docker collector uses local IPC only. It calls `/version`, then the negotiated version of `/containers/json`; it does not use a TCP Docker endpoint, pull images, start containers, inspect guest processes, or execute inside a container. A missing pipe is normal optional degradation. Access denial, timeout, invalid JSON, and API errors remain explicit collector evidence.

Each Engine publication is matched against Windows IP Helper evidence using transport protocol, published host port, and compatible host address. A concrete published address can match a wildcard socket of the same address family. Because Docker Desktop can own or forward the Windows socket, a match produces `ContainerExposureEvidence` at `medium` confidence with a tuple-correlation limitation. A publication with no matching Windows endpoint produces `docker_publication_unmatched`, makes the Docker collector partial, and is not converted into an observed listener.

When a lockfile includes complete container evidence and every correlated publication supplies an image ID, the normalized owner is `container-image-set:<sha256>` with strength `container_image`. The digest is computed over the sorted distinct image-ID set, so container names and restart-specific IDs are excluded while an image-set change remains detectable. `evidence.containers` distinguishes `complete`, `partial`, and `not_collected`; a baseline that used container evidence requires comparable evidence during `diff` and `check`. Dimension-level loss is emitted as `evidence_regressed`; strict diff and check return exit code `3` instead of presenting an evidence gap as no drift.

The integrated path was validated on 2026-08-09 against Docker Desktop client/server 28.3.2 on Windows NT 10.0.26200.0 with the `desktop-linux` WSL2 context. An official `alpine:3.22` fixture published one loopback TCP tuple and one wildcard UDP tuple; both echoed real payloads, an independent Windows CIM check observed the exact tuples, and the then-named BindWitness build correlated both while retaining `com.docker.backend.exe` as the Windows owner. A container-image lock passed unchanged, then reported `owner_changed` with exit code 1 when PowerShell replaced the same TCP endpoint. This is validation of the local collection/correlation/gating path on that environment, not a claim about external reachability, guest-process ownership, Linux hosts, or every Docker version.

## Scanner-to-owner verification

`verify` is an offline join over three independently preserved evidence sources:

1. a required normalized Nmap host and endpoint set;
2. optional normalized Nuclei and Nessus finding records; and
3. a new live Windows snapshot with binary hashing and, by default, static firewall collection.

The operator selects the imported host and labels the scanner vantage. PortCVE does not resolve the imported target or make a remote connection during verification. Target selection must identify one imported address; an ambiguous hostname is rejected. External protocol/port maps to the same local endpoint unless an explicit same-transport `--port-map` records forwarding knowledge.

The join key is selected target plus external protocol/port, followed by the explicit external-to-local mapping. Every matching local listener is retained. Supplemental hostname aliases must identify only the selected Nmap address, and a finding without a defensible transport protocol remains target-level. Imported observations, owner identity strength, bind scope, container identity, host-policy confidence, and limitations remain separate fields. Exact input and finding-record hashes remain available in private output; default output uses a schema-valid zero digest to prevent offline target enumeration. Correlation states describe agreement or disagreement; they never replace the original source state.

Strict verification scopes owner and bind completeness to listeners matching the selected imported endpoints, while still requiring a complete socket table and complete requested firewall collection. This prevents unrelated protected-process metadata gaps from making a strong selected owner unusable without allowing a weak selected owner to pass. Selected endpoint groups, findings, and finding-to-advisory memberships are independently capped before grouping and serialization.

CVE-bearing findings are grouped per endpoint and advisory while preserving source observations. Non-CVE findings are grouped by source and finding ID. Portless findings stay target-level. Neither grouping nor listener attribution changes `exploitability: not_assessed`.

The versioned output is `schema/portcve.verify.v1.schema.json`. The default redactor aliases the selected target and vantage, normalizes local addresses, removes hostnames and detailed diagnostics, and masks artifact/container hashes while preserving operational port, owner-name, evidence-strength, and correlation facts.

## Listener identity

The normalized bind key is:

```text
protocol / address-family / normalized-local-address / local-port
```

PIDs and timestamps are deliberately excluded from baselines. Duplicate binds are retained as a multiset. The diff engine first removes exact multiset matches, then compares owner/scope/policy changes, and finally reports additions or removals. A loopback-to-wildcard replacement on the same protocol/family/port/owner is coalesced into `exposure_expanded`.

## Static firewall evidence

The firewall collector uses bundled constant PowerShell against the merged `ActiveStore` because it is available across the supported Windows range and returns structured CIM data. User input is not interpolated into scripts.

The evaluator considers active profile, protocol, port, application, service, address, interface, interface type, authentication, encryption, block-all, and default inbound action. Unsupported service tokens, unresolved source ranges, packaged-app constraints, and IPsec requirements remain conditional.

An observed matching block takes precedence over an observed matching allow in the static model. A conditional rule cannot produce a high-confidence permit. Even a medium-confidence `allow` or `block` remains a configuration assessment: third-party WFP callouts, IPsec negotiation, upstream controls, and an actual source packet were not evaluated.

## Snapshot privacy modes

The domain model always contains the evidence collected for the current process. JSON list/inspect and snapshot serialization applies `SnapshotRedactor` unless `--include-private` is present. The default redactor replaces interface identity/address values, replaces the owning PID with `0`, removes creation time and optional owner identity fields, sanitizes rule identity/address/constraint fields, clears free-form listener evidence, and sanitizes diagnostic/limitation details. For container publications it replaces container IDs, names, and image references, omits image IDs, and normalizes host addresses. It intentionally preserves the structural facts needed for triage, including ports, scopes, image/service names, profile labels, policy verdict/confidence, collector status, and container mapping ports/protocol/confidence.

`--include-private` changes serialization, not collection. `--resolve-accounts` changes collection, not serialization. Both are needed to emit a resolved account name in JSON. Neither mode reads process command lines or environment variables.

## Performance

Fast commands avoid network-profile and firewall collection. Direct inspection performs those two slow operations concurrently with native socket, process, and local Docker collection. The Docker collector has a short pipe-availability probe and a bounded overall request timeout, so an absent or unresponsive Engine does not hang normal inventory. Watch polls the same collectors each iteration; it does not rerun firewall enumeration unless explicitly requested.

## Future backends

The domain, diff, lockfile, and rendering layers do not depend on Win32 rows. A Linux backend can provide equivalent observed facts while preserving platform-specific limitations. Firewall semantics must stay platform-specific rather than pretending Windows Firewall and nftables are interchangeable.

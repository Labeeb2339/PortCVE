# Architecture

PortCVE is a collection-and-correlation CLI. It does not sniff packets and does not execute untrusted code.

## Pipeline

1. The Windows endpoint collector calls native `GetExtendedTcpTable` and `GetExtendedUdpTable` for IPv4 and IPv6 owner-PID tables.
2. The owner collector enriches unique PIDs with image path, creation time, token identity, parent snapshot, and active Windows services.
3. The interface collector maps local addresses to active adapters and, when requested, Windows network profiles.
4. The bind classifier labels each endpoint `loopback`, `interface`, `wildcard`, or `unknown`.
5. The Docker collector probes the local `\\.\pipe\docker_engine` named pipe, negotiates the Engine API version, reads running-container publications, and correlates them to observed endpoints by protocol, host address, and host port.
6. The optional firewall collector reads the merged `ActiveStore` through structured NetSecurity CIM objects and joins rule filters by stable rule ID.
7. The evaluator separates exact matches from conditional or unsupported rules. Unresolved predicates lower confidence and can produce `mixed` or `unknown`.
8. Renderers emit human text, versioned JSON, JSONL events, or normalized lockfiles.

Native socket collection and a bounded Docker named-pipe probe run for every live collection. If the pipe is absent, the Docker collector returns `unavailable` quickly and does not start Docker Desktop or any container. Windows Firewall collection is intentionally opt-in for inventory, lock, and watch because effective rule enumeration is much slower.

## Evidence source boundary

PortCVE labels evidence by source because the sources have different semantics:

| Evidence | Source | Claim boundary |
| --- | --- | --- |
| TCP/UDP endpoint and PID | Native IP Helper owner-PID tables | Direct point-in-time host observation; still vulnerable to collection races and PID reuse. |
| Process path/time/SID, parent and service candidates | Native process/token, Toolhelp, and Service Control Manager APIs | Best-effort enrichment after the socket sample; access denial and process churn are explicit limitations. |
| Adapter address and state | Local .NET network-interface APIs | Local adapter configuration observed during the collection window. |
| Network profile | Local `Get-NetConnectionProfile` | Structured CIM configuration used to map an adapter to a Windows profile. |
| Docker published-port metadata | Local Docker Engine `/version` and negotiated `/containers/json` over `\\.\pipe\docker_engine` | Runtime-declared mapping for a running container; correlated to a host socket by tuple with medium confidence, not proof that the container owns the Windows socket. |
| Firewall profile/rules/filters | Local NetSecurity commands against `ActiveStore` | Static configuration evidence consumed by PortCVE's evaluator, not a live WFP packet-classification result. |

The PowerShell scripts are bundled constants and do not interpolate CLI input. They run locally, but `--resolve-accounts` separately calls Windows account lookup APIs; Windows can contact domain services when a SID is not local or cached.

## Data boundaries

The core model contains platform-neutral listeners, owners, interfaces, container publications, policy evidence, diagnostics, and collector status. Win32 and Docker transport/parser structures remain in their collection layers.

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

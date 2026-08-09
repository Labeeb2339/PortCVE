# PortCVE

**Explain local ports. Check what backs them. Lock what you expect.**

PortCVE is a read-only Windows CLI that connects the facts other port tools leave separate:

- which TCP listeners and UDP endpoints exist;
- which process or Windows service owns each bind;
- which local Docker Engine publication maps a container port to that observed host bind;
- which known vulnerability advisories match packages in an exactly identified local Docker image or explicitly supplied SBOM;
- whether the bind is loopback-only, interface-specific, or wildcard;
- which active interfaces and network profiles it covers;
- what a static evaluation of the merged Windows Firewall policy suggests; and
- whether that local attack surface changed since a trusted baseline.

PortCVE does not call a wildcard bind “Internet exposed” or an advisory match “exploitable.” It reports observed host facts, known-advisory evidence, confidence, and limitations separately.

> Status: `0.1.0-alpha.1`. Windows x64 is the only supported release target today. The CLI and JSON schemas can still change before `1.0`.
>
> Naming status: **PortCVE is the current project and CLI name.** The `v0.1.0-alpha.1` release was originally published as **BindWitness**; that historical artifact remains a BindWitness build. Exact PortCVE name checks on 2026-08-09 found no repository or package collision across GitHub, PyPI, npm, crates.io, or NuGet. This screening is not formal trademark clearance.

## Why this exists

`netstat`, TCPView, and PowerShell can show sockets and owners. PortCVE is for the next question:

> What opened this port, where can it receive traffic, what does the host firewall say, do its exact packages match known advisories, and is this new?

It is designed for developers, defenders, incident responders, lab machines, and Windows hardening checks—not remote scanning.

## Quick demo

Illustrative Docker-published port:

```text
PS> portcve tcp:8080 --evidence

TCP4  0.0.0.0:8080  LISTEN

OWNER
  Process      com.docker.backend.exe  pid 6840
  Binary       C:\Program Files\Docker\Docker\resources\com.docker.backend.exe
  User         S-1-5-21-...

CONTAINER PUBLICATION
  Container    web  (docker)
  Image        example/web:1.0
  Mapping      0.0.0.0:8080 -> 80/tcp
  Confidence   medium

BIND
  Scope        all IPv4 interfaces
  Active on    Wi-Fi  192.168.1.42/24  (Private)

HOST POLICY
  STATIC ALLOW A matching explicit inbound allow rule was observed; static host policy indicates allow.
  Confidence   medium

REACHABILITY
  Local socket LISTENING - application acceptance was not tested
  LAN/routed   STATIC HOST POLICY INDICATES ALLOW - packet path not tested
  Internet     UNKNOWN - router, NAT, cloud controls, and the remote path were not tested

LIMITATIONS
  - Docker Engine publication was correlated by protocol, host address, and host port;
    the host socket may be owned by a Docker Desktop forwarding process.
```

PortCVE reads published-port metadata from the local Docker Engine named pipe and attaches it only when protocol, host address, and host port match an observed Windows endpoint. That tuple join is useful but intentionally reported with medium confidence; it is not direct proof of guest-process socket ownership.

### Live Docker validation

The integrated path was exercised on 2026-08-09 using Windows NT `10.0.26200.0`, Docker Desktop client/server `28.3.2`, and the `desktop-linux` WSL2 context. An official `alpine:3.22` fixture (`sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce`) published TCP `127.0.0.1:64458 -> 8080` and UDP `0.0.0.0:51731 -> 5353`; both returned real echo payloads. An independent Windows CIM check saw those exact host tuples owned by PID `30176`, while the then-named BindWitness build kept the observed owner `com.docker.backend.exe` and attached both container publications with the Docker collector `complete`.

A container-aware lock recorded `evidence.containers: complete` and `owner_identity_strength: container_image`; an unchanged `check` passed. Replacing the same TCP host endpoint with PowerShell produced exit code `1` and `owner_changed`. This validates local Docker collection, tuple correlation, and baseline drift behavior on that environment. It does **not** prove external reachability, guest-process socket ownership, broader Docker-version compatibility, or Linux host support.

After building Release, the check is reproducible with:

```powershell
.\scripts\Test-DockerIntegration.ps1 -ValidateLockCheck
```

The script is intentionally mutating: it may pull `alpine:3.22`, creates and removes one uniquely labeled container, and publishes temporary echo ports. Its safe default binds both host ports to loopback. Add `-AllowWildcardUdp` only to exercise wildcard bind classification; that briefly publishes the UDP echo fixture on `0.0.0.0`, so it may be reachable from the local network until the guarded cleanup completes.

The reachability wording is intentional. `STATIC ALLOW` and `STATIC BLOCK` summarize a static assessment of Windows Firewall configuration; they are not results from the Windows Filtering Platform packet-classification path. A local socket table and firewall rules cannot prove what a third-party WFP filter, IPsec negotiation, router, cloud security group, VPN, or remote host will do.

### Live vulnerability validation

The offline scan path was exercised on 2026-08-09 with official Trivy `v0.73.0`, an isolated schema-2 database, and the immutable local Docker image ID `sha256:c4d56c24da4f009ecf8352146b43497fe78953edb4c679b841732beb97e588b0` (Alpine 3.22.1). PortCVE reported 87 known-advisory matches: 3 critical, 17 high, 26 medium, and 41 low. A fresh strict scan returned `0`; `--fail-on high` and `--fail-on critical` returned `1`; missing and 96-hour-stale databases returned `3` without converting incomplete evidence into a clean result.

The same run validated default/private redaction, Draft 2020-12 schema conformance, hostile inherited `TRIVY_*` scrubbing, zero image pulls, and per-scan temp cleanup. These results prove the tested local correlation, parsing, policy, and exit-code paths—not that every finding is reachable or exploitable. Exact hashes, representative findings, and claim boundaries are recorded in [docs/validation.md](docs/validation.md).

## Install

### Signed installer

For finalized signed releases, download, checksum, Authenticode-verify, inspect, and run the release's file-backed `install.ps1`. It refuses piped or in-memory execution, verifies its own signer before network or filesystem activity, installs without administrator rights to `%LOCALAPPDATA%\Programs\PortCVE`, verifies the versioned ZIP and signed executable, and updates the user `PATH` with rollback protection. See the complete [installer instructions and trust checks](docs/install.md).

The checked-in `scripts/install.ps1` is an unsigned, unfinalized template and deliberately refuses to run. Production installation requires the separately downloaded and signed release asset; pipe-to-execution installation is refused.

The installer never permits an unsigned production install. The historical `v0.1.0-alpha.1` release is unsigned and is intentionally rejected.

### Manual release binary

Download the Windows x64 ZIP from the repository's Releases page, verify its SHA-256 file, extract `portcve.exe`, and place it somewhere on your `PATH`.

Release binaries are self-contained; the .NET runtime is not required. Alpha binaries are not yet code-signed, so verify checksums before running them.

### Build from source

Install the [.NET 10 SDK](https://dotnet.microsoft.com/download/dotnet/10.0), then:

```powershell
cd portcve
dotnet restore PortCVE.sln --locked-mode
dotnet test PortCVE.sln -c Release --no-restore
dotnet publish src\PortCVE\PortCVE.csproj -c Release -r win-x64 --self-contained true --no-restore -o artifacts\win-x64
```

## Commands

```powershell
portcve                              # fast local inventory
portcve 8080                         # explain TCP and UDP binds on a port
portcve tcp:8080 --evidence          # protocol-specific deep explanation
portcve list --scope non-loopback    # filter likely remote-facing binds
portcve list --process node.exe      # filter by process or service
portcve snapshot --json              # full versioned evidence document
portcve scan tcp:8080 --strict        # offline advisory matches for one exact listener
portcve scan --all --fail-on high     # deduplicated Docker-image scan and CI gate
portcve lock -o listeners.lock.json  # normalized baseline, no PID or raw args
portcve lock --include-udp            # opt into noisier UDP baseline tracking
portcve diff listeners.lock.json     # report all current drift
portcve check listeners.lock.json    # CI-friendly security drift gate
portcve watch --json                 # stream changes as JSONL
portcve doctor                       # collection coverage and privacy mode
```

Direct port inspection collects Windows Firewall evidence by default. Fast inventory, lock, and watch do not; add `--firewall` when you need policy correlation and accept the extra collection time.

Run `portcve help` for the concise built-in reference. The complete option behavior, including privacy and baseline flags, is documented in [docs/cli.md](docs/cli.md).

## Baseline workflow

Create a baseline when the machine is in a known-good state:

```powershell
portcve lock -o listeners.lock.json
```

Lockfiles are TCP-only by default. Use `--include-udp` only when UDP bind drift matters to the review. UDP is connectionless, duplicate/reused binds are valid, and short-lived endpoints can create substantially more baseline churn. The `includes_udp` choice is stored in the lockfile and reused by later `diff` and `check` runs.

Review all drift:

```powershell
portcve diff listeners.lock.json
```

Gate a build, image, kiosk, or lab host:

```powershell
portcve check listeners.lock.json
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
```

`check` fails on a new endpoint, owner change, wider bind, or more-permissive host-policy assessment. Removed endpoints and narrower binds remain visible in `diff` but do not fail the security gate.

Lockfiles are deterministic and privacy-reduced. They omit PIDs, timestamps, command lines, environment variables, usernames, and full executable paths, but still reveal ports, protocols, bind scopes, owner identities such as process or service names or hashes, and policy metadata. Review a lockfile before publishing it. Duplicate UDP binds are preserved as a multiset rather than silently collapsed.

By default, `lock` refuses to write when ownership, bind-scope, or requested host-policy evidence is incomplete. `--allow-incomplete` overrides that write-time guard for investigation and diff workflows; it does **not** turn incomplete evidence into a passing security gate. `check` returns exit code `3` when its baseline or current evidence cannot support a decision.

Container evidence has its own completeness field. If the local Docker Engine responds, correlated endpoints use a deterministic SHA-256 of the sorted Docker image-ID set as `owner_identity` with strength `container_image` when every correlated publication has an image ID. This avoids container names, IDs, and restart-specific values in the lockfile. If the Docker pipe is absent, container evidence is `not_collected` and normal host-owner identity is used. Access denial, timeout, collector failure, or an Engine publication that cannot be reconciled with the Windows socket table makes requested container evidence `partial`; `lock` then requires `--allow-incomplete`, `diff --strict` returns exit code `3`, and `check` cannot pass until comparable evidence is available.

## Evidence model

PortCVE keeps five layers separate:

1. **Observed bind:** address, port, protocol, owning PID, executable/service, and bind scope.
2. **Local runtime correlation:** Docker Engine published-port metadata joined to an observed bind by protocol, host address, and host port, always with medium confidence and a tuple-correlation limitation.
3. **Static host-policy inference:** merged Windows Firewall profiles and matching inbound-rule evidence, with `allow`, `block`, `mixed`, or `unknown` plus confidence and limitations.
4. **Known-advisory match:** Trivy results for an immutable local Docker image ID or explicit local SBOM, with database identity/freshness and no exploitability claim.
5. **External path:** always `not tested` in the current release.

`UNKNOWN` is a valid result. Missing permissions, unsupported firewall constraints, process churn, WSL, third-party WFP filters, IPsec, and upstream network controls are not converted into false certainty. A Docker publication with no matching Windows endpoint remains a diagnostic and never becomes a synthetic listener.

More detail is in [docs/architecture.md](docs/architecture.md) and [docs/threat-model.md](docs/threat-model.md).

### Native, Docker, and CIM evidence

The evidence sources are intentionally identified rather than blended together:

- TCP/UDP endpoint ownership comes from native Windows IP Helper tables (`GetExtendedTcpTable` and `GetExtendedUdpTable`). Process paths, timestamps, token SIDs, parent snapshots, and active-service candidates come from native process, token, Toolhelp, and Service Control Manager APIs.
- Adapter addresses come from local .NET network-interface APIs.
- Running-container published-port metadata comes from `/version` and the negotiated `/containers/json` endpoint over the local `\\.\pipe\docker_engine` named pipe. It is runtime metadata, not direct socket-owner evidence.
- Network profile names and Windows Firewall `ActiveStore` rules/filters come from local PowerShell NetSecurity commands that return structured CIM objects.

The native socket row is direct point-in-time evidence from the host, although collection races still exist. CIM firewall data is configuration evidence consumed by a conservative static evaluator. It is slower, can degrade independently, and must not be described as a live packet decision.

## Privacy and safety

The default contract is deliberately small:

- read-only—no process killing or firewall changes;
- local/offline by default—collection uses local OS APIs and, when available, the local Docker Engine named pipe; vulnerability scans use a separately installed Trivy executable and pre-populated local database with online/update/telemetry paths disabled; PortCVE performs no reputation lookup, image pull, or sample upload;
- no target-process environment-variable reads;
- no command-line collection;
- no remote scan or external reachability probe; and
- diagnostics go to stderr so JSON stdout remains machine-readable.

Running elevated may reveal more process metadata, but the socket inventory still works for a standard user and reports gaps explicitly.

JSON list/inspect and `snapshot` output is redacted by default. It replaces interface identities and addresses, replaces the owning PID with `0`, removes process creation time and private owner fields, sanitizes firewall-rule fields, clears free-form evidence, and sanitizes diagnostic details. The schema covers both output modes, so optional private fields are absent unless they were collected and `--include-private` was supplied. Image names, service names, scopes, ports, profile labels, policy results, and collector metadata remain in the default snapshot; treat even redacted snapshots as host metadata. Human-readable inspection is intended for local viewing and can display local paths, SIDs/accounts, PIDs, and interface addresses.

For Docker correlations, default JSON replaces container IDs, container names, and image references, omits image IDs, and normalizes the published host address. It still reveals that a mapping exists, its host and container ports, protocol, runtime, and correlation confidence. `--include-private` permits the collected container identifiers and image references to be serialized. Review either mode before publishing.

`--resolve-accounts` asks Windows to translate token SIDs into account names. `LookupAccountSid` can consult domain controllers or the global catalog when the answer is not local or cached, so this flag may cause network activity. It is off by default and is separate from `--include-private`: resolution controls collection, while `--include-private` controls whether resolved private values appear in JSON.

## Machine-readable output

All JSON uses snake_case, stable enum strings, a mandatory `schema_version`, deterministic ordering, and diagnostics for partial evidence. Schema identifiers are stable URNs; they do not depend on a project website.

- [Snapshot schema v1](schema/portcve.snapshot.v1.schema.json)
- [Lockfile schema v1](schema/portcve.lock.v1.schema.json)
- [Vulnerability report schema v1](schema/portcve.vulnerability.v1.schema.json)

Human-readable output is not a compatibility API. JSON and lockfile schema changes follow the policy in [docs/versioning.md](docs/versioning.md).

## Scope

Included now:

- native IPv4/IPv6 TCP listener and UDP endpoint collection;
- PID, executable, parent process, account SID/name, and active-service attribution;
- loopback/interface/wildcard classification;
- active Windows network-profile mapping;
- local Docker Engine named-pipe collection and medium-confidence published-port correlation;
- offline known-advisory matching for immutable local Docker image IDs and explicit local SBOMs, with database freshness and CI exit gates;
- opt-in static Windows Firewall correlation;
- list, inspect, scan, snapshot, lock, diff, check, watch, and doctor workflows;
- text, JSON, and JSONL output; and
- standard-user degradation with explicit diagnostics.

Not included:

- remote port scanning;
- traffic capture or throughput graphs;
- process termination or automatic firewall changes;
- a generic “risk score”;
- proof of LAN or Internet reachability;
- exploitability proof, automatic remediation, automatic database downloads, or guessed CPEs from process/port names;
- WSL guest-process or Kubernetes workload attribution; or
- Linux support yet.

See [ROADMAP.md](ROADMAP.md) for the deliberately staged follow-up work.

## Development

```powershell
dotnet restore PortCVE.sln --locked-mode
dotnet build PortCVE.sln -c Release --no-restore
dotnet test PortCVE.sln -c Release --no-build
dotnet run --project src\PortCVE -- doctor
```

Runtime code has no third-party package dependency. Tests use xUnit. Committed NuGet lockfiles make `--locked-mode` fail if dependency resolution drifts. Warnings are treated as errors.

Before contributing, read [CONTRIBUTING.md](CONTRIBUTING.md). Security reports belong in a private GitHub Security Advisory as described in [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)

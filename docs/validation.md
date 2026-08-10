# Validation evidence

This file records dated release-candidate evidence. It is not a guarantee about other hosts, artifacts, databases, or future versions.

## Host and Docker path — 2026-08-09

- Windows NT `10.0.26200.0`, Windows x64.
- Docker Desktop client/server `28.3.2`, `desktop-linux` WSL2 context.
- Official `alpine:3.22` fixture, image ID `sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce`.
- Real TCP and UDP echo payloads succeeded through temporary published host ports.
- Independent Windows CIM observation found the exact host tuples.
- PortCVE retained the Windows forwarding-process owner and attached both Docker publications by protocol/address/port with collector status `complete`.
- Default JSON redaction, private mapping evidence, container-image lock identity, unchanged `check`, and owner-change failure were exercised.

The reproducible harness is:

```powershell
.\scripts\Test-DockerIntegration.ps1 -ValidateLockCheck -ValidateRemoteScan
```

The script creates and removes a uniquely labelled local container. Its safe default publishes only loopback host ports; wildcard UDP requires the explicit `-AllowWildcardUdp` option.
The optional remote leg scans only the temporary loopback TCP publication, requires PortCVE's normal authorization assertion, confirms the real Docker-forwarded endpoint is open, and rejects a false application identity for the generic echo protocol.

## Offline known-advisory path — 2026-08-09

Scanner integrity:

- Official Trivy release: [`v0.73.0`](https://github.com/aquasecurity/trivy/releases/tag/v0.73.0), published 2026-08-03.
- Downloaded checksum-manifest SHA-256: `36890275ffdff13025e9bd9fe039724c6e36bf58e698499856b801f619046fe2`.
- Published and observed Windows x64 ZIP SHA-256: `d2d3ad5292aae470a03eb6506db86fce81b1894592b8451cadaf60eaa22f2025`.
- Extracted `trivy.exe` SHA-256: `3f8d0a3f4306a628cccb0704ab5f9ab6589a8ff17f89d943722d551cdf8940ef`.
- The official executable was not Authenticode-signed; integrity for this validation was established by the matching checksum from the official GitHub release manifest.

Database evidence:

- Schema version `2`.
- `UpdatedAt`: `2026-08-09T07:04:26.972846897Z`.
- Database SHA-256: `5b9a2be561c5d1788c1df9e5974654bda5780f3e511eb20ae3a50945302ed502`.
- PortCVE freshness limit: 72 hours.

Pinned target:

- Local immutable Docker image ID: `sha256:c4d56c24da4f009ecf8352146b43497fe78953edb4c679b841732beb97e588b0`.
- Observed OS: Alpine `3.22.1`.
- PortCVE passed only the immutable image ID to Trivy; it did not pass a registry tag or pull the image.

Observed report:

| Severity | Matches |
| --- | ---: |
| Critical | 3 |
| High | 17 |
| Medium | 26 |
| Low | 41 |
| Total | 87 |

Representative database matches included `CVE-2025-58050` for `pcre2` `10.43-r1` (fixed in `10.46-r0`) and `CVE-2026-31789` for `libssl3`/`libcrypto3` `3.5.1-r0` (fixed in `3.5.6-r0`). These are advisory/package-version matches from the named database snapshot, not exploitability determinations.

Behavioral gates:

| Scenario | Expected exit | Observed |
| --- | ---: | ---: |
| Fresh database with `--strict` | `0` | `0` |
| `--fail-on critical` | `1` | `1` |
| `--fail-on high` | `1` | `1` |
| Missing database with `--strict` | `3` | `3` (`vulnerability_db_missing`) |
| Database aged to 96 hours with `--strict` | `3` | `3` (`vulnerability_db_stale`, all 87 findings retained) |

Seven live JSON variants and a hostile-environment rerun validated against the Draft 2020-12 vulnerability schema. Default JSON omitted the immutable image ID, artifact hash/reference, and raw listener address; private JSON retained the exact image ID. Both modes retained the same 87 operational findings.

The hostile environment set remote/suppressive `TRIVY_*` values. PortCVE removed them before setting its offline allowlist and still returned the full report. Docker event/inventory checks showed zero pulls and no image-inventory change. Per-invocation scanner temp directories and test containers were absent after completion.

## Authorized remote path — 2026-08-09

- Windows PowerShell `5.1.26100.8875`, Windows x64.
- Two disposable listeners were bound only to `127.0.0.1` on OS-assigned high ports.
- The SSH fixture returned `OpenSSH_9.6p1`; PortCVE reported OpenSSH `9.6p1`.
- The silent HTTP fixture returned `Server: Apache/2.4.58` only after receiving a request.
- Discovery sent zero HTTP requests and did not infer an identity for the silent unknown service.
- `--active` opened a fresh connection, sent exactly `HEAD / HTTP/1.1`, and reported Apache HTTP Server `2.4.58` with evidence source `active-adaptive-http-head`.
- No other HTTP method or path, external target, online-advisory request, credential, or exploit payload was used.
- Default/private privacy checks, schema-compatible output, command timeouts, process cleanup, listener cleanup, and temporary-directory cleanup passed.

The static PowerShell harness passed 29 checks. The reproducible live command is:

```powershell
.\scripts\Test-RemoteHostIntegration.ps1
```

Detailed behavior and the narrower adaptive-TLS limitation are recorded in [remote-live-validation.md](remote-live-validation.md).

## Daily-readiness integration — 2026-08-10

The current `0.2.0-alpha.1` development tree was rebuilt and exercised on Windows `10.0.26200.0` x64 as a standard user:

- locked restore, repository-wide formatting verification, and Release build passed with zero warnings or errors;
- the full .NET suite passed `386/386`, including socket churn, importer caps/redaction, remote authorization/rate/timeout gates, corrupt-database rejection, and schema contracts;
- the Windows PowerShell 5.1 installer lifecycle harness passed `66` checks for clean install, managed update, failure rollback, exact-version rollback, receipt/hash tamper rejection, guarded `PATH` handling, and offline uninstall;
- the self-contained publish produced exactly one `portcve.exe`, with no PDB or local build path embedded; it remains intentionally unsigned because no verified publisher credential has been configured;
- the Docker Desktop `28.3.2` fixture passed real TCP and UDP echo, Windows CIM tuple confirmation, default redaction, TCP/UDP lock-and-check, and an authorized scan of the temporary loopback-forwarded TCP port with no false product identity; cleanup left zero labelled containers or integration temp directories;
- the loopback remote harness again identified OpenSSH `9.6p1` and an Apache HTTP Server `2.4.58` fixture on OS-assigned nonstandard ports, with active HTTP limited to one `HEAD /` request and no online-advisory request;
- an explicit local Trivy `0.73.0` database update produced schema `2`, `UpdatedAt` `2026-08-10T01:00:06.25992962Z`, and a `1,227,595,776`-byte `trivy.db` with SHA-256 `75a2042291878bdb2cc564e4d0b5486c1b28a1ca6d1dfa4db5d78929aef0875c`;
- `db status` forced Trivy to open that database offline and returned ready/exit `0`; a junk database returned `vulnerability_db_unreadable`/exit `3`, and reduced JSON contained no local user path;
- the pinned local `docker/welcome-to-docker` image again produced `87` known-advisory matches (`3` critical and `17` high), while `--fail-on high` returned exit `1` and default JSON omitted the immutable image ID; and
- current NuGet sources reported no known vulnerable direct or transitive package in either project.

The performance harness passed its enforced budgets with ten local-inventory iterations over `144` observed endpoints (`203 ms` median, `215 ms` p95), a passive authorized loopback report covering `1,000` requested ports in `1,206 ms`, and `51.7 MiB` peak working set. These figures describe this host and run only; they are regression evidence, not universal performance guarantees.

Fresh Windows Server 2022 and 2025 CI jobs, each including the live loopback and smaller performance harness, are configured in `.github/workflows/ci.yml`. Compatibility is claimed only after those jobs pass on the published commit.

## Limitations

The evidence above supports the tested Windows collection, Docker tuple-correlation, Trivy adapter, authorized loopback discovery/adaptive HTTP, parsers, redaction, schemas, cleanup, and exit-policy paths. It does not prove:

- that a wildcard bind is reachable from a LAN or the Internet;
- that a matched package is reachable, exploitable, or compromised;
- that no unreported vulnerability exists;
- that a zero-finding result is safe beyond the named database snapshot; or
- authorization, behavior, or reachability for any untested remote target; or
- compatibility with every Windows, Docker, Trivy, image, SBOM, or firewall configuration.

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
.\scripts\Test-DockerIntegration.ps1 -ValidateLockCheck
```

The script creates and removes a uniquely labelled local container. Its safe default publishes only loopback host ports; wildcard UDP requires the explicit `-AllowWildcardUdp` option.

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

## Claim boundary

The evidence above supports the tested Windows collection, Docker tuple-correlation, Trivy adapter, parser, redaction, schema, cleanup, and exit-policy paths. It does not prove:

- that a wildcard bind is reachable from a LAN or the Internet;
- that a matched package is reachable, exploitable, or compromised;
- that no unreported vulnerability exists;
- that a zero-finding result is safe beyond the named database snapshot; or
- compatibility with every Windows, Docker, Trivy, image, SBOM, or firewall configuration.

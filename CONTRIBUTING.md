# Contributing to PortCVE

Thanks for helping make local exposure evidence more trustworthy.

## Before opening code

For a substantial feature, start with an issue describing the user problem, the evidence source, supported Windows versions, failure modes, privacy impact, and how the result avoids overclaiming reachability.

Small bug fixes and tests can go directly to a pull request.

## Local checks

Use Windows x64 and the .NET 10 SDK:

```powershell
dotnet restore PortCVE.sln --locked-mode
dotnet format PortCVE.sln --verify-no-changes --no-restore
dotnet build PortCVE.sln -c Release --no-restore
dotnet test PortCVE.sln -c Release --no-build
```

NuGet lockfiles are committed. Keep them synchronized with intentional package changes; `--locked-mode` should fail unexpected dependency-resolution drift.

When changing native collection, also compare a live fixture against structured `Get-NetTCPConnection -State Listen` and `Get-NetUDPEndpoint` output. Do not use localized `netstat` text as a parser or test oracle.

For Docker correlation changes, build Release and run `scripts\Test-DockerIntegration.ps1 -ValidateLockCheck`. The script may pull `alpine:3.22` and creates/removes a labeled test container. Its default publications are loopback-only; `-AllowWildcardUdp` intentionally exposes the UDP echo fixture on `0.0.0.0` for the duration of the test.

When changing firewall reasoning, add tests for both the intended match and a near-miss. An unavailable or unsupported predicate must reduce confidence; it must not silently become `allow` or `block`.

## Design rules

- Keep v1 read-only.
- Preserve JSON stdout; diagnostics belong on stderr.
- Never collect process environment variables.
- Do not add command-line collection without a separate privacy design and explicit opt-in.
- Keep external reachability `unknown` unless a future external verifier actually tests it.
- A collector failure is evidence degradation, not proof that an endpoint disappeared.
- Add or update schema fixtures for compatibility changes.
- Isolate Windows interop from correlation and diff logic.

## Pull requests

Include:

- the user-visible behavior;
- tests run and their result;
- Windows version and privilege level used for live checks;
- any known false-positive or false-negative boundary; and
- schema or documentation changes.

Do not include real usernames, hostnames, internal addresses, proprietary firewall rules, credentials, or captured process arguments in fixtures.

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
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\tests\Test-Installer.ps1
```

NuGet lockfiles are committed. Keep them synchronized with intentional package changes; `--locked-mode` should fail unexpected dependency-resolution drift.

When changing native collection, also compare a live fixture against structured `Get-NetTCPConnection -State Listen` and `Get-NetUDPEndpoint` output. Do not use localized `netstat` text as a parser or test oracle.

For Docker correlation changes, build Release and run `scripts\Test-DockerIntegration.ps1 -ValidateLockCheck -ValidateRemoteScan`. The script may pull `alpine:3.22` and creates/removes a labeled test container. Its default publications are loopback-only; `-AllowWildcardUdp` intentionally exposes the UDP echo fixture on `0.0.0.0` for the duration of the test.

For remote-scanner changes, run the loopback-only `scripts\Test-RemoteHostIntegration.ps1` harness. Never use a public, third-party, or local-network target as a release test without explicit authorization from its owner. Run `scripts\Test-Performance.ps1 -EnforceBudgets` when changing collection, planning, concurrency, or serialization paths.

When changing firewall reasoning, add tests for both the intended match and a near-miss. An unavailable or unsupported predicate must reduce confidence; it must not silently become `allow` or `block`.

## Design rules

- Keep local collection and all assessment workflows non-destructive.
- Require explicit authorization for active network assessment, preserve rate/concurrency/time/evidence caps, and never add an unlimited mode.
- Preserve JSON stdout; diagnostics belong on stderr.
- Never collect process environment variables.
- Do not add command-line collection without a separate privacy design and explicit opt-in.
- Keep local listener reachability conservative. A successful `scan-host` TCP connection proves only that exact tested path and observation time, not Internet-wide reachability or exploitability.
- Do not infer CPEs or vulnerability matches from a port number, filename, or untrusted HTTP header.
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

# Remote live validation

`scripts/Test-RemoteHostIntegration.ps1` is a bounded Windows PowerShell 5.1+
integration check for PortCVE's real `scan-host` executable path. It does not
scan an Internet or LAN address.

## Run it

From the repository root:

```powershell
.\scripts\Test-RemoteHostIntegration.ps1
```

The default run builds `src\PortCVE\PortCVE.csproj` in Release and uses
`src\PortCVE\bin\Release\net10.0\win-x64\portcve.exe`. A previously built
Release executable can be tested explicitly:

```powershell
.\scripts\Test-RemoteHostIntegration.ps1 `
  -SkipBuild `
  -PortCVEPath .\artifacts\win-x64\portcve.exe
```

The harness emits one JSON result only after listener, process, and temporary
file cleanup succeeds. Its static PowerShell 5.1 safety test is:

```powershell
.\scripts\tests\Test-RemoteHostIntegrationHarness.ps1
```

## What it proves

Each run creates two listeners bound explicitly to `127.0.0.1`:

- an SSH fixture on an OS-assigned temporary port, returning an
  `OpenSSH_9.6p1` identification string;
- a silent HTTP fixture on a separate OS-assigned temporary port, returning
  `Server: Apache/2.4.58` only after a request and logging request lines.

PortCVE is invoked with `--authorized` and `--ports` containing exactly those
two selected ports. The harness checks:

- both endpoints are reported open;
- the discovery profile sends no bytes to the nonstandard HTTP fixture and does
  not invent an application identity for it;
- the safe-active profile uses a fresh connection, sends exactly one
  `HEAD /`, records the `active-adaptive-http-head` evidence source, and parses
  Apache `2.4.58`;
- no method or path beyond the exact adaptive `HEAD /` reaches the fixture;
- default discovery and active JSON remove the target, address, and raw
  banner/header evidence;
- `--include-private` discovery retains the SSH evidence, while private active
  output also retains the adaptive HTTP header evidence;
- every CLI/build process has a timeout and is killed if it outlives it; and
- listeners and a uniquely named, verified system-temp directory are cleaned
  in `finally` blocks.

This end-to-end harness exercises the bounded adaptive fallback on a real
nonstandard port. Its first connection is greeting-read-only. Active mode then
uses one fresh connection for `HEAD /` and stops immediately when valid HTTP is
confirmed; it does not add `OPTIONS`, endpoint probes, or TLS. TLS fallback is
attempted only when adaptive HTTP is not confirmed, and HTTPS additionally
requires HTTP/1.1 ALPN. The harness passes only its two exact OS-assigned ports
to PortCVE; it never performs a range or common-port scan.

## Claim boundary

This validates loopback TCP discovery, adaptive HTTP fingerprinting on an
OS-assigned nonstandard port, output privacy modes, and cleanup on the tested
Windows host. It does not validate the separate adaptive TLS branch. It also
does not prove external reachability, CVE applicability, exploitability,
authorization for another target, or every remote service. The harness never
enables NVD enrichment and does not send credentials or exploit attempts.

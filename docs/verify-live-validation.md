# Scanner-to-owner live validation

Harness added and passed: 2026-08-10.

Run the local-only integration harness from the repository root:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\scripts\Test-ExposureVerificationIntegration.ps1
```

The harness does not scan a host. It opens one OS-assigned IPv4 wildcard TCP
listener on the machine running the test and imports three bounded synthetic
files:

- Nmap XML says that the matching TCP port was open on the documentation-only
  address `192.0.2.10`;
- Nuclei JSONL reports a synthetic CVE match on that endpoint; and
- Nessus XML reports the same synthetic CVE from a distinct scanner record.

`portcve verify` is run twice with `--strict --no-firewall`: once with default
redaction and once with `--include-private`. Both runs must return exit code
`0`. The harness asserts explicit `reduced`/`private` privacy modes, one
`correlated_open` endpoint, one CVE group with two private source-record
hashes, masked default hashes, Nuclei and Nessus provenance, `not_assessed`
exploitability, default target/vantage/address redaction, and private
target/vantage/address/file-name retention. It also checks that no connection
reached the listener, demonstrating that this workflow consumed evidence and
local socket state without probing the synthetic target or its local fixture.

The companion safety test parses the harness without executing it:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\scripts\tests\Test-ExposureVerificationHarness.ps1
```

It rejects arbitrary target parameters, scanner and web-request commands,
online advisory flags, unbounded child processes, restore-capable builds, and
unguarded cleanup. The Release build inside the live harness uses
`dotnet build --no-restore`; restore dependencies separately before running it
in a clean checkout.

## Validation evidence

On 2026-08-10, the static safety test passed all 40 checks and the Release
`win-x64` build completed successfully. Both strict runs returned exit code `0`.
The live run found the OS-assigned wildcard listener, its `powershell.exe` owner
with SHA-256 identity, one grouped synthetic CVE, and two distinct Nuclei/Nessus
source observations. Default redaction and private retention passed, the
listener accepted zero connections, and guarded cleanup removed the fixture and
temporary directory.

The host's process-owner collector was globally partial because metadata was
unavailable for unrelated protected or short-lived endpoints. Verification
scoped owner and bind completeness to the selected matching listener while
still requiring a complete socket table. This let the strong selected owner
pass without converting unrelated weak owners into evidence for the selected
port.

## Limits

This validates a same-port TCP correlation on one Windows host. The Nmap,
Nuclei, and Nessus inputs are synthetic and make no vulnerability-applicability
claim. The test does not validate NAT port mappings, UDP, firewall-policy
correlation, Docker ownership, external reachability, packet-path identity,
current CVE applicability, or exploitability. Strict success still requires a
complete socket table and sufficient owner, bind-scope, and requested firewall
evidence for every selected matching listener.

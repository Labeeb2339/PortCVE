## Purpose

Describe the user-visible problem and the evidence contract this change affects.

## Safety and compatibility

- [ ] No command gained implicit network access, privilege escalation, destructive behavior, or a weaker authorization gate.
- [ ] Privacy-reduced output and `--include-private` behavior were reviewed.
- [ ] Incomplete evidence still fails closed for `--strict` and finding gates.
- [ ] Versioned JSON/schema or CLI compatibility changes are documented and tested.
- [ ] New third-party actions and dependencies are pinned and justified.

## Verification

- [ ] `dotnet restore PortCVE.sln --locked-mode`
- [ ] `dotnet format PortCVE.sln --verify-no-changes --no-restore`
- [ ] `dotnet build PortCVE.sln -c Release --no-restore`
- [ ] `dotnet test PortCVE.sln -c Release --no-build --no-restore`
- [ ] Relevant PowerShell/live harnesses passed, or the omission is explained below.

Sanitized evidence and omitted gates:

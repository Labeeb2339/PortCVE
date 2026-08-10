## What changed

Explain the problem and the user-visible change.

## Safety and compatibility

- [ ] Any new network access, privilege requirement, or destructive behavior is documented.
- [ ] Default and `--include-private` output were reviewed for sensitive data.
- [ ] `--strict` and finding gates still fail when required data is incomplete.
- [ ] CLI or JSON schema changes are documented and tested.
- [ ] New dependencies and GitHub Actions are pinned and justified.

## Verification

- [ ] `dotnet restore PortCVE.sln --locked-mode`
- [ ] `dotnet format PortCVE.sln --verify-no-changes --no-restore`
- [ ] `dotnet build PortCVE.sln -c Release --no-restore`
- [ ] `dotnet test PortCVE.sln -c Release --no-build --no-restore`
- [ ] Relevant PowerShell/live harnesses passed, or the omission is explained below.

Notes, omitted checks, or sanitized test data:

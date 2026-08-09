# Security policy

## Supported versions

PortCVE is currently alpha software. Only the latest tagged release receives security fixes.

## Report a vulnerability

Please use the repository's private **Security > Advisories > New draft security advisory** flow. Do not open a public issue for a vulnerability that could expose users or their local machine data.

Include the affected version, Windows version, privilege level, reproduction steps, impact, and the smallest safe proof of concept. Redact usernames, hostnames, internal addresses, tokens, proprietary rule names, and unrelated local process data.

## Security boundaries

PortCVE parses local OS data that may change while it is being read. Its output is evidence, not an authorization decision or guarantee of network reachability.

The current release:

- is read-only;
- performs no remote scan or external probe;
- sends no telemetry or reputation request;
- does not read process environment variables or command lines;
- invokes Windows PowerShell only with bundled constant scripts and no user-controlled script interpolation; and
- may return partial metadata for protected or rapidly exiting processes.

Do not run a binary from an untrusted source merely to inspect it. PortCVE inspects running local endpoints; it is not a malware sandbox.

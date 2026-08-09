# Threat model and claim boundaries

## Assets

- Accurate local endpoint inventory
- Correct owner and bind-scope attribution
- Privacy of local process and network metadata
- Integrity and portability of baseline files
- Honest confidence and limitation reporting

## Trusted inputs

Windows kernel and service APIs, local adapter state, local Docker Engine responses, and merged Windows Firewall CIM objects are treated as evidence sources. They are not assumed immutable during collection. Docker responses describe runtime-declared publications and are not treated as direct Windows socket ownership. Firewall CIM objects describe configuration; they are not treated as a live packet-classification oracle.

Lockfiles are user-provided data. Their schema is validated before comparison, but they are not signed in the current release.

## In scope

- Buffer-size races while native endpoint tables change
- Processes exiting or PIDs being reused during collection
- Access denied for protected processes or policy data
- Duplicate/reused UDP binds
- Conflicting allow and block rules
- Conditional firewall rules and unsupported tokens
- Docker Engine absence, access denial, timeout, invalid response, or API failure
- Ambiguous or unmatched Docker publication-to-host-socket tuples
- JSON stdout contamination
- Accidental storage of PIDs, timestamps, usernames, paths, or arguments in privacy-reduced lockfiles
- Accidental disclosure of local addresses, process/container identities, image references, paths, firewall-rule details, or diagnostic text in redacted snapshots
- Unexpected domain/network lookup when resolving account SIDs

## Out of scope

- A compromised Windows kernel or administrator falsifying local evidence
- Malware evading observation or changing behavior after collection
- Third-party WFP filters not represented by Windows Firewall rules
- Proving that a correlated Docker publication owns the Windows socket or identifying the process inside the guest
- WSL guest-process or Kubernetes workload attribution
- Router, NAT, VPN gateway, cloud security group, or remote-host behavior
- Proving that a port is reachable from the Internet
- Safely executing an untrusted binary

## Safe failure rules

- Missing evidence produces `partial`, `not_collected`, `unknown`, or `mixed`; never an invented clean result.
- UDP is called `bound`, not necessarily listening for incoming datagrams.
- Static firewall reasoning says `static host policy indicates allow` or `static host policy indicates block`, not `Internet reachable`.
- Static firewall results always carry confidence and limitations and do not claim that WFP or a remote path accepted a packet.
- Docker publication correlation is always medium confidence. An unmatched publication produces a diagnostic and never a synthetic listener.
- An absent Docker pipe degrades quickly to optional `unavailable` evidence and never starts Docker Desktop or a container. Access denial, timeout, or failed Engine collection cannot become complete container baseline evidence.
- Watch does not report removals from a failed endpoint snapshot.
- V1 never kills a process, closes a socket, changes a firewall rule, or sends a probe.

## Privacy modes

Lockfiles are normalized, privacy-reduced baselines and never contain PIDs, timestamps, account names, command lines, environment variables, full executable paths, raw container IDs/names, or raw image references. When complete Docker image IDs are available, a lockfile can contain a deterministic hash of the correlated image-ID set as owner identity. That hash can still fingerprint a software/image set. Lockfiles also reveal ports, protocols, bind scopes, other owner identities, and policy/completeness metadata. Review them before sharing or publishing.

JSON snapshots are redacted by default, but they are not anonymous. Ports, scopes, process and service names, network profile labels, policy results, and collection metadata remain useful—and potentially sensitive—host facts. The redactor replaces the owning PID with `0` and omits creation time. For Docker publications it replaces container IDs, names, and image references, omits image IDs, and normalizes the host address, while preserving mapping ports, protocol, runtime, confidence, and the fact that a correlation exists. `--include-private` additionally permits collected PIDs/times, interface identities and addresses, paths, parent/account identity, container identifiers/images, firewall rule details, evidence, and diagnostic text to be serialized.

Docker collection uses the local `\\.\pipe\docker_engine` IPC endpoint. It does not contact a TCP Docker endpoint, pull an image, start a container, or execute inside one.

The dated live fixture described in the README validated TCP and UDP echo, independent host-tuple observation, BindWitness correlation, complete container-image lock evidence, an unchanged pass, and `owner_changed` after host-owner replacement. That evidence supports the local integration path only; it does not reduce the external-reachability, guest-ownership, WSL/Kubernetes, or cross-version boundaries above.

Account-name resolution is off by default. `--resolve-accounts` uses Windows `LookupAccountSid`, which can contact a domain controller or global catalog when data is not available locally. This opt-in weakens the otherwise local/offline collection boundary and is documented separately from `--include-private`.

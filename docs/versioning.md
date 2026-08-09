# Versioning and compatibility

Every JSON document and lockfile starts with `schema_version`.

Published schema documents use location-independent URNs:

- `urn:portcve:schema:snapshot:v1`
- `urn:portcve:schema:lock:v1`
- `urn:portcve:schema:vulnerability:v1`
- `urn:portcve:schema:remote:v1`
- `urn:portcve:schema:import:v1`

These identifiers do not imply that a `portcve.dev` website or schema host exists.

The `v0.1.0-alpha.1` release used `bindwitness.*.v1.schema.json` filenames, `urn:bindwitness:schema:*:v1` identifiers, and a `bindwitness/<version>` `created_by` value. The pre-1.0 PortCVE rename changes those brand identifiers without changing the JSON instance shape or `schema_version: 1`. Existing alpha lockfiles remain readable because compatibility is determined from `schema_version` and the document fields; consumers that pinned an old schema filename or `$id` must update that reference.

Before `1.0`, incompatible schema changes require a schema-version increment and a changelog entry. Readers reject unknown lockfile schema versions instead of guessing.

After `1.0`:

- patch releases may add diagnostics or fix incorrect values without changing required fields;
- minor releases may add optional fields and enum values; and
- removing or changing a field requires a new schema version and migration notes.

Consumers must inspect `schema_version` before parsing. Snapshot consumers may handle unknown optional fields defensively, but schema validation for a declared version remains authoritative. Lockfile readers reject unknown schema versions and unsupported selector or enum values rather than guessing. Never parse the human-readable table as an API.

Lockfiles deliberately omit volatile and private values. V1 includes `includes_udp`, the port/protocol `selector`, ownership/bind/policy/container `evidence` completeness, `owner_identity_strength`, and `host_policy_confidence`. Container-correlated endpoints can use a deterministic hash of the sorted distinct image-ID set with strength `container_image`; raw container IDs, names, and image references are omitted. Two captures of the same normalized endpoint set, selector, UDP choice, evidence class, normalized owner identity, and tool version produce the same lockfile content.

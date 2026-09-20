# Security design

Extracted from the [RepoBeacon project description](project-description.md), version 1.0. This document specifies proposed behavior; implementation is pending.

## 17. Security and operational considerations

**Untrusted repository execution.** Discovery and default scanning must not run installation hooks, tests, build scripts, Docker builds, or template plugins. Approved builds run in ephemeral workers with read-only inputs where possible, bounded writable storage, minimal environment variables, and restricted network access. Protect against symlink escapes, path traversal, oversized archives, and resource exhaustion.

**Trusted configuration.** A target repository cannot supply a new scanner executable, enable cloud AI, choose an exfiltration endpoint, or disable enforced checks. Ignore or explicitly reconcile scanner-native configuration and inline suppressions according to trusted policy; report effective exclusions. Exceptions require an owner, rationale, scope, expiry, and audit trail.

**Scanner supply chain.** Pin and verify scanner binaries, images, query packs, and rules against approved manifests. Prefer upstream signatures or attestations when available and an independently trusted checksum source otherwise. Qualify updates before promotion; support revocation of a compromised release. Separate dependency-update permissions from scan execution permissions.

**Credential and evidence handling.** Use minimal repository and registry credentials, pass them through approved mechanisms, and redact process output. Never inherit all developer or CI secrets into workers. Enable scanner redaction at the source and apply a second redaction boundary before persistence. Store sensitive artifacts under restrictive permissions with retention and deletion policies. A suspected exposed secret requires rotation/revocation guidance, not just deletion from source.

**Container and Kubernetes access.** Prefer image archives or registry retrieval without mounting a host Docker socket. Scanning an image must not run its entrypoint. Future live-cluster scanning uses explicit context selection, scoped read-only RBAC, and a separate authorization path; never silently use the current kubeconfig context.

**Network and privacy.** Inventory tool telemetry, rule downloads, database updates, registry pulls, advisory lookups, and AI requests. Disable telemetry by default. Record allowed destinations and database freshness; an offline run cannot silently fall back to cloud services. Treat exported reports as sensitive engineering information.

**Output safety.** Escape all repository and scanner text in HTML, sanitize terminal control sequences, restrict link protocols, and avoid external report assets. Parse scanner outputs with limits and schema checks. Raw results are untrusted input even when produced by an approved scanner.

**Policy reliability.** Preserve unknown severity and reachability. Do not automatically lower priority merely because no exploitability evidence is available. Keep technical severity separate from operational priority. Report both security-policy failure and incomplete execution, and prevent an optional AI response from affecting release decisions.

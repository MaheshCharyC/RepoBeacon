# Security policy

## Project status

RepoBeacon has an initial 0.1.0 scanner implementation. It has not completed production hardening or platform certification. No private vulnerability-reporting channel has been established.

The source snapshot and filtered subprocess environment reduce accidental exposure, but they are not an operating-system sandbox. Use an isolated worker for hostile repositories. Network isolation, scanner binary attestation, and centrally enforced suppression policy remain release-hardening requirements. See the [implementation limitations](docs/usage.md).

## Reporting a concern

Do not publish credentials, exploit-ready sensitive artifacts, or private repository content in public issues. Use a verified private contact for the repository owner if one is available. Before the first public release, maintainers must establish and document a private reporting channel, supported versions, and response expectations.

Do not assume that an unpublished email address or reporting service exists.

## Design requirements

The [security design](docs/security-design.md) covers untrusted repository execution, scanner supply chains, policy precedence, sensitive evidence, container and cluster access, network controls, and report rendering.

Findings and AI-generated explanations must remain distinct. AI cannot approve suppressions, alter release policy, or execute repository instructions.

## Release gate

Before publishing an executable, establish signed or otherwise verifiable releases, qualified scanner versions, dependency review, redaction tests, isolated worker controls, and a documented vulnerability response process.

# Documentation index

**Implementation:** Read [Usage and current behavior](usage.md) first. Version 0.1.0 is implemented in Python. The original design below remains the roadmap; its planned Go stack, commands, and acceptance criteria are not all implemented.

See [CodeQL setup and automatic scanning](codeql.md) for automatic installation, updates, language detection, and build options.

The [project description](project-description.md) is the authoritative version 1.0 specification, dated 19 September 2026. The focused documents below reproduce its sections for easier implementation and review. When changing requirements, update the master document and the corresponding focused document together.

| Document | Contents |
| --- | --- |
| [Product scope](product-scope.md) | Overview, names, users, goals, non-goals, coverage |
| [Scanner evaluation](scanner-evaluation.md) | Tool comparison, default stack, CodeQL policy |
| [CLI specification](cli-specification.md) | Commands, profiles, offline behavior, exit codes |
| [Architecture](architecture.md) | Components, adapters, platforms, workflow |
| [Finding schema](finding-schema.md) | Canonical data model, example, fingerprints, correlation |
| [Reporting and AI](reporting-and-ai.md) | Executive and technical outputs, evidence-grounded AI |
| [Implementation design](implementation-design.md) | Technology choices and proposed source layout |
| [MVP](mvp.md) | Initial coverage and acceptance criteria |
| [Roadmap](roadmap.md) | Delivery phases and exit gates |
| [Security design](security-design.md) | Trust boundaries and operational safeguards |
| [AI development](ai-development.md) | Implementation sequence and review expectations |

All command examples and implementation details are proposed behavior. No functioning scanner, release, or benchmark is implied by this documentation.

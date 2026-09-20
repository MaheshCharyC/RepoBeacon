# CLI specification

Extracted from the [RepoBeacon project description](project-description.md), version 1.0. This document specifies proposed behavior; implementation is pending.

## 7. CLI experience

After installation and scanner provisioning, the primary workflow is:

```text
repobeacon scan .
```

This discovers applicable inputs, runs the standard profile, writes HTML and JSON reports, and prints a concise summary with coverage status. First-run provisioning is separate from scanning so CI does not silently download or execute unreviewed tools.

Proposed commands work in PowerShell and common Unix shells without shell-specific continuation syntax:

```text
repobeacon doctor
repobeacon tools install --profile standard
repobeacon scan . --profile standard --output ./security-report
repobeacon scan "C:\work\payments" --output "C:\reports\payments"
repobeacon scan /home/dev/payments --format html,json,sarif,markdown
repobeacon scan . --profile deep --codeql auto
repobeacon scan . --secrets-history all
repobeacon scan . --image registry.example.com/team/app:release
repobeacon scan . --baseline ./previous/findings.json --fail-on high --new-only
repobeacon scan . --offline --ai off
repobeacon scan . --ai local
repobeacon scan . --ai cloud --ai-policy ./approved-ai-policy.yaml
repobeacon scan . --sbom cyclonedx --license-policy ./license-policy.yaml
repobeacon scan https://github.com/example/project.git --ref release-v1
```

The last command is a later-phase feature. Resolve remote refs to immutable commits; record image digests when tags are supplied. Authentication uses credential helpers or an approved secret store, never credentials embedded in command-line URLs.

**Profile semantics:** `standard` uses the default open-source stack. `deep` additionally attempts eligible CodeQL analysis and configured advanced checks. `auto` never overrides licensing, build trust, or network policy. `--offline` requires pre-provisioned rules and databases, blocks network activity, and disallows cloud AI.

**Proposed exit codes:** `0` = required coverage completed and policy passed; `1` = completed assessment failed finding policy; `2` = assessment incomplete or execution/configuration failure. Exit `2` takes precedence when both findings and coverage failures exist. Reports retain separate `execution_status` and `policy_status` fields so automation can distinguish causes. Optional skipped checks remain visible even when exit code is `0`.

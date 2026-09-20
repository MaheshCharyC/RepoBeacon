# Local validation record

Validated on macOS ARM64 with Python 3.12.6. Scanner versions and downloaded archive digests are recorded in [tested-tools.json](tested-tools.json).

## Automated checks

`REPOBEACON_INTEGRATION=1 .tools/venv/bin/python -m unittest discover -s tests -v` passed all 26 tests, including real Semgrep and Gitleaks execution. Other checks cover parser behavior, native failures, timeouts, output limits, source snapshots, credential environment filtering, AI response validation, baseline gating, and HTML escaping.

The real Gitleaks test inserted a synthetic credential into a temporary file, confirmed a secret finding, and verified that the value appeared in neither the console nor any of the seven generated artifacts.

## Full scanner run

```text
.tools/venv/bin/repobeacon scan testdata/vulnerable --output work/full-validation --cache .cache/trivy --timeout 180
```

Semgrep, Gitleaks, and Trivy all completed successfully. The synthetic target produced 30 unique findings: 8 high, 10 medium, and 12 low. Exit code 1 correctly indicated the finding-policy failure. The bundled Semgrep checks accounted for five findings.

A second scan using that report as a baseline, `--new-only`, and cached Trivy data completed with the same 30 existing findings and exit code 0. No findings were removed from its reports.

Generated assessment JSON passed the checked-in JSON Schema using `jsonschema`; summary totals matched the finding arrays. Documentation links were checked.

## Limits of this evidence

Counts depend on scanner rules and database versions and are not a permanent expected Trivy count. The original validation used SARIF fixtures for CodeQL; live provisioning and scanning were subsequently validated as recorded below. AI protocol validation used controlled responses, not a live model provider. Windows and Linux CI jobs are configured but were not executed from this local session. Container image retrieval and archive scanning are implemented but were not validated against a real image in this session.

The application is a runnable initial implementation, not a production security certification or completion of every roadmap item.

## CodeQL automatic setup and language detection — 19 September 2026

With Python 3.12.14 on macOS ARM64, the current suite ran 48 tests: 45 passed, and three opt-in integration tests were skipped. New tests cover latest-release selection, platform matching, reuse, install/upgrade/repair, checksum rejection, safe archive extraction, preserving the previous installation after failure, local verification without network checks, language grouping, build permission, snapshot executable modes, and incomplete reports after setup errors.

The real installer downloaded the official macOS CodeQL 2.27.0 bundle, checked its size and SHA-256 against GitHub release metadata, extracted it, and verified its version, language extractors, and query packs. The validation installation is in the ignored `.tools/codeql-validation` directory, separate from the normal user cache.

```sh
REPOBEACON_CODEQL_INTEGRATION=1 REPOBEACON_CODEQL_TEST_ROOT=.tools/codeql-validation .venv/bin/python -m unittest discover -s tests -p test_integration.py -v
```

The dedicated CodeQL integration test passed in approximately 33 seconds. A synthetic Python/TypeScript project was detected as `python` and `javascript`, extracted into separate databases, and analyzed using the security-extended suites. Both runs completed successfully, with zero findings and exit code 0. No update or download was performed during that scan. The two unrelated real-scanner tests were skipped in this invocation.

Other CodeQL language families and trusted autobuild execution have unit coverage but have not been validated with real toolchains in this session. The live test used a small clean fixture; it does not establish vulnerability detection accuracy or large-repository performance.

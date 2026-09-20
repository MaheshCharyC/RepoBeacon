# Contributing to RepoBeacon

## Current stage

RepoBeacon has a Python 0.1.0 implementation. Read the [usage guide](docs/usage.md) for implemented behavior and the [project description](docs/project-description.md), [MVP](docs/mvp.md), and [security design](docs/security-design.md) for the broader design.

## Implementation sequence

1. Define and validate the assessment schema, adapter contract, and execution-status model.
2. Implement repository discovery without executing repository code.
3. Build one scanner adapter and deterministic reports end to end.
4. Add remaining MVP adapters with provenance, redaction, cancellation, and error handling.
5. Add baseline comparison, trusted policy, and cross-platform integration coverage.
6. Add optional AI reporting after deterministic report correctness is established.

The current implementation lives in `repobeacon/`, with automated tests in `tests/` and synthetic scan targets in `testdata/`. The original Go layout remains a proposal, superseded for this implementation by the Python package. Runtime Python dependencies are limited to the standard library; scanner binaries are installed separately.

## Change expectations

Keep changes focused and document behavior changes. Preserve scanner evidence, identify unsupported coverage, and avoid treating scanner failures as clean assessments. New adapters must declare supported inputs, platform prerequisites, network access, output formats, and repository-code execution requirements.

Use synthetic fixtures only. Never commit real secrets, private repository snapshots, scanner databases, or generated customer reports.

## Validation

Once implementation begins, validate schema compatibility, native scanner exit-code handling, malformed output, timeouts, redaction, policy outcomes, and platform behavior. The MVP requires Windows, Linux, and macOS coverage.

Run `python -m unittest discover -s tests -v`. Install the CLI with `python -m pip install -e .`. Real scanner validation must also check the synthetic target and record scanner versions. Never execute the deliberately vulnerable fixtures.

## Documentation updates

Keep the master project description and focused documents consistent. Distinguish proposed features from implemented behavior, cite upstream sources for scanner capabilities, and record material changes to licensing or compatibility assumptions.

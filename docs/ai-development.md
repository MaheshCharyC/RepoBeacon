# AI-assisted implementation

Extracted from the [RepoBeacon project description](project-description.md), version 1.0. This document specifies proposed behavior; implementation is pending.

## 18. Guidance for AI-assisted implementation

Build the product in small, verifiable slices. First define the canonical schema, adapter contract, execution-status model, and golden report fixtures. Next implement discovery and one scanner adapter end to end, including malformed output and timeout handling. Add subsequent scanners only after the first pipeline produces reproducible reports.

Use AI coding assistance to scaffold adapters, generate synthetic fixtures, draft documentation, and propose report copy. Require review for process execution, network access, redaction, fingerprints, policy precedence, and licensing assumptions. Never include real credentials or private customer repositories in test fixtures.

The first reviewable milestone is a local command that produces a traceable finding, a visible coverage result, and matching executive/technical output. The MVP is complete when the acceptance criteria in this document pass across the certified platform matrix, including failure and privacy tests.

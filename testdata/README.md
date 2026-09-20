# Synthetic scan targets

The `vulnerable` directory contains deliberately insecure static examples for scanner validation. Do not execute the source, install its dependencies, build its image, or deploy its Kubernetes manifest. RepoBeacon reads these files without performing those actions.

Expected bundled Semgrep detections: Python eval, shell execution, disabled TLS verification, JavaScript eval, and HTML assignment. Trivy findings depend on its installed rules and vulnerability database.

Tests generate synthetic secret records in memory; no actual credentials are stored here.

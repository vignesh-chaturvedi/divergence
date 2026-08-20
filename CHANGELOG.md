# Changelog

All notable changes will be documented here. This project follows Semantic Versioning.

## 1.1.0 — release candidate

- Adds a fail-closed Linux dynamic observation tier. The verified arm64 gate recovers
  24/25 obfuscated positives with all five controls clean; the full dynamic row reaches
  49/50 recall with 0/35 trap false positives and per-sample coverage metadata.
- Adds an opt-in, provider-neutral adjudication command with a hard five-percent selector cap.
- Makes `label.malicious` the benchmark source of truth and expands the synthetic corpus
  to 110 artifacts, including 25 obfuscated positives and five matched controls.
- Adds deterministic benchmark provenance, raw counts, and Wilson 95% intervals.
- Renames the PyPI distribution to `divergence-mcp`; the command remains `divergence`.
- Bundles the labelled corpus in the wheel so `divergence-bench` works outside a checkout.
- Hardens the composite Action and release-candidate checks.
- Adds a candidate workflow configured to produce a checksummed Linux x86-64 sandbox runner
  and containment evidence alongside Python artifacts without publication permission.
- Tracks the generated all-strata static, dynamic, and pinned external candidate evidence
  under `benchmarks/v1.1/`; unavailable hosted scanners remain explicit.

Local release engineering is complete. This version has not been independently certified,
published, or tagged. Independent label/rationale review, Linux x86-64 candidate
reproduction, the non-author clean-install/scan/issue gate, and protected tag/PyPI/GitHub
publication remain; see `docs/RELEASING.md`.

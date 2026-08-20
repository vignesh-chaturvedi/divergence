# P6 — publish v1.1

## Objective

Publish a reproducible `divergence-mcp` 1.1.0 release with a final all-strata benchmark,
an honest static-versus-dynamic writeup, and an independent-user issue.

## Local readiness

- Distribution identity, bundled corpus, metadata, candidate workflow, benchmark truth,
  scanner versions, raw counts, and Wilson intervals are implemented locally.
- The candidate corpus is 110 fixtures (50 positive, 60 benign/control), including 30
  obfuscated fixtures (25 positive, five controls). Generated static, dynamic, and external
  evidence is tracked under `benchmarks/v1.1/`.
- ADR 0011 closes the reopened P5 gate on verified unprivileged Linux arm64 evidence:
  24/25 obfuscated positives recovered, all five controls clean, and per-sample coverage.
- Publication is deliberately absent from repository automation until trusted publishing
  and the protected release environment are configured.
- The manual candidate workflow still has to reproduce the Linux x86-64 sandbox artifact.

## Formal completion gates

- An independent human reviews the corpus labels and rationales. Any correction is followed
  by regenerated and re-reviewed benchmark evidence.
- The manual candidate workflow reproduces the sandbox checks and artifact on Linux x86-64.
- Someone other than the author installs the candidate in a clean environment, scans a real
  configuration, and files a GitHub issue. This is the locked specification exit gate.
- A protected release owner rechecks the package name, creates the signed tag, publishes to
  PyPI, and creates the GitHub release with the reviewed evidence and checksums.

The release is not complete before all four have durable evidence, even if every local
automated check passes.

## Ticket status

- 01 — resolved locally: fail-closed containment verified on Linux arm64; x86-64
  reproduction remains in the release workflow.
- 02 — resolved locally: generated candidate evidence is tracked under `benchmarks/v1.1/`.
- 03 — open, `ready-for-human`: complete the non-author install/run/issue exit gate.
- 04 — open, `ready-for-human`: perform protected tag, PyPI, and GitHub publication.
- 05 — implementation complete, `ready-for-human`: independently review all corpus labels
  and rationales; regenerate issue 02 evidence if review changes the dataset.
- 06 — open, `ready-for-human`: reproduce the sandbox gate and distributable artifact on
  Linux x86-64 through the manual candidate workflow.

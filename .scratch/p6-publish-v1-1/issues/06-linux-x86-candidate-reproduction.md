# Reproduce the Linux x86-64 candidate

Status: ready-for-human

Run the manual `release-candidate` workflow from the reviewed release commit. Preserve the
Linux x86-64 kernel probe, Rust format/Clippy/test output, containment-gate log, sandbox
binary, archive, and both SHA-256 files. Confirm the installed-wheel smoke uses the same
commit and corpus digest as `benchmarks/v1.1/`.

## Comments

The local fail-closed evidence is from unprivileged Linux arm64. It closes the local P5
gate but does not manufacture architecture-specific release evidence. This ticket must be
completed before protected publication and cannot be resolved by a macOS-only check.

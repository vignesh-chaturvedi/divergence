# ADR 0011 — Close P5 on verified fail-closed sandbox evidence

**Status:** accepted · **Phase:** P5 closure / P6 candidate · **Date:** 2026-08-20

## Context

ADR 0008 reopened P5 after boundary tests disproved ADR 0007's containment conclusion.
The ptrace-only child inherited ambient environment values and retained real network
egress. That earlier 4/5 diagnostic result was unsafe and is not release evidence.

The hardened runner and its Python driver have now been tested on an unprivileged Linux
arm64 environment against the final 30-sample obfuscated stratum. The locked P5 exit gate
requires recovery of at least half the obfuscated positives missed by static analysis and
observed coverage with each result.

## Decision

P5 is closed for the v1.1 release candidate on the following fail-closed contract:

- the runner refuses root and verifies the child uses an unprivileged identity;
- the driver clears the ambient environment, constructs an allowlist, and assigns a private
  `HOME` containing only exact planted decoys;
- Landlock ABI v4 confines filesystem access and TCP bind/connect operations;
- seccomp independently denies disallowed networking, escape, and process-control calls;
- ptrace records attempted operations and their normalized capability results without
  allowing instrumentation to become an artifact finding;
- time, memory, file-size, descriptor, and process limits are applied, and the full process
  group plus staged resources are cleaned on success, timeout, or failure;
- unavailable, timed-out, boundary-failed, and entrypoint-not-reached states remain explicit.
  No such state is converted into successful `B_dynamic` evidence.

The specification proposed a private network namespace with a sinkhole. The unprivileged
Docker environment used for the arm64 verification returned `EPERM` when creating that
namespace. P5 does not treat this as an invisible downgrade: the probe reports the namespace
as unavailable, while Landlock ABI v4 and seccomp independently enforce verified denial of
real egress and listening. Ptrace still records the attempted operation. If neither denial
layer can be installed and verified, the dynamic tier fails closed as unavailable.

This decision therefore accepts a verified deny-and-observe boundary as the safe network
mechanism; it does not restore ptrace-only containment and does not claim a sinkhole was
present where the kernel prohibited it.

## Gate evidence

- Obfuscated recovery: **24/25 (96%; Wilson 95% CI 80.5%–99.3%)**.
- Matched obfuscated controls: **5/5 clean**.
- Static analysis flags 3/25 obfuscated positives; the registered static+dynamic union
  flags 25/25, eliminating all 22 static misses in the stratum.
- Full `divergence+dynamic` row: **0/35 trap false positives**, **49/50 recall
  (98%; Wilson 95% CI 89.5%–99.6%)**, **100% precision**, **87.8% attribution**.
- Confirmed runtime entrypoints: **83/110**; coverage and failure state are serialized per
  sample in the tracked JSON evidence under `benchmarks/v1.1/`.
- Rust formatting, Clippy with warnings denied, unit tests, kernel probes, and the recovery
  gate passed on Linux arm64.

## Platform and release consequences

This is Linux arm64 evidence, not a cross-platform containment claim. macOS and unsupported
platforms report dynamic analysis unavailable and may continue static-only. The manual
candidate workflow must reproduce the checks and build the distributable sandbox runner on
Linux x86-64 before publication.

P5 closure does not complete P6. Independent corpus label/rationale review, the locked
non-author clean-install-and-issue gate, and protected tag/PyPI/GitHub publication remain
external. No tag or release is authorized by this ADR.

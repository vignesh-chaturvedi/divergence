# ADR 0008 — Reopen P5 and require fail-closed containment

**Status:** superseded for P5 closure by ADR 0011 · **Phase:** P5 · **Date:** 2026-08-20

ADR 0011 closes the reopened P5 gate after verified fail-closed Linux evidence. This ADR's
rejection of the earlier ptrace-only boundary remains authoritative; the unsafe 4/5 run did
not become release evidence retroactively.

## Context

ADR 0007 accepted ptrace supervision as the substance of the dynamic tier and concluded
that containment held. Subsequent boundary testing disproved that conclusion. A traced
child inherited the caller's environment, including credentials, and could reach the real
network. Landlock restricted filesystem access, but it did not isolate networking or
sanitize process state. Observation is not containment.

This is not a documentation caveat. Executing an untrusted artifact with real egress and
inherited secrets is unsafe even when every syscall is recorded.

## Decision

This ADR **supersedes ADR 0007's acceptance of ptrace-only supervision and its
“Containment held” conclusion**. ADR 0007's instrumentation lessons, driver rationale,
and warning about decoy interpretation remain valid.

At adoption, P5 was reopened until the requirements below could be verified. Dynamic
observation must fail closed and may produce benchmark or product
results only when all of these boundaries are established and verified from inside the
child:

- a deliberately constructed environment allowlist, never ambient environment inheritance;
- a network boundary that prevents real egress while still permitting an explicit local
  sink used by inert fixtures;
- filesystem confinement to the staged artifact, driver, runtime dependencies, and planted
  decoys;
- resource and timeout limits, with the full process tree terminated on failure;
- an observation record that distinguishes “ran inside verified boundaries” from
  unavailable, timed out, boundary-unverified, or never reached.

If any boundary cannot be installed or verified, the dynamic tier is unavailable. It must
not fall back to unconfined execution and must not emit `B_dynamic` as though observation
succeeded. Static analysis remains available.

## Platform boundary

Containment verification is Linux-only. macOS and other unsupported platforms must return
a concrete reason and continue static-only. Passing unit tests on macOS does not verify
Linux namespaces, Landlock, ptrace, seccomp, or process-tree cleanup.

## Consequences for results

The earlier “4 of 5 payloads caught” run is historical diagnostic evidence, not a v1.1
release result. It has a small denominator and, more importantly, predates verified
network and environment boundaries. This ADR prohibited a combined static/dynamic headline
until the Linux gate was rerun under the fail-closed implementation, with a raw count,
Wilson 95% interval, and benign-control result.

ADR 0011 records the qualifying rerun: 24/25 obfuscated positives recovered with all five
matched controls clean, plus explicit per-sample coverage and boundary evidence.

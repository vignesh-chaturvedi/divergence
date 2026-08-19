# ADR 0001 — Build the benchmark before the scanner

**Status:** accepted · **Phase:** P0 · **Date:** 2026-08-19

## Context

The spec (§06, §07) inverts the usual order: build the corpus and scoring harness before
any detection code. Existing benchmarks in this space measure recall — can a scanner find
the planted attack. None measures precision against benign artifacts engineered to look
malicious, which is where every shipping scanner falls over (the April 2026 audit: ~78%
false positives, 27 flags, 6 real).

## Decision

P0 ships a labelled corpus and a scoring harness with **no divergence detection code**.
The headline metric is **FPR-on-traps**, not recall or F1. Two reference scanners ship
in-repo: `null` (the floor) and `keyword` (a faithful strawman that reproduces the audit's
failure mode). Third-party scanners are wired as real subprocess adapters but gated behind
`DIVERGENCE_ALLOW_EXTERNAL=1` so `make bench` never executes external code silently.

## Consequences

- Everything downstream is measurable against a fixed baseline from day one.
- The corpus is the moat: 80 samples, each with a written rationale a reviewer can dispute.
- The trap strata (35 of 80) are the contribution — privileged-by-design, imperative
  language, and wildcard/broad-trigger. A scanner is scored on precision here, not coverage.
- Determinism is load-bearing: `make bench` output is byte-reproducible, enforced by test.
  Any future model input (claim extraction in P3) must preserve this or the headline number
  stops meaning anything.

## The wildcard rule

`"*"` in a skill's allowed-tools is routed to **posture**, never risk. The strawman flags
it and pays for it (85.7% FPR on the wildcard trap family). This is deliberate: a competing
benchmark had to withdraw headline scores over exactly this conflation.

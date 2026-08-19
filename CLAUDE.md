# Divergence

A precision-first analyzer for MCP servers and agent skills. It measures the gap
between what an artifact **claims** to do and what it **actually** does —
statically first, then confirmed in a sandbox.

The full build specification is **`build-plan/divergence-spec.html`** (v2, scope
locked). Read it before planning any work. It is the source of truth for scope,
architecture, phase sequence and exit gates — this file does not restate it.

## Status

**P3 complete** (2026-08-19). A5 claim extractor + A6 divergence engine. On the 80-sample
benchmark: **0.0% FPR-on-traps, 100% precision, 96% recall, 98% F1** against the keyword
strawman's 57.1% / 45% / 72% / 55.4%. 18 of 19 attack classes at full recall.
Next: **P4 — fleet and routing analysis (A7)**, then the v1 ship checkpoint.

Three rules that are load-bearing and must not be "simplified" — see `docs/adr/0004`:

- **A5 maps text to a claim, never to a verdict.** That is the only reason a lexical
  extractor is defensible where the keyword strawman is not.
- **`B ⊄ C` raises risk only for high-signal capabilities** (network, credentials, exec,
  eval, delete). Undeclared filesystem and env access go to posture — prose cannot separate
  a todo list from an exfiltrator.
- **Cross-tool instruction needs a directive, not a reference.** "for use with other billing
  tools" is documentation; "route all operations here" is not.

`core/probe.py` is gone — `core/behaviour.py` is the single capability extractor.
`core/pipeline.load()` is the single way to acquire+extract; calling them separately loses
handler attribution.

**The corpus was written and then tuned against.** `tests/test_holdout.py` is the
out-of-sample check and it has already caught one real generalisation failure. Add to it
before trusting a new rule.

Two capability-model rules prevent whole false-positive classes and must not be "simplified":
`Bash` grants everything, and an absent `allowed-tools` is unrestricted rather than empty.
See `docs/adr/0002-deterministic-core-scope.md`.

## Core rule

A finding is the **gap**, not the capability. A shell-execution server executing
shells is not a finding. A shell-execution server that never said it would touch
the network is.

Output splits into two channels that never mix:

- **Posture** — what an artifact *can* do. Non-urgent. Never counts toward the verdict.
- **Risk** — divergence between representations. Only these count toward the verdict.

## Phase discipline

Phases P0–P6 each have an exit gate in §07 of the spec. **Do not start a phase
until the previous gate passes.** The ship checkpoint after P4 is load-bearing:
v1 ships before any Rust sandbox work begins, even if the sandbox looks more
interesting that week.

## Phase reports

At the end of each phase, write an HTML progress report to
`build-plan/reports/phase-NN-<slug>.html`, styled to match `build-plan/divergence-spec.html`
(same fonts, same `:root` palette). Local file only — do not publish it anywhere.
Report what actually landed, what is blocked, and what needs a decision.

## Agent skills

### Issue tracker

Issues and specs live as local markdown under `.scratch/<feature-slug>/`. See `docs/agents/issue-tracker.md`.

### Triage labels

The five canonical triage roles, using their default label strings. See `docs/agents/triage-labels.md`.

### Domain docs

Single-context: `CONTEXT.md` and `docs/adr/` at the repo root. See `docs/agents/domain.md`.

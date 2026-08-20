# Divergence

A precision-first analyzer for MCP servers and agent skills. It measures the gap
between what an artifact **claims** to do and what it **actually** does —
statically first, then confirmed in a sandbox.

The full build specification is **`build-plan/divergence-spec.html`** (v2, scope
locked). Read it before planning any work. It is the source of truth for scope,
architecture, phase sequence and exit gates — this file does not restate it.

## Status

**P4 and the v1 ship checkpoint are complete** (2026-08-19). A7 fleet analyzers cover
shadowing with provenance, relative preference scoring, and toxic-flow analysis. SARIF
2.1.0, the composite GitHub Action, `uvx` distribution, and the benchmark/writeup surface
landed before sandbox work began.

**P5 is locally complete on verified unprivileged Linux arm64** (2026-08-20). The hardened
runner refuses root, clears the ambient environment, installs a private `HOME`, confines
filesystem and TCP access with Landlock ABI v4, applies seccomp denials, records results via
ptrace, plants exact decoys, and cleans up resources and the full process group. Docker did
not permit creation of a network namespace, so the verified boundary used independent
Landlock and seccomp egress denial instead; ADR 0011 records that explicit deviation.

The P5 recovery gate catches **24/25 obfuscated positives (96%; Wilson 95% CI
80.5%–99.3%)**, with all five matched controls clean. The complete hardened row is
**0/35 trap false positives, 49/50 recall (98%; CI 89.5%–99.6%), 100% precision, and
87.8% attribution**. Runtime entrypoints were confirmed for 83/110 fixtures and per-sample
coverage is part of the JSON evidence. Unsupported platforms remain visibly static-only;
the candidate workflow still has to reproduce the Linux x86-64 artifact.

**P6 local release engineering is complete; formal P6 is not.** The final candidate corpus
has 110 synthetic artifacts: 50 risk-positive and 60 benign/control, including an
obfuscated stratum of 25 positives and five controls. Static `divergence` and
`divergence+fleet` both have 0/35 trap false positives, 27/50 recall, and 100% precision;
attribution is 77.8% and 85.2% respectively. Pinned third-party results and all generated
provenance are tracked under `benchmarks/v1.1/`. Python dependency and RustSec audits are
clean, and 384 tests pass with 83.67% branch coverage against the retained 80% threshold.

Pinned baselines on that corpus: Semgrep 1.173.0 with rules SHA-256
`f8b8461199c4d0ac23c0faf60f8b00a50139854d742e5b7374ccde09f81c9afd` has 5/35 trap
false positives, 30/50 recall, and 81.1% precision (seven false positives across all
controls); mcp-shield has 4/21 trap false positives, 1/33 recall, 20% precision, and 66.4%
corpus coverage; the keyword control has 20/35 trap false positives and 27/50 recall.

The remaining P6 gates require humans or protected external state: independent corpus
label/rationale review; a non-author clean install, real scan, and filed GitHub issue; and
the protected tag, PyPI publication, and GitHub release. No tag or publication exists yet.

`snyk-agent-scan` (formerly `mcp-scan`) remains unavailable because it requires a vendor
token and hosted API. It is recorded as unavailable, not scored as zero; see ADR 0006.

Two dynamic-analysis corrections worth keeping — see ADRs 0007, 0008, and 0011:

- **Instrumentation must never appear in the result.** `Command::exec` walking `PATH` put
  `proc_spawn` on every sample in the corpus before a fix.
- **§05 overstates the decoy argument.** A credential manager legitimately reads `~/.ssh`,
  so a decoy read is risk only when credential access was absent from B_static.
- **Observation is not containment.** Ptrace evidence is admissible only after the runner
  establishes and verifies fail-closed environment, filesystem, network, resource, and
  process boundaries.

Three rules that are load-bearing and must not be "simplified" — see `docs/adr/0004`:

- **A5 maps text to a claim, never to a verdict.** That is the only reason a lexical
  extractor is defensible where the keyword strawman is not.
- **`B ⊄ C` raises risk only for high-signal capabilities** (network, credentials, exec,
  eval, delete). Undeclared filesystem and env access go to posture — prose cannot separate
  a todo list from an exfiltrator.
- **Cross-tool instruction needs a directive, not a reference.** "for use with other billing
  tools" is documentation; "route all operations here" is not.
- **Shadowing flags only the weaker-provenance side.** A detector that also condemns the
  artifact being imitated is worse than useless. See `docs/adr/0005`.

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

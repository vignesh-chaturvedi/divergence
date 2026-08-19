# ADR 0003 — What B_s extraction claims, and what it cannot

**Status:** accepted · **Phase:** P2 · **Date:** 2026-08-19

## Context

P1 used a flat sink scan: every capability found anywhere in an artifact was attributed
to the whole artifact. That forced a guard in A2 — suppress the annotation check whenever
any sibling tool might explain a mutation — because otherwise a server exposing an honest
reader beside an honest writer had the reader blamed. The guard cost detections.

## Decision

`core/behaviour.py` parses with tree-sitter (Python, TypeScript, shell), builds a call
graph, and computes the **reachable** capability set per entrypoint. `core/probe.py` is
deleted; two capability extractors would eventually disagree.

Entrypoints are tool handlers (`@mcp.tool()`), skill scripts, and module scope. Module
scope counts because it runs at import — a credential path built as a module constant is
reachable, and calling it dead was simply wrong.

## Consequences

- A2's annotation check is per-tool. The sibling guard remains only as a fallback for
  when attribution genuinely fails (an unparsed grammar, dynamic registration).
- Unreachable sinks are reported separately as posture — unreferenced today, callable
  tomorrow — rather than either incriminating a handler or vanishing.
- Benchmark scores are unchanged at 100% precision / 0% FPR-on-traps / 20% recall. P2
  buys **fidelity**, not recall; recall needs C, which is P3.

## The measured gate

Extraction is scored against hand-verified ground truth on all 80 artifacts
(`make capabilities`), exceeding §07's requirement of 50:

| Metric | Value |
|---|---|
| Precision | 100% |
| Recall | 91.9% |
| False-negative rate | **8.1%** (published, per §11) |
| Exact-set match | 93.8% |

Precision is treated as a hard failure and recall is not, deliberately: over-claiming a
capability manufactures divergence that does not exist, while a miss is a known cost of
static analysis.

## Every false negative is one class

All five misses are a capability reached **through a spawned process** — `ssh` opening a
connection, `pip install` fetching from a registry, `git push` reaching a remote, `sqlite`
writing through SQL. The parser sees the spawn; it cannot follow what the spawned program
does. Nothing static will. This is the case §05 says the sandbox exists for, and it is
recorded per-sample in `sample.yaml` under `capabilities.miss_reason`.

## Precision rules found by hand-verification

Three exclusions on credential-path detection, each of which was producing a false
positive on the security-vocabulary trap family:

- **Docstrings are not paths.** A tool documenting "reads the key at `~/.ssh/id_rsa`" is
  describing itself, not doing it.
- **Interpolated strings are not paths.** `f"sess-{hash(api_key)}"` touches nothing.
- **Anything containing whitespace is not a path.** A real path literal is one token.

## Prose is not code

P1 matched commands anywhere in a skill body, which flagged prose that merely mentioned
`curl`. P2 parses **fenced code blocks** with the matching grammar and ignores prose. This
is correct for code and introduces one known false negative: an instruction written inline
without a fence. Separating "run this" from "people used to run this" is semantic, and
belongs to P3.

## Scope held deliberately

The taint pass is name-based, intra-procedural, and carries provenance back to the
originating parameter. No field sensitivity, no propagation across calls. §04 asks for "a
light taint pass"; the sandbox settles the hard cases.

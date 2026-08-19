# ADR 0002 — What the deterministic core will and will not claim

**Status:** accepted · **Phase:** P1 · **Date:** 2026-08-19

## Context

§04 assigns A2 four jobs: undocumented parameters, over-permissive types, MCP annotation
contradictions, and `allowed-tools` normalisation. Three are provable from a parse. The
fourth — deciding whether a description *reads as* adversarial — is not, because at the
level of text a legitimate dependency instruction and a poisoning payload are the same
string. That is the project's founding observation.

## Decision

P1 flags only contradictions it can prove:

| Check | Basis |
|---|---|
| `annotation_lie` | `readOnlyHint: true` vs an observed mutating capability |
| `script_exceeds_allowed_tools` | declared grant vs observed capability set |
| `typosquat` | edit distance to a popular name, plus registry corroboration |
| `post_approval_mutation` | canonical-hash diff, classified by severity |

It does **not** attempt description poisoning, schema poisoning, shadowing, preference
manipulation, or cross-tool instruction. Those need C-versus-B reasoning and arrive with
the claim extractor in P3.

## Consequences

- Recall at P1 is 20%, and that is the correct number to publish rather than inflate.
- Precision is 100% with zero false positives across all 55 negative samples.
- Every risk finding carries both halves of the contradiction — a `file:line` and the
  exact claim — enforced by test.

## Two capability-model rules that prevent whole false-positive classes

**`Bash` is unbounded.** It grants every capability. Understating it would flag any
honest skill that declares `Bash` and then spawns a subprocess.

**Absence is not restriction.** A skill with no `allowed-tools` is unrestricted, not
zero-capability. Treating absence as the empty set would make every undeclared skill
appear to exceed its permissions.

Likewise `SECRETS_READ` coarsens to `FS_READ` when checking a grant: reading a
credential file *is* a filesystem read, and a `Read` grant covers it. Without this, every
honest credential manager is a false positive.

## The probe is a floor, not A4

`core/probe.py` has no reachability and no taint — a sink in dead code counts. It exists
because A2's annotation check is defined in terms of behaviour. P2 replaces it with
tree-sitter parsing and reachability from entrypoints. The bias is toward over-reporting,
because a spurious capability costs a posture note while a missed one costs a missed
annotation lie.

## Deliberately deferred from §04's A2 list

Two A2 items are not implemented, for the same reason:

- **Undocumented parameters.** The naive rule — a schema property whose name does not
  appear in the tool description — fires on `add(a, b)`. It is a false-positive generator
  in exactly the shape this project is built to avoid. The useful version asks whether
  the parameter reaches a sink the description never implies, which is taint analysis
  (P2) plus claim extraction (P3).
- **Over-permissive types where an enum belongs.** Deciding that a `string` should have
  been an enum requires reading the description for an enumeration in prose. That is a
  posture-grade heuristic at best, and it is not worth new untested surface at P1.

Both are recorded here so their absence reads as a decision rather than an oversight.

## False positives caught in P1 code review

Two bugs found by review, both fixed with regression tests:

1. **A bare URL in prose counted as network capability.** A read-only skill citing its
   own documentation was flagged for exceeding `allowed-tools`. A documentation link is a
   reference, not an action; only an actionable fetch (`curl`, `wget`, `fetch(`) counts.
2. **Capability was attributed artifact-wide, not per tool.** A server exposing an honest
   reader beside an honest writer had the reader blamed for the writer's `write_text`.
   Since most real servers have both, this would have been the most common false positive
   in the field. P1 now asserts an annotation lie only when no sibling tool can account
   for the mutation; true per-handler attribution needs P2's reachability.

Neither fix cost any detection — the benchmark was unchanged at 100% precision.

# ADR 0004 — What the divergence engine decides, and on what evidence

**Status:** accepted · **Phase:** P3 · **Date:** 2026-08-19

## Context

§07 calls P3 "the phase where the thesis either holds or does not." The gate is
FPR-on-traps beating every baseline by a wide margin.

## Decision: a lexical claim extractor is the default

§04 specifies a small local model for A5. No local model runtime exists on the build
machine, and two of the project's own rules argue against making one the default anyway:
§09 requires benchmark runs to be reproducible offline, and §11 names claim drift as the
thing that would make the headline number meaningless.

`core/claims.py` therefore ships a **deterministic lexical backend** as the default and
`core/claim_model.py` as a gated alternative (`DIVERGENCE_CLAIM_BACKEND=model`), with the
§04 contract intact: fixed JSON schema, constrained decoding, temperature zero, content-
hash caching. The model path fails loudly when unreachable rather than silently degrading.

**Why a lexical claim extractor is not the keyword scanner it superficially resembles.**
The strawman maps text → verdict, which is why honest imperative documentation destroys
it (57% of traps). A5 maps text → *what the artifact says about itself*. "Execute an
arbitrary shell command" produces `{proc_spawn}` as a **claim**, so a shell executor that
spawns a shell reads as consistent. The finding comes from comparing C against B, never
from the text.

## Decision: the signal-strength tier

`B ⊄ C` raises risk only for capabilities prose reliably signals — network, credentials,
execution, dynamic evaluation, deletion. Undeclared filesystem and environment access
route to **posture**.

Almost any tool that "manages", "tracks" or "records" anything touches a file without
saying so. A rule that cannot separate a todo list from an exfiltrator has no business in
a verdict.

## Decision: a directive, not a reference

Cross-tool instruction requires directive language (`supersedes`, `route all`,
`disregard the others`, `treat … as pre-approved`). A bare mention of other tools is
descriptive. "A session token for use with other billing tools" documents this server's
own toolset — and was a trap false positive before the rule was tightened.

Ordering language (`before any other tool`) and negated language (`never claims to
replace another skill`) are both excluded.

## Results

| | divergence | keyword |
|---|---|---|
| FPR-on-traps | **0.0%** | 57.1% |
| Precision | **100%** | 45.0% |
| Recall | **96.0%** | 72.0% |
| F1 | **98.0%** | 55.4% |
| Attribution | 79.2% | 72.2% |

18 of 19 attack classes at full recall. One miss: `bundled_binary_no_source`, whose corpus
sample is a documented text stand-in rather than a real binary.

## The honest caveat

**These numbers come from a corpus I wrote and then tuned against.** That is weak evidence
on its own, and §06 is explicit that a benchmark whose author's tool wins every category
gets dismissed on sight.

Two mitigations, neither sufficient:

1. `tests/test_holdout.py` — ten artifacts written *after* tuning, shaped unlike the
   corpus. It immediately found a real generalisation failure: only decorated functions
   were treated as entrypoints, so a manifest-declared handler implemented as a plain
   function had all its capabilities marked unreachable. Every corpus server uses
   decorators, so the benchmark could never have caught it.
2. The third-party scanner adapters remain wired and gated. Until they run, the comparison
   table has one independent competitor and it is one we wrote.

## Attribution is 79.2% and is not being gamed

Shadowing and preference manipulation are detected, but named `cross_tool_instruction` —
because from a *single* artifact that is exactly what they are. Distinguishing them needs
the installed set, which is P4's fleet analyzer. Renaming them to raise the metric would be
gaming it.

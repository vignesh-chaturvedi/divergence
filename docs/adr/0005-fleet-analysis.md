# ADR 0005 — Cross-artifact analysis, and not condemning the original

**Status:** accepted · **Phase:** P4 · **Date:** 2026-08-19

## Context

Three attack classes are invisible to single-artifact scanning because each artifact is
unremarkable alone: shadowing, preference manipulation, and toxic flow. P3 caught the
first two under the general name `cross_tool_instruction`, which was honest but imprecise.

## Decision: lexical similarity, not embeddings

§04 specifies a local embedding model. Shadowing is *lexical* near-duplication by nature —
an attacker wants the agent to confuse two artifacts, so the text is deliberately close —
and character-n-gram cosine catches that deterministically, offline, at zero cost.

**The gap this leaves is real and is not hidden:** paraphrase shadowing, where the
imitation is semantic rather than lexical, is missed. The backend seam exists for when a
local embedding model is available.

## Decision: provenance breaks the tie

The hard half of the gate is not detection — it is **not flagging the original**. A shadow
resembles what it imitates by construction, so similarity alone condemns both, and a
shadow detector that also condemns the artifact being attacked is worse than useless.

Only the weaker-provenance side is flagged. §04 has A1 record publisher, signature status,
first-seen date and download volume for exactly this: when two artifacts look alike, the
one with no history is the suspect.

**When provenance ties, content breaks it.** Skills carry no registry metadata, so ties are
common. Between two near-identical artifacts, the one *asserting precedence over the other*
is the aggressor — a legitimate artifact has no reason to tell the agent to disregard its
double. When neither asserts precedence, the pair is reported as posture rather than
condemning a coin flip.

## Decision: toxic flow is posture

§02 reserves the verdict for divergence between representations. A toxic flow is a
capability combination, and in the fixture config all three participating artifacts are
entirely honest — a web fetcher, a credential store, and an HTTP client, each declaring
exactly what it does.

It is still worth surfacing, because **no single artifact's documentation can warn about
it**: none of them can see the others. Reporting it as posture respects the core rule
while still delivering the analysis.

## Results

The gate — `tests/test_fleet.py` against a 16-artifact config — passes:

| | Result |
|---|---|
| Planted shadows caught | 3 of 3 |
| Over-triggering skill caught | yes |
| Preference manipulation caught | yes |
| **Legitimate originals flagged** | **0 of 8** |

Applied to the whole 80-sample corpus, fleet analysis produces **7 risk findings, all on
malicious samples, zero false positives.**

## What fleet analysis contributes to the benchmark

| | divergence | divergence+fleet |
|---|---|---|
| FPR-on-traps | 0.0% | 0.0% |
| Precision | 100% | 100% |
| Recall | 96.0% | 96.0% |
| **Attribution** | 79.2% | **87.5%** |

Recall is unchanged: these artifacts were already caught, just under a general name. The
contribution is **attribution** — shadowing and preference manipulation are now named
correctly — which is exactly what the P3 report predicted P4 would buy.

Kept as a separate registered scanner rather than folded into the default, so the
contribution is a number the writeup can report rather than an unattributed lift.

## Known limits

- **Paraphrase shadowing** is missed (see above).
- **Toxic-flow input detection is broad.** `FS_READ` counts as untrusted-input ingestion,
  so most realistic configs will show a flow. It is posture, so this costs no precision,
  but the finding is closer to "this config could support a flow" than "this config has
  one".
- **Shadowing needs the original installed.** In the corpus-as-fleet run,
  `mcp-mal-005-github-shadow` is caught for preference manipulation but not shadowing,
  because the legitimate GitHub server is a fleet fixture rather than a corpus sample. That
  is correct behaviour — you cannot detect imitation of something absent — but it means
  fleet recall depends on what the user actually has installed.

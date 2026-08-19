# ADR 0006 — Comparing against third-party scanners

**Status:** accepted · **Phase:** v1 ship checkpoint · **Date:** 2026-08-19

## Context

§06 is explicit that the strong artifact is "here is a reproducible corpus, here is how
six existing tools score on it, here is where mine wins and where it loses." From P0 to
P4 the comparison table had exactly one independent competitor and it was one we wrote
(`keyword`). Running real scanners was deferred at the user's request and became the
blocking item for v1.

## What we found trying to run them

**Existing scanners analyse a *live* MCP server, not source.** They read a client config,
launch each server, call `tools/list`, and reason about the tool descriptions that come
back. The corpus is static source that is not runnable — it imports an SDK that is not
installed, and half of it is agent skills, which are not servers at all.

That is a structural incompatibility, not a bug in either tool. It is also part of the
answer to "why does no precision benchmark exist for this space": the incumbent input
contract makes a static labelled corpus hard to compare against.

**`mcp-scan` has been renamed `snyk-agent-scan`.** The most-cited tool in this space is
now a Snyk product.

## Decision: a manifest shim

`bench/manifest_shim.py` serves a sample's `manifest.json` over the MCP stdio protocol
without importing or executing the sample's implementation.

This is **safer and more faithful at the same time**:

- Safer: a malicious sample's handler never runs.
- More faithful: these scanners analyse the reasoning surface — names, descriptions,
  schemas, annotations — and that is exactly what the manifest holds. Running the real
  handler would give them nothing extra to read.

The protocol is implemented directly rather than via the MCP SDK, so the shim adds no
dependency and cannot itself become a variable in the comparison.

## Decision: not-applicable is not a miss

mcp-shield has no notion of an agent skill. Scoring it as missing all 12 malicious skills
would manufacture a recall gap out of a scope difference and flatter our own numbers.

`SampleResult.not_applicable` excludes those artifacts from scoring entirely, and the
comparison table gains a **coverage** column so a reader can see what each scanner could
analyse. A scanner is scored on the artifacts it can see.

## Finding: snyk-agent-scan cannot be part of a reproducible benchmark

Attempted, with the project owner's explicit authorisation, on 2026-08-19. It does not run.

`mcp-scan` — the most-cited scanner in this space — is now `snyk-agent-scan`, a Snyk
product at v0.6.0. Three properties, established by running it:

1. It analyses a **live** server from a client config, so it needs the manifest shim, like
   mcp-shield.
2. It **transmits tool descriptions to a hosted Snyk analysis API.** There is no offline
   mode; `--analysis-url` only redirects the verification server, and the tool pins its own
   API version.
3. **It requires a `SNYK_TOKEN` from a Snyk account.** Without one it prints
   *"To use Agent Scan, set the SNYK_TOKEN environment variable"* and exits 1 before
   scanning anything.

The third is binding and the first two are why. **A benchmark that cannot be reproduced
without a vendor account is not reproducible.** §09 requires benchmark runs to be fully
reproducible offline after the first pass; a hosted analyser gated behind account
registration fails that on both counts.

The adapter therefore reports itself unavailable with that reason rather than silently
scoring zero, which would have been the dishonest outcome — an absent competitor reading
as a beaten one. If a token is present in the environment, it runs.

### Why this belongs in the writeup rather than in a footnote

It is a substantive observation about the state of this tooling. The most-cited open-source
scanner in the space has become a hosted commercial product that sends the artifact
metadata it analyses to a vendor API. For the configuration under examination — which §10
notes "is itself sensitive" — that is a material property, and it is one a precision
benchmark can state as fact rather than opinion.

It also sharpens why `semgrep` is the more useful competitor: it runs offline, needs no
account, and can therefore actually appear in a table anyone can reproduce.

## Consequence for the writeup

The comparison now has genuinely independent competitors, which is the claim §06 says the
project needs. It also carries a caveat that must not be dropped: **the scanners are being
compared on inputs shaped to fit them.** A tool that reads live servers is being fed a
faithful manifest; a general SAST tool is being pointed at source. Neither was designed
for this corpus, and both would score differently on their native inputs.

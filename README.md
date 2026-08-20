# Divergence

A precision-first analyzer for MCP servers and agent skills.

It does not look for dangerous-sounding text. It looks for the gap between what an
artifact **claims** to do and what it **actually** does — measured statically, then
confirmed in a sandbox.

> A finding is the gap, not the capability.

A shell-execution server that executes shells is doing its job. A shell-execution
server that quietly opens a socket is not.

## Status

**Phase P5 complete — v1 shipped, sandbox landed.** All nine components are built: the
deterministic core, static behaviour extraction, the divergence engine, fleet analyzers,
and a Rust sandbox that observes what an artifact actually does under Landlock.

Six scanners, one corpus, one command (`make bench-external`):

| Scanner | FPR-on-traps | Precision | Recall | Attribution |
|---|---:|---:|---:|---:|
| **divergence+fleet** | **0.0%** | **100%** | 87.1% | 85.2% |
| semgrep | 5.7% | 87.5% | 56.0% | 0.0% |
| mcp-shield | 19.0% | 20.0% | 8.3% | 100% |
| keyword strawman | 57.1% | 45.0% | 72.0% | 72.2% |

Zero false positives across all 55 benign and trap artifacts, fully offline and
deterministic with no model in the pipeline.

**The most useful row is semgrep's.** It is a mature general-purpose analyser and a
genuinely strong competitor — but it scores **78% on code-surface attack classes and 48%
on reasoning-surface** ones, with 0% attribution. That is this project's thesis, measured
by somebody else's tool: read only the code and the poisoned description is invisible.

**Recall is 87.1%, down from 96%, and that is deliberate.** P5 added an obfuscated stratum
built specifically to defeat static analysis. Leaving it out would have kept a prettier
number by declining to measure the thing the sandbox exists for. `make sandbox-gate`
recovers 4 of the 5 payloads that static analysis cannot see.

**Read all of it with the caveat it deserves:** the corpus was written by the same author
and then tuned against. `tests/test_holdout.py` is an out-of-sample check written after
tuning — 26 artifacts in shapes deliberately unlike the corpus — and it has caught a real
generalisation failure every time it has grown.

See `build-plan/divergence-spec.html` for the full build specification, and
`build-plan/reports/` for phase progress reports.

## Using it

```bash
divergence inspect <path>    # print the declared surface — executes nothing
divergence scan    <path>    # findings, split into risk and posture
divergence fleet   <path>    # cross-artifact analysis over an installed set
divergence approve <path>    # record a fingerprint for later diffing
divergence diff    <path>    # detect post-approval mutation
```

A target is a directory, a skill bundle, or a local MCP client config
(`claude_desktop_config.json`, `mcp.json`) — pointing at a config scans every server
in it. Remote specs raise rather than reaching the network: §10 makes offline-by-default
a feature, because the configuration you are asking about is itself sensitive.

## The benchmark

Existing benchmarks in this space measure **recall** — can a scanner find the planted
attack? That is the easy half. `divergence-bench` leads with **FPR-on-traps**: the
false-positive rate against benign artifacts deliberately engineered to look malicious.

An independent April 2026 audit of two open-source scanners across 33 servers and 433
tools found that of 27 flagged patterns only 6 were real — a ~78% false positive rate.
Eight fired on ordinary dependency instructions. Nine fired on a browser-automation
server for doing browser automation. The trap stratum exists to measure exactly that.

## Quickstart

```bash
make install        # uv sync, pinned to Python 3.12
make validate       # every corpus sample is well-formed and carries a rationale
make test           # unit tests
make bench          # the baseline comparison table
make capabilities   # B_s extraction vs verified ground truth
```

## Corpus layout

```
corpus/samples/<kind>/<stratum>/<sample-id>/
├── sample.yaml     # label, stratum, attack classes, written rationale
└── artifact/       # the actual MCP server or skill bundle
```

Every sample carries a written label rationale — why it is malicious, or specifically
why it merely looks that way. The rationales are as much of the artifact as the samples,
because they are what a reviewer checks when they disagree with a verdict.

## Safety

Samples in the `malicious` and `obfuscated` strata are **inert fixtures**. Their payloads
target `localhost` sinkholes and decoy paths under the sample directory; none of them
reach a live endpoint or touch real credentials. They exist to be read by a scanner, not
to be run. `make validate` enforces this.

## Licence

Apache-2.0. The corpus is intended for publication under a permissive licence with a
versioned dataset tag.

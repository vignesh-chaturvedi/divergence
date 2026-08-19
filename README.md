# Divergence

A precision-first analyzer for MCP servers and agent skills.

It does not look for dangerous-sounding text. It looks for the gap between what an
artifact **claims** to do and what it **actually** does — measured statically, then
confirmed in a sandbox.

> A finding is the gap, not the capability.

A shell-execution server that executes shells is doing its job. A shell-execution
server that quietly opens a socket is not.

## Status

**Phase P4 — fleet analysis.** Cross-artifact analyzers on top of the divergence engine:
shadowing, relative preference scoring, and a toxic-flow graph over the installed set.

| | divergence | keyword strawman |
|---|---|---|
| **FPR-on-traps** | **0.0%** | 57.1% |
| Precision | **100%** | 45.0% |
| Recall | **96.0%** | 72.0% |
| F1 | **98.0%** | 55.4% |

18 of 19 attack classes at full recall, zero false positives across all 55 benign and
trap artifacts, fully offline and deterministic with no model in the pipeline. Fleet
analysis lifts attribution from 79.2% to 87.5% and catches three planted shadows in a
16-artifact config without flagging the eight legitimate originals.

**Read that with the caveat it deserves:** the corpus was written by the same author and
then tuned against. `tests/test_holdout.py` is an out-of-sample check written after
tuning, and it caught a real generalisation failure the benchmark could not. The
third-party scanner comparison is still gated and unrun.

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

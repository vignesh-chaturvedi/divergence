# Divergence

A precision-first analyzer for MCP servers and agent skills.

It does not look for dangerous-sounding text. It looks for the gap between what an
artifact **claims** to do and what it **actually** does — measured statically, then
confirmed in a sandbox.

> A finding is the gap, not the capability.

A shell-execution server that executes shells is doing its job. A shell-execution
server that quietly opens a socket is not.

## Status

**Phase P0 — ground truth.** The benchmark exists before the scanner does. There is
no detection code in this repository yet, by design: the corpus and the scoring
harness come first so that everything downstream is measurable rather than asserted.

See `build-plan/divergence-spec.html` for the full build specification, and
`build-plan/reports/` for phase progress reports.

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

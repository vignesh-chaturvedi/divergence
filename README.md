# Divergence

A precision-first analyzer for MCP servers and agent skills.

It does not look for dangerous-sounding text. It looks for the gap between what an
artifact **claims** to do and what it **actually** does — measured statically, then
confirmed in a sandbox.

> A finding is the gap, not the capability.

A shell-execution server that executes shells is doing its job. A shell-execution
server that quietly opens a socket is not.

## Status

**Phase P2 — static behaviour extraction.** A tree-sitter parse of the implementation
across Python, TypeScript and shell, with reachability from each entrypoint and a light
parameter-taint pass. Capabilities are attributed to the handlers that can actually
reach them, which is what lets a per-tool annotation check work at all.

Against hand-verified ground truth on all 80 corpus artifacts, extraction scores
**100% precision and 91.9% recall, with a published 8.1% false-negative rate.** Every
miss is the same class: a capability reached through a spawned process (`ssh`, `pip
install`, `git push`) that no parser can follow.

Against the benchmark, the scanner scores **100% precision at 0% false positives on the
trap stratum**, with 20% recall. The keyword strawman scores 45% precision at 57.1%
FPR-on-traps. That trade — far less recall, no false positives — is the thesis, and P3
is where recall arrives.

See `build-plan/divergence-spec.html` for the full build specification, and
`build-plan/reports/` for phase progress reports.

## Using it

```bash
divergence inspect <path>    # print the declared surface — executes nothing
divergence scan    <path>    # findings, split into risk and posture
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

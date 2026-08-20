# ADR 0010 — Separate distribution identity from command and truth from stratum

**Status:** accepted · **Phase:** P6 release hardening · **Date:** 2026-08-20

## Context

The original project metadata used `divergence` as both the PyPI distribution and command.
PyPI's JSON API shows that `divergence` is an unrelated information-theory package. The
benchmark also inferred positivity from stratum, even though the obfuscated cohort contains
a deliberately benign control and every manifest already carries `label.malicious`.

Both are identity errors: one at package level, one at dataset level.

## Decision

- The PyPI distribution is `divergence-mcp`. The Python import remains `divergence`, and
  the console commands remain `divergence` and `divergence-bench`.
- `src/divergence/__init__.py` is the canonical version source. Hatch distribution metadata,
  the internal adapter, CLI version output, and SARIF import that value.
- `label.malicious` is the only benchmark verdict. Stratum records experimental design;
  `obfuscated` may contain positive payloads and negative controls.
- The corpus and its dataset manifest are bundled in the wheel so benchmark commands do
  not depend on the current working directory.

## Name-availability evidence

On 2026-08-20, `https://pypi.org/pypi/divergence-mcp/json` returned HTTP 404. The candidate
names `mcp-divergence` and `agent-divergence` also returned 404, while
`https://pypi.org/pypi/divergence/json` returned metadata for the unrelated existing
project. A 404 is point-in-time availability evidence, **not a reservation**. The release
owner must recheck immediately before protected publication.

## Consequences

Existing source imports do not change. Installation documentation must always distinguish
the distribution from the command (`uvx --from divergence-mcp divergence ...`). Benchmark
counts now contain 50 risk-positive and 60 benign/control artifacts. The 30-sample
obfuscated stratum contains 25 positives and five matched controls; encoding or stratum
membership never overrides their explicit labels.

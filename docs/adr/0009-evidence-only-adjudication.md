# ADR 0009 — A9 is an evidence-only command backend

**Status:** accepted · **Phase:** P6 release hardening · **Date:** 2026-08-20

## Context

The locked architecture permits a frontier model only for genuinely contested cases and
caps that tier at five percent. A built-in hosted-model client would add a provider,
network, privacy, cost, and reproducibility policy to the default scanner.

## Decision

The deterministic finding remains authoritative and unchanged. A9 is off by default and
is enabled only by a caller using `ScanOptions(adjudicate=True)` or the explicit
`divergence scan --adjudicate` flag. There is no implicit network call and no provider SDK;
setting the backend environment variable alone does nothing.

The built-in provider-neutral backend reads `DIVERGENCE_ADJUDICATOR_COMMAND`, splits it
into an argument vector, and invokes that executable directly without a shell. The command
receives one JSON object on standard input containing only normalized finding evidence:

```json
{
  "artifact": "artifact-id",
  "channel": "risk",
  "attack_class": "undeclared_network",
  "severity": "high",
  "message": "normalized finding text",
  "claim": "normalized claim evidence",
  "evidence": "normalized implementation evidence",
  "confidence": 0.65
}
```

It must return exactly one JSON object on standard output:

```json
{"verdict": "confirm", "reasoning": "Concise evidence-based reason."}
```

`verdict` is one of `confirm`, `dismiss`, or `uncertain`; `reasoning` must be non-empty.
The default timeout is 60 seconds. Invalid JSON, a non-zero exit, timeout, or missing
configuration makes adjudication unavailable and does not rewrite the finding.

The selector's budget is `floor(total_normalized_findings * 0.05)`, never rounded up.
Only risk findings with confidence from 0.45 inclusive to 0.85 exclusive are candidates,
ordered deterministically by distance from 0.65 and stable identifiers. A scan with fewer
than 20 findings therefore sends none. The five-percent ceiling cannot be raised by caller
configuration.

## Consequences

- Raw artifacts, source files, MCP configs, and credentials are outside the A9 contract.
- Any network or vendor behavior belongs to the operator-supplied executable.
- Adjudications are supplemental records; deterministic findings and exit semantics do
  not change.
- Benchmark runs remain A9-off unless a separately identified experiment says otherwise.

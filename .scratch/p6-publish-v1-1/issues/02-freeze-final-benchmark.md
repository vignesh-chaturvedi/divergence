# Rerun and freeze the final all-strata benchmark

Status: resolved

Internal scanners and every available pinned external adapter were rerun after local P5
containment and corpus expansion settled. Generated JSON and Markdown provenance, the
writeup, and explicit unavailable baselines are tracked. Independent issue 05 review can
still reopen this ticket if it changes a label or fixture.

## Comments

Generated JSON and Markdown are tracked under `benchmarks/v1.1/`. JSON is authoritative;
the writeup and release summary must be regenerated if independent label review changes
the corpus.

## Answer

The 110-artifact candidate run records static, fleet, hardened dynamic, Semgrep 1.173.0,
mcp-shield 1.0.4, keyword, and unavailable Snyk rows with corpus/platform/scanner
provenance, raw numerators and denominators, Wilson intervals, durations, and dynamic
coverage. Semgrep's reviewed rules snapshot hash is
`f8b8461199c4d0ac23c0faf60f8b00a50139854d742e5b7374ccde09f81c9afd`.

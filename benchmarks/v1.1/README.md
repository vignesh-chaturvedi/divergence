# Divergence 1.1 benchmark evidence

This directory freezes the generated release-candidate evidence for the 110-artifact
`divergence-corpus-v1.1` dataset. JSON is authoritative; Markdown is a compact rendering
of the same raw counts and Wilson 95% intervals.

| File | Environment | Rows |
|---|---|---|
| `static-external.json` / `.md` | macOS arm64, Python 3.12 | static, fleet, reference, Semgrep, mcp-shield, unavailable Snyk |
| `static-dynamic-linux-aarch64.json` / `.md` | unprivileged Linux arm64, Python 3.12 | static and hardened static+dynamic |
| `sandbox-probe-linux-aarch64.json` | unprivileged Linux arm64 | Landlock v4, seccomp, and identity preflight |
| `sandbox-gate-linux-aarch64.txt` | unprivileged Linux arm64 | per-sample P5 recovery evidence and gate result |

Both runs use corpus SHA-256
`1f7bf90619185d584137bd7b9b37203c13c46c32a098791ea0580f245a8e9dce`.
They are also bound to analyzer-source SHA-256
`71aa8d411a8eba580c0ea7b40db7cec4d7550e47c7c78f4195ee5bb16628d15b`;
the JSON records the exact PyYAML and tree-sitter runtime versions. The source digest
hashes analyzer modules only, so it is identical in a checkout and in the wheel that
force-includes Python corpus fixtures under package data.
The Linux dynamic run used sandbox binary SHA-256
`558c21f3cea1fbeccdd0447d84c4413293b8e371412ef223f3eb390707164238`.

The separate P5 recovery gate caught 24/25 obfuscated positive simulations (96.0%;
Wilson 95% CI 80.5%–99.3%) and left all five matched controls clean. The registered
static+dynamic row caught 49/50 positives across all strata with zero false positives.

## Reconstruct the Semgrep rules snapshot

The external run never uses a mutable registry alias. Reconstruct the snapshot described
by `semgrep-rules.lock.yaml`, then verify its checkout-independent content hash:

```bash
git clone --no-checkout https://github.com/semgrep/semgrep-rules.git \
  .bench-cache/semgrep-rules
git -C .bench-cache/semgrep-rules checkout --detach \
  40b8c63f75dc7c22c8a77482d73bfb864b146f7e
mkdir -p .bench-cache/semgrep-rules-snapshot
cp -R .bench-cache/semgrep-rules/{ai,bash,python,typescript} \
  .bench-cache/semgrep-rules-snapshot/
uv run python -c 'from pathlib import Path; from divergence.adapters.semgrep_scanner import ruleset_sha256; print(ruleset_sha256(Path(".bench-cache/semgrep-rules-snapshot")))'
```

The printed digest must match `snapshot_sha256` in the lock file before running:

```bash
DIVERGENCE_SEMGREP_RULESET=.bench-cache/semgrep-rules-snapshot make bench-external
```

Snyk Agent Scan is intentionally represented as unavailable: it requires an account token
and sends tool descriptions to a hosted service, so it cannot satisfy this benchmark's
offline reproducibility rule.

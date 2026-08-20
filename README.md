# Divergence

Divergence is a precision-first analyzer for MCP servers and agent skills. It measures
the gap between what an artifact **claims** to do and what its implementation can do.

> A finding is the gap, not the capability.

A shell-execution server that executes shells is doing its job. One that also opens an
undeclared network connection is not. Divergence reports capability as non-verdict
**posture** and only contradictions as **risk**.

## Release status

Version 1.1.0 is a release candidate, not a published release. The deterministic static
core and fleet analyzers are implemented. Local release engineering and the tracked
candidate benchmark are complete. Two explicitly opt-in tiers also exist:

- **A8 dynamic observation** executes fixtures only through the fail-closed Linux sandbox.
  P5 passed locally on unprivileged Linux arm64; unsupported platforms report static-only,
  and the release workflow still has to reproduce the Linux x86-64 runner.
- **A9 adjudication** is a provider-neutral command backend for normalized evidence only.
  It is off by default, never changes deterministic findings, and has a hard five-percent
  selector cap.

Formal P6 completion still requires independent corpus label/rationale review, Linux
x86-64 candidate-workflow reproduction, a non-author clean install plus real scan and filed
GitHub issue, and protected tag/PyPI/GitHub publication. No release has been tagged or
published. The remaining gates are tracked in the
[release guide](https://github.com/vignesh-chaturvedi/divergence/blob/main/docs/RELEASING.md).

## Run from a checkout

Python 3.12 and [uv](https://docs.astral.sh/uv/) are required.

```bash
uv sync --frozen --extra dev
uv run divergence inspect <path>
uv run divergence scan <path>
uv run divergence fleet <client-config-or-fleet.yaml>
```

The eventual PyPI distribution is named `divergence-mcp` because `divergence` is
already an unrelated project. The installed command remains `divergence`:

```bash
# Works after 1.1.0 is actually published:
uvx --from divergence-mcp==1.1.0 divergence --help
```

Targets may be a local directory, skill bundle, MCP client configuration, or fleet
manifest. Network acquisition is denied by default; `--allow-network` is an explicit
download-only opt-in for supported npm, PyPI, or GitHub targets.

## Benchmark

The bundled v1.1 candidate dataset contains 110 synthetic artifacts:

| Stratum | Count | Risk-positive | Benign/control |
|---|---:|---:|---:|
| Malicious | 25 | 25 | 0 |
| False-positive traps | 35 | 0 | 35 |
| Benign plain | 20 | 0 | 20 |
| Obfuscated | 30 | 25 | 5 |
| **Total** | **110** | **50** | **60** |

`label.malicious` is authoritative. Stratum describes how a fixture tests the scanner;
it does not determine the verdict. This matters because the obfuscated stratum deliberately
contains five matched benign controls, including a base64-heavy decoder.

All 110 artifacts are synthetic fixtures authored for this project, not packages pulled
from public registries. That makes the labels auditable but means the benign set does not
measure a real-world registry base rate. [The corpus provenance policy](https://github.com/vignesh-chaturvedi/divergence/blob/main/corpus/README.md)
defines the immutable source/version/license fields required for any future derived sample.

```bash
uv run divergence-bench validate --check-p0-target
uv run divergence-bench bench --detail \
  --json out/bench.json --markdown out/bench.md
```

The wheel bundles the corpus, so `divergence-bench` works outside a repository checkout.
JSON results include the corpus SHA-256, project and scanner versions, exact external-tool
pins and local ruleset hashes, Python/platform provenance, durations, raw numerators and
denominators, and Wilson 95% intervals for trap FPR and recall.

The generated v1.1 candidate evidence is tracked in
[`benchmarks/v1.1/`](https://github.com/vignesh-chaturvedi/divergence/tree/main/benchmarks/v1.1).
The JSON files are authoritative; the table below is a readable summary.

| Scanner | Trap false positives | Precision | Recall | Attribution |
|---|---:|---:|---:|---:|
| `divergence` | 0/35 (0.0%; CI 0.0–9.9%) | 100% | 27/50 (54%; CI 40.4–67.0%) | 77.8% |
| `divergence+fleet` | 0/35 (0.0%; CI 0.0–9.9%) | 100% | 27/50 (54%; CI 40.4–67.0%) | 85.2% |
| `divergence+dynamic` | 0/35 (0.0%; CI 0.0–9.9%) | 100% | 49/50 (98%; CI 89.5–99.6%) | 87.8% |
| Semgrep 1.173.0 | 5/35 (14.3%; CI 6.3–29.4%) | 81.1% | 30/50 (60%; CI 46.2–72.4%) | 0% |
| mcp-shield 1.0.4 | 4/21 (19.0%) | 20% | 1/33 (3.0%) | 100% |
| keyword baseline | 20/35 (57.1%) | 52.9% | 27/50 (54%) | 77.8% |

Semgrep used a reviewed rules snapshot with SHA-256
`f8b8461199c4d0ac23c0faf60f8b00a50139854d742e5b7374ccde09f81c9afd`; it produced
seven false positives across all controls, five of them in the trap stratum. mcp-shield
supports only 66.4% of the corpus, so its 21-trap and 33-positive denominators must travel
with its percentages. `snyk-agent-scan` is unavailable without a vendor token and hosted
API and is not scored as zero.

Third-party scanners download or execute other projects and are opt-in:

```bash
DIVERGENCE_ALLOW_EXTERNAL=1 make bench-external
```

Semgrep additionally requires `DIVERGENCE_SEMGREP_RULESET` to point to a reviewed local
rules snapshot. The adapter executes `semgrep@1.173.0` via `uvx`; mutable registry aliases
are rejected so both the scanner package and rules can be reproduced.

Dynamic benchmarking is a separate Linux-only opt-in because it executes fixtures:

```bash
make sandbox-gate   # fails if confinement is unavailable
make bench-dynamic  # registered divergence+dynamic row with coverage metadata
```

On the candidate corpus, the hardened recovery gate observed 24/25 obfuscated positives
(96%; Wilson 95% CI 80.5–99.3%) and kept all five matched controls clean. Static analysis
flagged three of those positives; the combined row flags all 25, eliminating all 22 static
misses in that stratum.
It confirmed runtime entrypoints for 83/110 fixtures; the authoritative JSON records
coverage per sample. The verified Linux arm64 boundary refuses root, drops to an
unprivileged identity, clears the environment into a private `HOME`, uses exact decoys,
Landlock ABI v4, seccomp denial, and ptrace observation, and cleans up resources and the
entire process group. Docker denied network-namespace creation, so independently verified
Landlock and seccomp rules blocked egress instead; ADR 0011 records that limitation.

The product CLI uses the same guarded path. A requested tier that is unavailable, times
out, or fails an entrypoint makes the scan visibly partial and exits 2 unless the caller
explicitly accepts partial coverage:

```bash
uv run divergence scan <path> --dynamic --sandbox-timeout 30
```

## Optional A9 adjudication

A9 is available through both the pipeline API and an explicit CLI flag. Merely setting an
environment variable never activates it:

```bash
DIVERGENCE_ADJUDICATOR_COMMAND='/reviewed/path/to/backend --model frontier' \
  uv run divergence scan <path> --adjudicate
```

The equivalent API is:

```python
from divergence.core.pipeline import ScanOptions, scan_detailed

report = scan_detailed(
    "artifact",
    options=ScanOptions(adjudicate=True),
)
```

Set `DIVERGENCE_ADJUDICATOR_COMMAND` to an executable that accepts one normalized
finding as JSON on stdin and returns:

```json
{"verdict": "confirm", "reasoning": "Concise evidence-based reason."}
```

Valid verdicts are `confirm`, `dismiss`, and `uncertain`. Raw source, artifact files,
MCP configs, and credentials are never part of the built-in contract. See
[ADR 0009](https://github.com/vignesh-chaturvedi/divergence/blob/main/docs/adr/0009-evidence-only-adjudication.md) for the exact selector and JSON
fields.

## GitHub Action

The composite Action writes SARIF but intentionally does not upload it. Pin a released tag
or audited commit, then use GitHub's upload action in a separate step:

```yaml
- uses: vignesh-chaturvedi/divergence/action@<audited-commit-sha>
  with:
    target: .
    fail-on-risk: "true"
    allow-partial: "false"
    sarif-file: divergence.sarif

- uses: github/codeql-action/upload-sarif@<audited-commit-sha>
  if: always()
  with:
    sarif_file: divergence.sarif
```

## Corpus safety and limitations

Corpus payloads are inert fixtures aimed at reserved domains, loopback sinks, and planted
decoys. They are intended to be read, not executed outside the fail-closed sandbox.
`divergence-bench validate` checks label structure and inert destinations.

The corpus and scanner share an author, so the benchmark is not independent. The holdout
suite reduces but does not remove that bias. Label disagreements are welcome through the
benchmark issue template; do not post credentials or real MCP configurations.

## License

Code, corpus, and documentation are licensed under the
[Apache License 2.0](https://github.com/vignesh-chaturvedi/divergence/blob/main/LICENSE).
[Citation metadata](https://github.com/vignesh-chaturvedi/divergence/blob/main/CITATION.cff)
is provided for the software and corpus.

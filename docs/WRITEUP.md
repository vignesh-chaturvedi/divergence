# Measuring the wrong thing: a precision benchmark for MCP scanners

*v1.1 release-candidate evidence. The benchmark is tracked and reproducible; the release
is not yet independently reviewed, tagged, or published.*

## The failure mode

A scanner can fail in two directions. It can miss a planted attack, or it can describe a
legitimate capability as an attack so often that nobody trusts the output. Recall-only
benchmarks measure the first failure and hide the second.

This distinction is unusually important for MCP servers and agent skills. A shell server
is supposed to spawn processes. A credential manager is supposed to read credential
paths. A workflow may genuinely require one tool to run before another. The capability,
path, or imperative phrase is not enough to decide whether the artifact is malicious.

The useful question is relational:

> What does this artifact do that it did not tell the user it would do?

## Two surfaces, independent representations

Agent artifacts expose a **reasoning surface**—names, descriptions, schemas, annotations,
and skill instructions—and a **code surface**—source, dependencies, bundled files, and
runtime behavior.

Divergence builds separate representations:

- **C**: capabilities claimed by names and descriptions;
- **S**: capabilities permitted by schemas, annotations, and skill tool grants;
- **B_static**: capabilities reachable in the implementation without executing it;
- **B_dynamic**: capabilities observed only inside a verified sandbox boundary.

The rule table is intentionally asymmetric:

| Relation | Interpretation | Channel |
|---|---|---|
| B_static ⊆ C | Behavior matches the claim, however powerful | Posture |
| High-signal B_static ⊄ C | Network, credentials, exec, eval, or delete was undeclared | Risk |
| S ⊄ C | Inputs permit a hidden interface | Risk |
| annotation contradicts B_static | The manifest's safety hint is false | Risk |
| C asks another tool to act | Cross-tool directive, not a local capability | Risk |
| B_dynamic ⊄ B_static | Execution revealed a statically hidden capability | Risk, coverage-qualified |

Filesystem and environment posture do not automatically become risk because prose cannot
reliably separate a todo list from an exfiltrator. Lexical extraction maps text to a claim,
never directly to a verdict. A cross-tool finding requires a directive, not a reference.
These constraints cost recall in exchange for the benchmark's central goal: precision.

## The corpus

The v1.1 candidate corpus has 110 labelled artifacts across MCP servers and agent skills.
The obfuscated stratum was expanded to the approximately 30 samples planned in §06, with
five matched benign controls. Independent human label and rationale review remains a P6
release gate; the machine-readable labels below are the current candidate truth.

| Stratum | Count | Risk-positive | Benign/control | Purpose |
|---|---:|---:|---:|---|
| Malicious | 25 | 25 | 0 | Documented and skill-specific attack classes |
| False-positive traps | 35 | 0 | 35 | Benign artifacts engineered to look dangerous |
| Benign plain | 20 | 0 | 20 | Ordinary base-rate controls |
| Obfuscated | 30 | 25 | 5 | Diverse static-analysis evasions plus matched benign controls |
| **Total** | **110** | **50** | **60** | |

Ground truth comes from the explicit `label.malicious` boolean, not from the stratum.
That correction matters: treating every obfuscated sample as positive turned the benign
decoder control into a false negative and understated static recall.

Every sample includes a written rationale, expected risk or posture findings, and inert
artifact bytes. Positive fixtures may reference only loopback, reserved domains, or
planted decoys. The validator enforces those invariants.

All 110 are synthetic fixtures authored for this project. Despite the original plan to
sample benign artifacts from public registries, none of the current files is copied or
derived from an upstream package. Embedded registry records are test data. This improves
license clarity but means the benign stratum is not evidence of a real-world base rate.
`corpus/dataset.yaml` and `corpus/README.md` record the dataset-level provenance and the
required immutable revision/version/license fields for future derived samples.

### Why traps are the contribution

The trap stratum isolates five common false-positive causes:

- privileged by design;
- imperative language;
- wildcard permissions;
- security-domain vocabulary;
- broad but honest triggers.

Matched pairs hold the suspicious surface constant and change the claim. A note reader
that quietly reads an SSH key diverges; an SSH credential manager reading the same path
does not. A local renderer opening an undeclared socket diverges; an HTTP client fetching
its requested URL does not.

This follows the false-positive-trap pattern used by the
[OWASP Benchmark](https://owasp.org/www-project-benchmark/): safe and vulnerable cases
must both be present or a scanner can win by alarming on everything.

## Measurement and provenance

`divergence-bench` scores every adapter through the same normalized finding model.
Posture never counts toward a verdict. Unsupported artifact kinds are reported as
not-applicable and removed from that scanner's denominator instead of being manufactured
into misses.

The JSON result records:

- project, scanner, command/package, Python, and platform versions;
- corpus dataset identifier and content SHA-256;
- external package pins and the SHA-256 of Semgrep's required local rules snapshot;
- per-run duration and not-applicable coverage;
- raw confusion-matrix counts;
- raw numerators/denominators and Wilson 95% intervals for trap FPR and recall;
- per-class attribution and per-trap-family false positives;
- per-sample execution coverage for the opt-in dynamic adapter.

Percentages without denominators overstate certainty. For example, even a clean result of
0 false positives in 35 traps has a Wilson 95% interval of **0.0%–9.9%**. A result should
therefore be written as `0/35 (0.0%; Wilson 95% CI 0.0%–9.9%)`, not simply “zero FPR.”

## Candidate results

The prior 80-sample static checkpoint and the unsafe ptrace-only dynamic run are historical
results on different evidence. The current records were generated on the 110-artifact
candidate corpus and are tracked under `benchmarks/v1.1/`. JSON is authoritative; Markdown
is generated from the same run rather than maintained as a second source of truth:

```bash
uv run divergence-bench bench --detail \
  --json out/bench.json --markdown out/bench.md
```

The current generated summary is:

| Scanner | Trap FPR | Precision | Recall | Attribution |
|---|---:|---:|---:|---:|
| `divergence` | 0/35 · 0.0% · CI 0.0–9.9% | 100% | 27/50 · 54.0% · CI 40.4–67.0% | 77.8% |
| `divergence+fleet` | 0/35 · 0.0% · CI 0.0–9.9% | 100% | 27/50 · 54.0% · CI 40.4–67.0% | 85.2% |
| `divergence+dynamic` | 0/35 · 0.0% · CI 0.0–9.9% | 100% | 49/50 · 98.0% · CI 89.5–99.6% | 87.8% |
| Semgrep 1.173.0 | 5/35 · 14.3% · CI 6.3–29.4% | 81.1% | 30/50 · 60.0% · CI 46.2–72.4% | 0% |
| mcp-shield 1.0.4 | 4/21 · 19.0% | 20.0% | 1/33 · 3.0% | 100% |
| keyword | 20/35 · 57.1% | 52.9% | 27/50 · 54.0% | 77.8% |

The static result is the precision-first trade: no false alarms in 35 deliberately
difficult traps, but only 27/50 positives found. Fleet context improves attribution from
77.8% to 85.2% without changing that confusion matrix. The hardened dynamic tier recovers
22 additional positives, reaching 49/50 recall while keeping the same 0/35 trap result and
100% precision.

### What changed after hardening

The P5 recovery gate exercises all 25 obfuscated positive fixtures. Static analysis flags
three of them; the verified dynamic gate observes **24/25 (96%; Wilson 95% CI
80.5%–99.3%)**; and their union in the registered combined row flags all 25. Dynamic
evidence therefore eliminates all 22 static misses in the stratum while all five matched
obfuscated controls remain clean. Across the whole corpus, confirmed runtime entrypoints
were reached for 83/110 fixtures. Per-sample
entrypoint, syscall, duration, and availability metadata travels in the JSON; the combined
row does not pretend every path executed.

This evidence came from an unprivileged Linux arm64 run. The runner refuses root, clears
the ambient environment into a private `HOME`, uses exact planted decoys, applies Landlock
ABI v4 and seccomp denials, observes results with ptrace, enforces resource limits, and
cleans up the full process group. Docker returned `EPERM` for network-namespace creation;
Landlock and seccomp independently enforced and verified egress denial instead. ADR 0011
records both the accepted fail-closed boundary and this platform limitation. The candidate
workflow must still reproduce the release runner and checks on Linux x86-64.

## Optional adjudication is not the detector

A9 does not send artifacts to a built-in model. It is an off-by-default command contract
for normalized evidence on genuinely contested risk findings. The selector is
`floor(total_findings × 0.05)`, never rounded up, and considers only mid-confidence risk
findings. A scan with fewer than 20 findings sends nothing.

The command configured in `DIVERGENCE_ADJUDICATOR_COMMAND` receives one JSON object on
stdin and returns `confirm`, `dismiss`, or `uncertain` plus a reason. Adjudication is a
supplemental record; it never mutates the deterministic finding. ADR 0009 defines the exact
contract. The command runs only when a caller also passes `divergence scan --adjudicate`
or sets `ScanOptions(adjudicate=True)` in the pipeline API.

## Third-party baselines

External execution is opt-in and package versions are pinned where the registry permits.
Semgrep runs the exact `semgrep@1.173.0` package and refuses mutable registry aliases:
`DIVERGENCE_SEMGREP_RULESET` must identify a reviewed local rules file or directory, and
the adapter records its content SHA-256.

The candidate Semgrep run used rules SHA-256
`f8b8461199c4d0ac23c0faf60f8b00a50139854d742e5b7374ccde09f81c9afd`. It found 30/50
positives and produced seven false positives across all controls, five of them in the 35
trap fixtures. Its 14.3% trap FPR remains materially above Divergence's 0/35, while its
60% recall is slightly above static Divergence and far below the hardened dynamic row.

mcp-shield supports only 66.4% of this mixed MCP-server/agent-skill corpus. Its honest
denominators are therefore 4/21 trap false positives and 1/33 positives found, with 20%
precision. The keyword control alarms on 20/35 traps and finds 27/50 positives. Coverage
and applicability are part of the result rather than silently counting unsupported inputs.

`snyk-agent-scan` 0.6.0 requires a Snyk account token and sends tool descriptions to a
hosted API. The adapter reports it unavailable without that token rather than scoring it
as zero. Vendor credentials do not belong in public reproducibility CI. ADR 0006 records
the observed constraint and input-shim tradeoffs.

These external rows are included in the tracked candidate evidence, not carried forward
from the old corpus. `snyk-agent-scan` remains explicitly unavailable.

## Limitations

- The corpus and scanner share an author. The holdout suite helps, but does not create
  independent ground truth.
- Every fixture is synthetic, so performance may not transfer to the distribution of
  artifacts in public registries.
- The obfuscated positive set has 25 samples. Its 24/25 dynamic-gate estimate still has a wide
  80.5%–99.3% Wilson interval.
- Static extraction cannot follow arbitrary spawned programs, native binaries, or every
  dynamically assembled call.
- Dynamic evidence is path-dependent. “Not observed” is not “impossible,” so entrypoint and
  syscall coverage travels with each result.
- mcp-shield covers only 66.4% of the corpus, so its smaller denominators are not directly
  comparable without the coverage qualifier.
- A9 output is provider-dependent and is excluded from the deterministic benchmark.

The locked P6 gate addresses the most important social limitation: someone other than the
author must install the candidate, run it, and file an issue before release completion.
Independent human review of the synthetic labels and rationales is also still open. These
checks, Linux x86-64 candidate-workflow reproduction, and protected tag/PyPI/GitHub
publication are why tracked candidate evidence is not described here as a completed
release.

## Reproducing the candidate

```bash
uv sync --frozen --extra dev
uv run ruff check .
uv run ruff format --check .
uv run pyright
uv run pytest --cov --cov-branch --cov-report=term-missing
uv run divergence-bench validate --check-p0-target
uv run divergence-bench bench --detail \
  --json out/bench.json --markdown out/bench.md
uv build --clear --no-sources
```

The local candidate run passed 384 tests and 83.67% branch coverage against the retained
80% threshold; Ruff and Pyright were clean. Python dependency and RustSec audits also
reported no known advisories. On a verified Linux host, run `make sandbox-gate` and then
`make bench-dynamic`. Third-party tools require
`DIVERGENCE_ALLOW_EXTERNAL=1 make bench-external`.

The tracked static/external and Linux dynamic JSON share analyzer-source SHA-256
`71aa8d411a8eba580c0ea7b40db7cec4d7550e47c7c78f4195ee5bb16628d15b` and record
the exact runtime parser versions. Available scanner rows contain zero errors; errored
samples are excluded from outcome denominators and make the benchmark command fail.

See [`docs/RELEASING.md`](RELEASING.md) for the external-user, PyPI, tag, and GitHub
release steps that remain.

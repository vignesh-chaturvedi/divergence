# Releasing Divergence 1.1

Local release engineering is complete, but v1.1 is not published or tagged. The canonical
version is `divergence.__version__`; Hatch reads it into distribution metadata. The PyPI
distribution is `divergence-mcp`, while the commands remain `divergence` and
`divergence-bench`.

## Local and CI candidate checks

```bash
uv sync --frozen --extra dev
uv run ruff check .
uv run ruff format --check .
uv run pyright
uv run pytest --cov --cov-branch --cov-report=term-missing
uv run divergence-bench validate --check-p0-target
uv run divergence-bench bench --detail --json out/bench.json --markdown out/bench.md
uv build --clear --no-sources
```

The manual `release-candidate` GitHub workflow performs the same build and an installed-
wheel smoke test. Its Linux job also formats, lints, tests, builds, probes, hashes, and
uploads the `divergence-sandbox` x86-64 runner with the containment-gate log. The workflow
has no package-index permission and does not publish anything.

The last local quality run passed 384 tests with 83.67% branch coverage against the
unchanged 80% threshold. Ruff and Pyright passed, and Python dependency and RustSec audits
reported no known advisories. The versioned candidate benchmark evidence lives under
`benchmarks/v1.1/`.

Both tracked benchmark JSON files bind their results to analyzer-source SHA-256
`71aa8d411a8eba580c0ea7b40db7cec4d7550e47c7c78f4195ee5bb16628d15b`, the corpus
digest, and exact runtime parser versions. Available rows contain zero scanner errors;
the benchmark command fails by default instead of publishing a partial errored table.

## Local gates completed

- The corpus is 110 synthetic artifacts: 50 positives and 60 controls. Its 30-sample
  obfuscated stratum contains 25 positives and five matched controls.
- Static and fleet rows have 0/35 trap false positives, 27/50 recall, and 100% precision.
  Attribution is 77.8% and 85.2%, respectively.
- On unprivileged Linux arm64, the fail-closed sandbox gate recovered 24/25 obfuscated
  positives (96%; Wilson 95% CI 80.5%–99.3%) and kept all five controls clean. The full
  dynamic row has 0/35 trap false positives, 49/50 recall (98%; CI 89.5%–99.6%), 100%
  precision, and 87.8% attribution. Runtime entrypoints were confirmed for 83/110 fixtures;
  JSON records coverage per sample.
- The Linux arm64 run verified root refusal and an unprivileged identity, `env_clear` with
  private `HOME`, exact decoys, Landlock ABI v4, seccomp denial, ptrace results, resource
  limits, and process-tree cleanup. Docker did not permit a network namespace; verified
  Landlock and seccomp rules enforced egress denial instead. ADR 0011 records the boundary.
- Available external baselines were rerun with provenance. Semgrep 1.173.0 used rules hash
  `f8b8461199c4d0ac23c0faf60f8b00a50139854d742e5b7374ccde09f81c9afd` and recorded
  5/35 trap false positives, 30/50 recall, and 81.1% precision (seven total false positives).
  mcp-shield recorded 4/21 trap false positives, 1/33 recall, 20% precision, and explicit
  66.4% corpus coverage. The keyword control recorded 20/35 and 27/50 respectively. Snyk
  remains unavailable without a vendor token and hosted API.

## Gates that require external state or an independent human

1. Complete an independent human review of every corpus label and rationale. If review
   changes truth or bytes, regenerate `benchmarks/v1.1/` and re-review the resulting diff.
2. Run the manual candidate workflow to reproduce the Linux x86-64 sandbox artifact,
   checksums, kernel probe, and containment log. The verified local evidence is Linux
   arm64; architecture-specific release artifacts must come from the workflow.
3. Have someone other than the author install the built wheel in a clean environment,
   scan an artifact, and file a GitHub issue. This is the locked P6 exit gate.
4. Recheck `https://pypi.org/pypi/divergence-mcp/json`. It returned HTTP 404 on
   2026-08-20, which is evidence of current availability, not a reservation.
5. Configure PyPI Trusted Publishing for this repository and a protected release
   environment. Review the wheel contents and provenance before granting publish authority.

## Publication sequence

Only after every gate above passes:

1. Confirm that the independently reviewed corpus digest matches the tracked benchmark
   evidence, or regenerate and review the JSON/Markdown if it changed.
2. Change the changelog heading from “release candidate” to the actual release date; remove
   the candidate qualifier from `CITATION.cff` and add `date-released`.
3. Commit the release, create the signed `v1.1.0` tag, and build from that tag.
4. Publish `divergence-mcp` to PyPI through the protected environment.
5. Create a GitHub release with the wheel, sdist, benchmark JSON, corpus digest, and Linux
   sandbox report. Attach the checksummed `divergence-sandbox-1.1.0-linux-x86_64.tar.gz`
   produced by the candidate workflow; the tar archive preserves the executable bit.
6. Verify from a clean directory:

   ```bash
   uvx --from divergence-mcp==1.1.0 divergence --help
   uvx --from divergence-mcp==1.1.0 divergence-bench validate --check-p0-target
   ```

Tagging, PyPI upload, and GitHub release creation are intentionally not automated by the
candidate workflow.

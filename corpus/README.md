# Divergence benchmark corpus

## License and origin

The v1.1 candidate corpus contains **synthetic fixtures authored for this project**. The
artifacts are not copied from, derived from, or snapshots of packages in public registries.
Package names, publishers, versions, registry records, URLs, and histories that appear
inside a fixture are synthetic test data unless a future sample explicitly says otherwise.

The corpus is licensed under the repository's [Apache License 2.0](../LICENSE). There are
no per-sample upstream licenses in the current dataset because there are no derived samples.

This differs from the locked spec's proposed benign-plain stratum of public-registry
artifacts. The present benign set tests false-positive behavior but does **not** establish a
real-world registry base rate. Publications must carry that limitation.

## Dataset identity

`dataset.yaml` records the dataset version, truth counts, license, and provenance class.
`obfuscated-design.yaml` freezes the expanded cohort's families, truth labels, and expected
static/dynamic capability gaps before the final Linux measurement. Benchmark JSON records a
SHA-256 over both manifests plus every `sample.yaml` and artifact file, using
checkout-independent relative paths.

Ground truth is the explicit `label.malicious` boolean in each `sample.yaml`. The `stratum`
field describes the experiment, not the verdict; the 30-sample obfuscated stratum contains
25 positive simulations and five matched benign controls.

## Policy for future upstream or derived samples

Any sample copied or adapted from another project must add this mapping to `sample.yaml`:

```yaml
provenance:
  origin: derived
  upstream_url: https://example.invalid/owner/project
  upstream_revision: immutable-commit-or-release-digest
  upstream_version: 1.2.3
  upstream_license: SPDX-Identifier
  retrieved: YYYY-MM-DD
  changes: Description of every material modification and inerting step.
```

The contributor must preserve every license, notice, and attribution required by the
upstream; use an immutable revision; document how executable or live-network behavior was
made inert; and obtain a label review. A URL or package name without version and license is
not sufficient provenance.

Synthetic additions declare `provenance.origin: synthetic`. The original fixtures inherit
the dataset-level synthetic declaration to avoid a mechanical metadata-only rewrite.

## Safety

Positive fixtures may target only loopback, reserved domains, or planted decoys. They are
intended for static inspection. Do not execute them outside the verified fail-closed Linux
sandbox. Report a fixture that can reach a real endpoint or host credential through the
repository's private security channel.

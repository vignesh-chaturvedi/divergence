# Divergence — P0 benchmark
#
# `make bench` is the P0 exit gate: from a clean checkout it must reproduce the
# baseline comparison table. Everything here stays offline unless you explicitly
# opt in to third-party scanners with DIVERGENCE_ALLOW_EXTERNAL=1.

.PHONY: help install validate describe test bench bench-detail bench-external bench-dynamic capabilities sandbox sandbox-gate release-build scan inspect fleet clean

BENCH := uv run divergence-bench

help:
	@echo "install       uv sync, pinned to Python 3.12"
	@echo "validate      every sample well-formed, rationalised and inert"
	@echo "describe      list the corpus without running anything"
	@echo "test          unit tests"
	@echo "bench         the baseline comparison table  <- P0 exit gate"
	@echo "bench-detail  ... plus per-attack-class and per-trap-family breakdowns"
	@echo "capabilities  B_s extraction vs verified ground truth  <- P2 exit gate"
	@echo "bench-external  ... including third-party scanners (downloads + executes them)"
	@echo "sandbox-gate  B_dynamic vs B_static on the obfuscated stratum  <- P5 exit gate (Linux)"
	@echo "bench-dynamic registered static+dynamic benchmark row (Linux; executes fixtures)"
	@echo "release-build clear stale dist files, then build the pinned wheel and sdist"
	@echo ""
	@echo "scan TARGET=<path>     run the scanner over a directory or MCP client config"
	@echo "inspect TARGET=<path>  print an artifact's declared surface, run nothing"
	@echo "fleet TARGET=<path>    cross-artifact analysis over an installed set"
	@echo ""
	@echo "Third-party scanners are gated. To include them:"
	@echo "  DIVERGENCE_ALLOW_EXTERNAL=1 DIVERGENCE_SEMGREP_RULESET=<snapshot> make bench-external"

install:
	uv sync --frozen --extra dev

release-build:
	uv build --clear --no-sources

validate:
	$(BENCH) validate --check-p0-target

describe:
	$(BENCH) describe

test:
	uv run pytest --cov --cov-branch --cov-report=term-missing

bench:
	$(BENCH) bench --json out/bench.json

capabilities:
	$(BENCH) capabilities

# Linux only. Builds the crate, then measures what execution reveals that parsing cannot.
sandbox:
	cd sandbox && cargo build --locked --release

sandbox-gate: sandbox
	DIVERGENCE_SANDBOX_BIN=sandbox/target/release/divergence-sandbox $(BENCH) sandbox-gate --require-available

bench-dynamic: sandbox
	DIVERGENCE_ALLOW_DYNAMIC=1 DIVERGENCE_SANDBOX_BIN=sandbox/target/release/divergence-sandbox \
	  $(BENCH) bench --scanner divergence --scanner divergence+dynamic \
	  --markdown out/table-dynamic.md --json out/bench-dynamic.json

# Downloads and executes third-party scanners. Opt-in by construction.
bench-external:
	DIVERGENCE_ALLOW_EXTERNAL=1 $(BENCH) bench \
	  --scanner divergence --scanner divergence+fleet --scanner keyword --scanner null \
	  --scanner mcp-shield --scanner semgrep --scanner snyk-agent-scan --detail \
	  --markdown out/table.md --json out/bench-external.json

bench-detail:
	$(BENCH) bench --detail --json out/bench.json

TARGET ?= .

scan:
	uv run divergence scan $(TARGET)

inspect:
	uv run divergence inspect $(TARGET)

fleet:
	uv run divergence fleet $(TARGET)

clean:
	rm -rf out .pytest_cache .bench-cache
	find . -name __pycache__ -type d -prune -exec rm -rf {} +

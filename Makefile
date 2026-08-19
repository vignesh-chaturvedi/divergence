# Divergence — P0 benchmark
#
# `make bench` is the P0 exit gate: from a clean checkout it must reproduce the
# baseline comparison table. Everything here stays offline unless you explicitly
# opt in to third-party scanners with DIVERGENCE_ALLOW_EXTERNAL=1.

.PHONY: help install validate describe test bench bench-detail scan inspect clean

BENCH := uv run divergence-bench

help:
	@echo "install       uv sync, pinned to Python 3.12"
	@echo "validate      every sample well-formed, rationalised and inert"
	@echo "describe      list the corpus without running anything"
	@echo "test          unit tests"
	@echo "bench         the baseline comparison table  <- P0 exit gate"
	@echo "bench-detail  ... plus per-attack-class and per-trap-family breakdowns"
	@echo ""
	@echo "scan TARGET=<path>     run the scanner over a directory or MCP client config"
	@echo "inspect TARGET=<path>  print an artifact's declared surface, run nothing"
	@echo ""
	@echo "Third-party scanners are gated. To include them:"
	@echo "  DIVERGENCE_ALLOW_EXTERNAL=1 make bench"

install:
	uv sync --extra dev

validate:
	$(BENCH) validate --check-p0-target

describe:
	$(BENCH) describe

test:
	uv run pytest

bench:
	$(BENCH) bench --json out/bench.json

bench-detail:
	$(BENCH) bench --detail --json out/bench.json

TARGET ?= .

scan:
	uv run divergence scan $(TARGET)

inspect:
	uv run divergence inspect $(TARGET)

clean:
	rm -rf out .pytest_cache .bench-cache
	find . -name __pycache__ -type d -prune -exec rm -rf {} +

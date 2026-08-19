"""The P0 exit gate: `make bench` reproduces a stable table.

Runs the deterministic reference scanners twice and asserts the JSON results are
byte-identical. If claim extraction or any future model input made the benchmark
non-deterministic, this is the test that would catch it.
"""

from divergence.adapters.base import run_adapter
from divergence.adapters.reference import KeywordScanner, NullScanner
from divergence.bench.metrics import score_all
from divergence.bench.report import comparison_table, to_json


def _table_and_json(samples):
    runs = [run_adapter(NullScanner(), samples), run_adapter(KeywordScanner(), samples)]
    scores = score_all(samples, runs)
    return comparison_table(scores), to_json(samples, scores)


def test_bench_is_deterministic(samples):
    table1, json1 = _table_and_json(samples)
    table2, json2 = _table_and_json(samples)
    assert table1 == table2
    assert json1 == json2


def test_headline_metric_present_in_json(samples):
    _, payload = _table_and_json(samples)
    import json as _json
    data = _json.loads(payload)
    by_name = {s["name"]: s for s in data["scanners"]}
    assert by_name["null"]["fpr_on_traps"] == 0.0
    assert by_name["keyword"]["fpr_on_traps"] > 0.3
    assert data["corpus"]["total"] == 80

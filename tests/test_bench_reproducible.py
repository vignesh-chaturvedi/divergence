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
    # Wall-clock duration is provenance and intentionally varies. All inputs and scores
    # must remain identical after removing that one observational field.
    import json as _json

    payload1, payload2 = _json.loads(json1), _json.loads(json2)
    for payload in (payload1, payload2):
        for scanner in payload["scanners"]:
            scanner.pop("duration_s")
    assert payload1 == payload2


def test_headline_metric_present_in_json(samples):
    _, payload = _table_and_json(samples)
    import json as _json

    data = _json.loads(payload)
    by_name = {s["name"]: s for s in data["scanners"]}
    assert by_name["null"]["fpr_on_traps"] == 0.0
    assert by_name["keyword"]["fpr_on_traps"] > 0.3
    assert data["corpus"]["total"] >= 80
    assert data["corpus"]["malicious"] == 50
    assert data["corpus"]["benign"] == 60
    assert data["corpus"]["origin"] == "synthetic"
    assert data["corpus"]["license"] == "Apache-2.0"
    assert len(data["corpus"]["sha256"]) == 64
    assert data["schema"] == "divergence-benchmark/v1"
    assert data["project"]["version"] == "1.1.0"
    assert data["runtime"]["python"]
    assert data["runtime"]["platform"]
    assert by_name["null"]["version"] != "unknown"
    assert by_name["null"]["duration_s"] >= 0
    assert by_name["null"]["provenance"]["python"]
    trap_estimate = by_name["null"]["estimates"]["fpr_on_traps"]
    assert trap_estimate["numerator"] == 0
    assert trap_estimate["denominator"] == 35
    assert trap_estimate["wilson95"]["high"] > 0.09

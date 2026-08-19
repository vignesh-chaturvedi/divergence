"""SARIF output.

The contract that matters is the channel split: a consumer must be able to drop posture
entirely, and must never see it as an error.
"""

import json

from divergence.core.sarif import to_sarif
from divergence.core.vocabulary import AttackClass, Channel, Finding


def _risk(**kw):
    base = dict(
        sample_id="s", channel=Channel.RISK, attack_class=AttackClass.ANNOTATION_LIE,
        severity="critical", message="m", evidence="server.py:17", claim="c",
    )
    base.update(kw)
    return Finding(**base)


def _posture(**kw):
    base = dict(
        sample_id="s", channel=Channel.POSTURE, severity="low",
        message="broad access", evidence="server.py:3", claim="posture",
    )
    base.update(kw)
    return Finding(**base)


def test_document_validates_against_the_basic_shape():
    doc = to_sarif([_risk()])
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["tool"]["driver"]["name"] == "Divergence"
    assert doc["runs"][0]["results"]


def test_posture_is_never_an_error():
    doc = to_sarif([_posture(severity="critical")])
    assert doc["runs"][0]["results"][0]["level"] == "note"


def test_risk_severity_maps_to_error():
    assert to_sarif([_risk(severity="critical")])["runs"][0]["results"][0]["level"] == "error"
    assert to_sarif([_risk(severity="high")])["runs"][0]["results"][0]["level"] == "error"
    assert to_sarif([_risk(severity="low")])["runs"][0]["results"][0]["level"] == "note"


def test_channel_is_filterable_on_every_result():
    doc = to_sarif([_risk(), _posture()])
    channels = [r["properties"]["divergence.channel"] for r in doc["runs"][0]["results"]]
    assert channels == ["risk", "posture"]


def test_evidence_becomes_a_physical_location():
    result = to_sarif([_risk(evidence="src/server.py:42")])["runs"][0]["results"][0]
    loc = result["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "src/server.py"
    assert loc["region"]["startLine"] == 42


def test_evidence_without_a_line_still_produces_a_location():
    result = to_sarif([_risk(evidence="manifest.json")])["runs"][0]["results"][0]
    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "manifest.json"
    assert "region" not in result["locations"][0]["physicalLocation"]


def test_the_claim_half_survives_into_sarif():
    """A consumer showing only the message would strip what makes a finding reviewable."""
    result = to_sarif([_risk(claim="readOnlyHint = true")])["runs"][0]["results"][0]
    assert result["properties"]["divergence.claim"] == "readOnlyHint = true"


def test_rules_are_deduplicated():
    doc = to_sarif([_risk(), _risk(), _risk()])
    assert len(doc["runs"][0]["tool"]["driver"]["rules"]) == 1


def test_empty_findings_produce_a_valid_empty_run():
    doc = to_sarif([])
    assert doc["runs"][0]["results"] == []
    assert json.loads(json.dumps(doc))

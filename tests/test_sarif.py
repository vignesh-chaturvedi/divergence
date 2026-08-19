import re
from pathlib import Path
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


# --- regressions from the first CI run ------------------------------------------------
# GitHub code scanning rejected the uploaded SARIF outright. Both causes are here, because
# a schema-valid document that a consumer refuses is not valid in any useful sense.

def _uris(doc):
    out = []
    for r in doc["runs"][0]["results"]:
        for loc in r.get("locations", []):
            out.append(loc["physicalLocation"]["artifactLocation"]["uri"])
    return out


def test_prose_evidence_never_becomes_a_uri():
    """Fleet findings carry prose, not `file:line`.

    `'code-review-pro: publisher=unknown, ...'` was emitted as an artifactLocation URI,
    and GitHub parsed the leading `code-review-pro:` as a URI *scheme*, failing the whole
    upload. Anything that is not path-shaped must not be a location.
    """
    findings = [
        Finding(
            sample_id="code-review-pro",
            channel=Channel.RISK,
            attack_class=AttackClass.SHADOWING,
            severity="critical",
            message="'code-review-pro' closely imitates 'code-review'",
            evidence="code-review-pro: publisher=unknown, signed=None, downloads30d=None",
            claim="code-review: publisher=unknown",
        ),
    ]
    doc = to_sarif(findings)
    for uri in _uris(doc):
        assert ":" not in uri, f"prose leaked into a URI: {uri!r}"
        assert " " not in uri


def test_prose_evidence_is_preserved_in_properties():
    """Dropping it from the location must not drop it from the finding."""
    findings = [
        Finding(
            sample_id="installed-config",
            channel=Channel.POSTURE,
            severity="medium",
            message="toxic flow available across this config",
            evidence="16 artifacts in the installed set",
            claim="posture: no single artifact declares this path",
        ),
    ]
    result = to_sarif(findings)["runs"][0]["results"][0]
    assert result["properties"]["divergence.evidence"] == "16 artifacts in the installed set"


def test_every_uri_is_relative_and_scheme_free():
    """Code scanning compares the SARIF URI scheme against the checkout's `file` scheme."""
    findings = [
        Finding(sample_id="a", channel=Channel.RISK, attack_class=AttackClass.UNDECLARED_NETWORK,
                severity="high", message="m", evidence="scripts/collect.py:7", claim="c"),
        Finding(sample_id="b", channel=Channel.POSTURE, severity="low",
                message="m", evidence="16 artifacts in the installed set", claim="c"),
    ]
    for uri in _uris(to_sarif(findings)):
        assert not uri.startswith("/"), f"absolute path: {uri}"
        assert "://" not in uri
        # A bare `word:` prefix is what GitHub reads as a scheme.
        assert not re.match(r"^[A-Za-z][A-Za-z0-9+.\-]*:", uri), f"looks like a scheme: {uri}"


def test_roots_make_locations_repo_relative():
    """`scripts/collect.py` is relative to the artifact, not to the checkout.

    Without this the alert points at a path that does not exist in the repository.
    """
    findings = [
        Finding(sample_id="code-formatter", channel=Channel.RISK,
                attack_class=AttackClass.UNDECLARED_NETWORK, severity="high",
                message="m", evidence="scripts/collect.py:7", claim="c"),
    ]
    doc = to_sarif(findings, roots={"code-formatter": Path("corpus/fleets/x/members/cf")})
    assert _uris(doc) == ["corpus/fleets/x/members/cf/scripts/collect.py"]
    region = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
    assert region["startLine"] == 7


def test_real_fleet_scan_produces_only_valid_uris():
    """End to end against the actual fleet — this is what CI uploads."""
    from divergence.core.fleet import analyze_fleet, load_fleet

    fleet = load_fleet(Path("corpus/fleets/installed-config/fleet.yaml"))
    findings = analyze_fleet(fleet)
    roots = {m.id: m.root for m in fleet.members}

    for uri in _uris(to_sarif(findings, roots=roots)):
        assert not re.match(r"^[A-Za-z][A-Za-z0-9+.\-]*:", uri), f"invalid URI: {uri!r}"
        assert " " not in uri, f"space in URI: {uri!r}"


def test_check_rejects_a_scheme_like_uri(tmp_path):
    """The validator must catch exactly what CI caught."""
    from divergence.core.sarif import check

    bad = tmp_path / "bad.sarif"
    bad.write_text(json.dumps({
        "version": "2.1.0",
        "runs": [{"results": [{
            "ruleId": "x",
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": "code-review-pro: publisher=unknown"}}}],
        }]}],
    }))
    problems = check(bad)
    assert problems and "scheme" in problems[0]


def test_check_passes_a_real_fleet_sarif(tmp_path):
    from divergence.core.fleet import analyze_fleet, load_fleet
    from divergence.core.sarif import check, dumps

    fleet = load_fleet(Path("corpus/fleets/installed-config/fleet.yaml"))
    out = tmp_path / "f.sarif"
    out.write_text(dumps(
        analyze_fleet(fleet),
        roots={m.id: m.root for m in fleet.members},
        anchor="corpus/fleets/installed-config/fleet.yaml",
    ))
    assert check(out) == []

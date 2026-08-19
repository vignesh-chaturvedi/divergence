"""Verify the third-party output parsers against captured fixtures.

None of these tools need to be installed. An adapter's parser is pure — stdout string in,
normalised Findings out — so the risky part is tested without ever executing external code.
This is what lets us ship real adapters that stay dormant until explicitly enabled.
"""

import json

from divergence.adapters.external import (
    map_attack_class,
    parse_flat_json_issues,
    parse_sarif,
)
from divergence.bench.models import AttackClass, Channel, Kind, Sample, Stratum
from pathlib import Path


def _sample():
    return Sample(
        id="fix-1", kind=Kind.MCP_SERVER, stratum=Stratum.MALICIOUS, language="python",
        rationale="x" * 130, path=Path("."), artifact_path=Path("."),
    )


def test_map_attack_class_aliases_and_passthrough():
    assert map_attack_class("prompt_injection") is AttackClass.DESCRIPTION_POISONING
    assert map_attack_class("tool-poisoning") is AttackClass.DESCRIPTION_POISONING
    assert map_attack_class("shadowing") is AttackClass.SHADOWING  # exact enum value
    assert map_attack_class("rug pull") is AttackClass.POST_APPROVAL_MUTATION
    assert map_attack_class("something_unknown") is None
    assert map_attack_class(None) is None


def test_parse_flat_json_issues_shape():
    stdout = json.dumps({"issues": [
        {"type": "prompt_injection", "severity": "high", "message": "poisoned description"},
        {"type": "wildcard", "severity": "info", "message": "broad permissions"},
    ]})
    findings = parse_flat_json_issues(stdout, _sample())
    assert len(findings) == 2
    assert findings[0].channel is Channel.RISK
    assert findings[0].attack_class is AttackClass.DESCRIPTION_POISONING
    # 'info' severity routes to posture, not risk.
    assert findings[1].channel is Channel.POSTURE


def test_parse_flat_json_bare_list():
    stdout = json.dumps([{"category": "data_exfiltration", "severity": "critical"}])
    findings = parse_flat_json_issues(stdout, _sample())
    assert findings[0].attack_class is AttackClass.UNDECLARED_NETWORK
    assert findings[0].channel is Channel.RISK


def test_parse_flat_json_handles_garbage():
    assert parse_flat_json_issues("not json at all", _sample()) == []
    assert parse_flat_json_issues("", _sample()) == []


def test_parse_sarif_shape():
    sarif = {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "semgrep"}},
            "results": [
                {"ruleId": "command_injection", "level": "error",
                 "message": {"text": "subprocess with shell=True"},
                 "locations": [{"physicalLocation": {
                     "artifactLocation": {"uri": "server.py"},
                     "region": {"startLine": 12}}}]},
                {"ruleId": "style", "level": "note",
                 "message": {"text": "informational"}},
            ],
        }],
    }
    findings = parse_sarif(json.dumps(sarif), _sample())
    assert len(findings) == 2
    assert findings[0].attack_class is AttackClass.UNDECLARED_EXEC
    assert findings[0].channel is Channel.RISK
    assert findings[0].evidence == "server.py:12"
    # 'note' level is posture.
    assert findings[1].channel is Channel.POSTURE


def test_parse_sarif_handles_garbage():
    assert parse_sarif("{}", _sample()) == []
    assert parse_sarif("garbage", _sample()) == []

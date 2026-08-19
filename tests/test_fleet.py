"""The P4 exit gate, as an executable assertion.

§07: "Detects a planted shadow tool and an over-triggering skill inside a realistic
multi-artifact config, without flagging the legitimate originals."

The second half is the hard half. Anything can flag a near-duplicate; the gate is passing
over the artifact being imitated, which looks almost identical by construction.
"""

from pathlib import Path

import pytest

from divergence.core.fleet import analyze_fleet, load_fleet
from divergence.core.vocabulary import AttackClass, Channel

FLEET = Path(__file__).resolve().parent.parent / "corpus" / "fleets" / "installed-config"


@pytest.fixture(scope="module")
def fleet():
    return load_fleet(FLEET / "fleet.yaml")


@pytest.fixture(scope="module")
def findings(fleet):
    return analyze_fleet(fleet)


def _risks_for(findings, member_id):
    return [
        f for f in findings
        if f.channel is Channel.RISK and f.sample_id == member_id
    ]


def _classes_for(findings, member_id):
    return {f.attack_class for f in _risks_for(findings, member_id)}


# --- the gate -------------------------------------------------------------------------

def test_fleet_loads_every_member(fleet):
    assert len(fleet.members) == 16


def test_planted_shadow_server_is_caught(findings):
    assert AttackClass.SHADOWING in _classes_for(findings, "github-plus")


def test_planted_shadow_skill_is_caught(findings):
    assert AttackClass.SHADOWING in _classes_for(findings, "code-review-pro")


def test_typosquat_shadow_is_caught(findings):
    assert AttackClass.SHADOWING in _classes_for(findings, "filesystem-mcp-server")


def test_over_triggering_skill_is_caught(findings):
    assert AttackClass.TRIGGER_SCOPE_HIJACK in _classes_for(findings, "code-formatter")


def test_preference_manipulation_is_caught(findings):
    assert AttackClass.PREFERENCE_MANIPULATION in _classes_for(findings, "websearch")


def test_legitimate_originals_are_not_flagged(findings, fleet):
    """The hard half of the gate."""
    offenders = []
    for member_id in fleet.expected["must_stay_clean"]:
        for f in _risks_for(findings, member_id):
            offenders.append(f"{member_id}: {f.attack_class}")
    assert offenders == [], "\n".join(offenders)


# --- toxic flow -----------------------------------------------------------------------

def test_toxic_flow_path_is_reported(findings):
    flows = [f for f in findings if f.attack_class is AttackClass.CROSS_TOOL_INSTRUCTION
             or "toxic flow" in f.message.lower()]
    assert flows, "no toxic-flow path reported for a fleet that has one"


def test_toxic_flow_is_posture_not_a_verdict_on_honest_members(findings):
    """A capability combination is posture by the project's own rule.

    `web-fetcher`, `vault` and `http-post` each declare exactly what they do. The flow
    between them is worth surfacing and must not condemn any of them.
    """
    for member_id in ("web-fetcher", "vault", "http-post"):
        assert _risks_for(findings, member_id) == []


# --- evidence -------------------------------------------------------------------------

def test_every_fleet_risk_names_its_counterpart(findings):
    """A shadowing finding is meaningless without saying what is being shadowed."""
    for f in findings:
        if f.channel is Channel.RISK and f.attack_class is AttackClass.SHADOWING:
            assert f.claim and f.evidence


def test_fleet_analysis_is_deterministic(fleet):
    first = [(f.sample_id, f.attack_class, f.message) for f in analyze_fleet(fleet)]
    second = [(f.sample_id, f.attack_class, f.message) for f in analyze_fleet(fleet)]
    assert first == second

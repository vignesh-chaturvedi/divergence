"""B_dynamic parsing, degradation, and the sixth rule-table row.

These run everywhere, including macOS where the sandbox cannot execute — the parsing and
rule logic are pure functions over a JSON contract, so they are testable without a kernel.
That separation is deliberate: it is what lets the optional dependency stay genuinely
optional instead of becoming an untested corner.
"""

import json

from divergence.core.sandbox import Dynamic, Observation, parse_report, unavailable
from divergence.core.vocabulary import Capability

SAMPLE = {
    "schema": "divergence.sandbox/1",
    "capabilities": ["net_outbound", "secrets_read"],
    "observations": [
        {"capability": "net_outbound", "syscall": "connect", "target": "127.0.0.1:9", "decoy": False},
        {"capability": "secrets_read", "syscall": "openat", "target": "/root/.ssh/id_rsa", "decoy": True},
    ],
    "coverage": {
        "syscalls_observed": 812, "entrypoints_invoked": 1,
        "exited_cleanly": True, "exit_code": 0, "timed_out": False,
    },
    "evidence": {"net_outbound": "connect(127.0.0.1:9)"},
    "limitations": ["env_read is not observable via syscalls"],
}


def test_parses_capabilities_and_coverage():
    d = parse_report(json.dumps(SAMPLE))
    assert d.available
    assert d.capabilities == {Capability.NET_OUTBOUND, Capability.SECRETS_READ}
    assert d.syscalls_observed == 812
    assert d.ran


def test_decoy_reads_are_isolated():
    """A decoy read is unambiguous — nothing legitimate opens a planted fake key."""
    d = parse_report(json.dumps(SAMPLE))
    assert len(d.decoy_reads) == 1
    assert d.decoy_reads[0].target == "/root/.ssh/id_rsa"


def test_unknown_capability_is_skipped_not_fatal():
    """A newer runner must degrade this build, not crash it."""
    doc = dict(SAMPLE)
    doc["observations"] = [
        {"capability": "quantum_entanglement", "syscall": "x", "target": "y"},
        {"capability": "net_outbound", "syscall": "connect", "target": "z"},
    ]
    d = parse_report(json.dumps(doc))
    assert d.capabilities == {Capability.NET_OUTBOUND}


def test_invalid_json_degrades():
    assert not parse_report("not json").available


def test_empty_set_with_no_syscalls_is_unknown_not_clean():
    """The distinction the coverage note exists to make.

    An empty capability set means "does nothing" only if something ran. Otherwise it means
    "nothing ran", and those are opposite conclusions.
    """
    doc = dict(SAMPLE, observations=[], coverage={"syscalls_observed": 0, "entrypoints_invoked": 0,
                                                  "exited_cleanly": False, "exit_code": -1, "timed_out": False})
    d = parse_report(json.dumps(doc))
    assert d.available
    assert not d.ran
    assert "unknown" in d.coverage_note


def test_unavailable_carries_its_reason():
    d = unavailable("Darwin — Landlock is Linux-only")
    assert not d.available and "Darwin" in d.coverage_note


# --- rule table row six: B_dynamic ⊄ B_static ----------------------------------------

def _static(*caps):
    return set(caps)


def test_runtime_capability_absent_from_source_is_a_finding():
    from divergence.core.engine import dynamic_divergence

    dynamic = parse_report(json.dumps(SAMPLE))
    findings = dynamic_divergence(_static(Capability.FS_READ), dynamic, sample_id="obf-001")
    classes = {f.attack_class for f in findings}
    assert classes, "a capability observed at runtime but absent from source was not flagged"


def test_runtime_subset_of_static_raises_no_risk():
    """B_dynamic ⊆ B_static is the normal, healthy case.

    A posture note on the decoy read is still correct and useful — it says *which* path was
    opened. What must not happen is a verdict, because the artifact did exactly what its
    source said it would.
    """
    from divergence.core.engine import dynamic_divergence
    from divergence.core.vocabulary import Channel

    dynamic = parse_report(json.dumps(SAMPLE))
    static = _static(Capability.NET_OUTBOUND, Capability.SECRETS_READ, Capability.FS_READ)
    findings = dynamic_divergence(static, dynamic, sample_id="x")
    assert [f for f in findings if f.channel is Channel.RISK] == []


def test_declared_credential_manager_is_not_condemned_by_the_decoy():
    """The over-flagging guard, stated as its own case.

    A credential manager reads ~/.ssh because that is its job, and the decoy is planted at
    exactly that path. Flagging it would reproduce the failure mode this project exists to
    eliminate.
    """
    from divergence.core.engine import dynamic_divergence
    from divergence.core.vocabulary import Channel

    dynamic = parse_report(json.dumps(SAMPLE))
    findings = dynamic_divergence(
        _static(Capability.SECRETS_READ, Capability.NET_OUTBOUND), dynamic, sample_id="vault"
    )
    assert all(f.channel is Channel.POSTURE for f in findings)


def test_no_findings_when_the_sandbox_did_not_run():
    """Absence of observation is not observation of absence."""
    from divergence.core.engine import dynamic_divergence

    assert dynamic_divergence(_static(), unavailable("macOS"), sample_id="x") == []


def test_every_dynamic_finding_carries_its_coverage():
    """§05: coverage is part of the result, not a footnote."""
    from divergence.core.engine import dynamic_divergence

    dynamic = parse_report(json.dumps(SAMPLE))
    for f in dynamic_divergence(_static(), dynamic, sample_id="x"):
        assert "syscalls observed" in f.claim or "syscalls observed" in f.evidence

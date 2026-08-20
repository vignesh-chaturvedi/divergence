"""B_dynamic parsing, degradation, and the sixth rule-table row.

These run everywhere, including macOS where the sandbox cannot execute — the parsing and
rule logic are pure functions over a JSON contract, so they are testable without a kernel.
That separation is deliberate: it is what lets the optional dependency stay genuinely
optional instead of becoming an untested corner.
"""

import json

from divergence.core.sandbox import _validate_probe, parse_report, unavailable
from divergence.core.vocabulary import Capability

SAMPLE = {
    "schema": "divergence.sandbox/1",
    "runner_version": "1.1.0",
    "capabilities": ["net_outbound", "secrets_read"],
    "observations": [
        {
            "capability": "net_outbound",
            "syscall": "connect",
            "target": "127.0.0.1:9",
            "decoy": False,
            "succeeded": False,
            "result": -1,
        },
        {
            "capability": "secrets_read",
            "syscall": "openat",
            "target": "/tmp/divergence-overlay-1/home/.ssh/id_rsa",
            "decoy": True,
            "succeeded": True,
            "result": 3,
        },
    ],
    "coverage": {
        "syscalls_observed": 812,
        "observations_dropped": 0,
        "entrypoints_invoked": 1,
        "entrypoints_completed": 1,
        "entrypoints_failed": 0,
        "confinement_enforced": True,
        "exited_cleanly": True,
        "exit_code": 0,
        "timed_out": False,
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
    assert d.decoy_reads[0].target.endswith("/home/.ssh/id_rsa")


def test_unknown_capability_is_skipped_not_fatal():
    """A newer runner must degrade this build, not crash it."""
    doc = dict(SAMPLE)
    doc["capabilities"] = ["quantum_entanglement", "net_outbound"]
    doc["observations"] = [
        {
            "capability": "quantum_entanglement",
            "syscall": "x",
            "target": "y",
            "decoy": False,
            "succeeded": False,
            "result": -1,
        },
        {
            "capability": "net_outbound",
            "syscall": "connect",
            "target": "z",
            "decoy": False,
            "succeeded": False,
            "result": -1,
        },
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
    doc = dict(
        SAMPLE,
        capabilities=[],
        observations=[],
        coverage={
            "syscalls_observed": 0,
            "observations_dropped": 0,
            "entrypoints_invoked": 0,
            "entrypoints_completed": 0,
            "entrypoints_failed": 0,
            "confinement_enforced": True,
            "exited_cleanly": False,
            "exit_code": -1,
            "timed_out": False,
        },
    )
    d = parse_report(json.dumps(doc))
    assert d.available
    assert not d.ran
    assert "unknown" in d.coverage_note


def test_unavailable_carries_its_reason():
    d = unavailable("Darwin — Landlock is Linux-only")
    assert not d.available and "Darwin" in d.coverage_note


def test_probe_requires_an_unprivileged_launcher_identity():
    probe = {
        "schema": "divergence.sandbox.probe/1",
        "runner_version": "1.1.0",
        "platform": "linux",
        "available": True,
        "landlock_abi": 4,
        "required_landlock_abi": 4,
        "seccomp_available": True,
        "unprivileged_identity": True,
        "identity_reason": None,
    }
    assert _validate_probe(json.dumps(probe)) == ""

    probe["unprivileged_identity"] = False
    probe["identity_reason"] = "uid 0 is not accepted"
    assert "uid 0" in _validate_probe(json.dumps(probe))


def test_failed_credential_attempt_is_high_signal_but_not_a_decoy_read():
    doc = dict(SAMPLE)
    doc["capabilities"] = ["secrets_read"]
    doc["observations"] = [
        {
            "capability": "secrets_read",
            "syscall": "openat",
            "target": "/root/.ssh/id_rsa",
            "decoy": False,
            "succeeded": False,
            "result": -13,
        }
    ]
    parsed = parse_report(json.dumps(doc))
    assert parsed.capabilities == {Capability.SECRETS_READ}
    assert parsed.decoy_reads == ()
    assert not parsed.observations[0].succeeded


def test_failed_attempt_cannot_be_labeled_a_decoy_read():
    doc = dict(SAMPLE)
    doc["observations"] = [dict(SAMPLE["observations"][1], succeeded=False, result=-13)]
    assert not parse_report(json.dumps(doc)).available


def test_report_requires_schema_shapes_and_confinement():
    wrong_schema = dict(SAMPLE, schema="divergence.sandbox/99")
    assert not parse_report(json.dumps(wrong_schema)).available

    wrong_coverage = dict(SAMPLE, coverage={"syscalls_observed": "many"})
    assert not parse_report(json.dumps(wrong_coverage)).available

    unconstrained = dict(SAMPLE, coverage=dict(SAMPLE["coverage"], confinement_enforced=False))
    parsed = parse_report(json.dumps(unconstrained))
    assert not parsed.available
    assert "Landlock" in parsed.unavailable_reason


def test_non_json_artifact_output_cannot_be_mistaken_for_a_report():
    parsed = parse_report("artifact says hello\n" + json.dumps(SAMPLE))
    assert not parsed.available


def test_coverage_note_distinguishes_attempted_from_succeeded():
    note = parse_report(json.dumps(SAMPLE)).coverage_note
    assert "1/2 recorded operations succeeded" in note


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


def test_gate_models_controls_from_truth_labels_not_a_magic_id():
    from divergence.bench.sandbox_gate import GateReport, SampleDelta

    report = GateReport(
        deltas=[
            SampleDelta(sample_id="payload", malicious=True, risk_findings=1),
            SampleDelta(sample_id="any-control-id", malicious=False, risk_findings=0),
        ]
    )
    assert [delta.sample_id for delta in report.payloads] == ["payload"]
    assert report.caught == 1
    assert report.control_clean


def test_gate_counts_path_bound_decoy_evidence_as_a_catch():
    from divergence.bench.sandbox_gate import GateReport, SampleDelta

    report = GateReport(
        deltas=[
            SampleDelta(
                sample_id="numeric-decoy",
                malicious=True,
                risk_findings=1,
                high_signal_revealed=set(),
            ),
            SampleDelta(sample_id="static-visible", malicious=True, risk_findings=0),
            SampleDelta(sample_id="control", malicious=False, risk_findings=0),
        ]
    )

    assert report.caught == 1
    assert report.catch_rate == 0.5


def test_gate_cannot_pass_vacuously_without_a_control():
    from divergence.bench.sandbox_gate import GateReport, SampleDelta

    report = GateReport(deltas=[SampleDelta(sample_id="payload", malicious=True)])
    assert not report.control_clean

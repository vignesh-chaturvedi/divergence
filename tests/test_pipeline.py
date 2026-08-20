from __future__ import annotations

from divergence.core.adjudicator import Verdict
from divergence.core.pipeline import ScanOptions, dedupe, scan_detailed
from divergence.core.sandbox import Dynamic
from divergence.core.vocabulary import AttackClass, Capability, Channel, Finding


def _finding(evidence: str, confidence: float = 0.8) -> Finding:
    return Finding(
        sample_id="artifact",
        channel=Channel.RISK,
        attack_class=AttackClass.UNDECLARED_NETWORK,
        severity="high",
        message="undeclared network",
        evidence=evidence,
        claim="network was not declared",
        confidence=confidence,
    )


def test_dedupe_keeps_distinct_evidence_locations():
    first = _finding("a.py:10")
    second = _finding("b.py:20")
    assert dedupe([first, second]) == [first, second]


def test_dedupe_keeps_strongest_exact_contradiction():
    weak = _finding("a.py:10", confidence=0.5)
    strong = _finding("a.py:10", confidence=0.9)
    assert dedupe([weak, strong]) == [strong]


def test_dynamic_tier_is_opt_in(monkeypatch, tmp_path):
    (tmp_path / "server.py").write_text(
        "from mcp.server.fastmcp import FastMCP\n"
        "mcp = FastMCP('x')\n"
        "@mcp.tool()\n"
        "def add(a: int, b: int):\n"
        '    """Add two numbers."""\n'
        "    return a + b\n"
    )
    calls: list[object] = []

    def fake_observe(root, *, timeout):
        calls.append((root, timeout))
        return Dynamic(
            available=True,
            capabilities={Capability.NET_OUTBOUND},
            syscalls_observed=1,
            entrypoints_invoked=1,
            exited_cleanly=True,
            evidence={Capability.NET_OUTBOUND: "connect(127.0.0.1:9)"},
        )

    monkeypatch.setattr("divergence.core.pipeline.observe", fake_observe)
    static = scan_detailed(tmp_path, artifact_id="x")
    assert static.dynamic is None
    assert calls == []

    dynamic = scan_detailed(
        tmp_path,
        artifact_id="x",
        options=ScanOptions(dynamic=True, sandbox_timeout=7),
    )
    assert dynamic.dynamic is not None
    assert calls == [(tmp_path, 7)]
    assert any(f.attack_class is AttackClass.DYNAMIC_CODE_LOADING for f in dynamic.findings)


class _Backend:
    name = "test"

    def adjudicate(self, evidence):
        return Verdict.UNCERTAIN, "The normalized evidence is insufficient."


def test_adjudicator_tier_is_explicit_and_budgeted(monkeypatch, tmp_path):
    (tmp_path / "SKILL.md").write_text(
        "---\nname: harmless\ndescription: Read text files.\nallowed-tools: Read\n---\n"
    )
    # A small real scan has no 5% integer budget, so enabling A9 must still make zero calls.
    report = scan_detailed(
        tmp_path,
        artifact_id="x",
        options=ScanOptions(adjudicate=True, adjudicator_backend=_Backend()),
    )
    assert report.adjudications == ()

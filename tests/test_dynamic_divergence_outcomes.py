"""Dynamic findings must distinguish a denied attempt from a completed operation."""

from divergence.core.engine import dynamic_divergence
from divergence.core.sandbox import Dynamic, Observation
from divergence.core.vocabulary import Capability


def _dynamic(*, succeeded: bool) -> Dynamic:
    observation = Observation(
        capability=Capability.NET_OUTBOUND,
        syscall="connect",
        target="127.0.0.1:9",
        succeeded=succeeded,
        result=0 if succeeded else -13,
    )
    return Dynamic(
        available=True,
        capabilities={Capability.NET_OUTBOUND},
        observations=(observation,),
        evidence={Capability.NET_OUTBOUND: "connect(127.0.0.1:9)"},
        syscalls_observed=1,
        entrypoints_invoked=1,
    )


def test_denied_runtime_operation_is_described_as_attempted():
    finding = dynamic_divergence(set(), _dynamic(succeeded=False))[0]
    assert "attempted a net_outbound operation" in finding.message
    assert "performed" not in finding.message


def test_successful_runtime_operation_is_described_as_performed():
    finding = dynamic_divergence(set(), _dynamic(succeeded=True))[0]
    assert "performed a net_outbound operation" in finding.message

"""Seam: the shared capability vocabulary.

A2 (declared), A4 (static behaviour) and A8 (sandbox) must all speak this, or the
divergence engine ends up special-casing per source. Locking the normalisation here.
"""

from divergence.core.vocabulary import Capability, capabilities_for_allowed_tools


def test_read_tool_grants_only_filesystem_read():
    assert capabilities_for_allowed_tools("Read") == {Capability.FS_READ}


def test_edit_grants_read_and_write():
    assert capabilities_for_allowed_tools("Read, Edit") == {
        Capability.FS_READ,
        Capability.FS_WRITE,
    }


def test_bash_is_unbounded():
    """Bash can do anything a shell can, so it must grant the full set.

    Understating this would let a skill declare `Bash` and then be flagged for
    spawning a subprocess — a false positive on an honest declaration.
    """
    caps = capabilities_for_allowed_tools("Bash")
    assert Capability.PROC_SPAWN in caps
    assert Capability.NET_OUTBOUND in caps
    assert Capability.FS_WRITE in caps


def test_wildcard_grants_everything():
    assert capabilities_for_allowed_tools('"*"') == set(Capability)


def test_absent_declaration_is_unbounded_not_empty():
    """No allowed-tools means no restriction, which is the opposite of no capability.

    Treating absence as the empty set would make every undeclared skill look like it
    exceeds its permissions — a whole stratum of false positives.
    """
    assert capabilities_for_allowed_tools(None) == set(Capability)


def test_unknown_tool_names_are_ignored_not_fatal():
    caps = capabilities_for_allowed_tools("Read, SomeFutureTool")
    assert caps == {Capability.FS_READ}

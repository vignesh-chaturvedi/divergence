"""B_dynamic — the bridge to the Rust sandbox runner.

The runner is an **optional dependency**, consumed over a stable JSON interface and never
linked. §05 is explicit about why: "if the sandbox work overruns — and systems work usually
does — it cannot take the rest of the project down with it."

So every function here is written to degrade rather than fail. On macOS, or on a Linux
kernel without Landlock, or with the binary simply absent, `observe()` returns a result
that says so and the pipeline continues static-only.
"""

from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from divergence.core.vocabulary import Capability

BINARY_ENV = "DIVERGENCE_SANDBOX_BIN"
BINARY_NAME = "divergence-sandbox"
DEFAULT_TIMEOUT = 30


@dataclass(frozen=True, slots=True)
class Observation:
    """One syscall the artifact actually made."""

    capability: Capability
    syscall: str
    target: str
    decoy: bool = False


@dataclass
class Dynamic:
    """B_dynamic for one artifact, plus the coverage that qualifies it.

    Coverage is not a footnote. §05: "dynamic analysis only observes the paths that
    actually execute... report observed coverage alongside every dynamic finding — the
    number is part of the result." A capability set with no coverage figure is unreadable,
    because an empty set means either "does nothing" or "nothing ran" and those are
    opposite conclusions.
    """

    available: bool = False
    unavailable_reason: str = ""
    capabilities: set[Capability] = field(default_factory=set)
    observations: tuple[Observation, ...] = ()
    evidence: dict[Capability, str] = field(default_factory=dict)
    limitations: tuple[str, ...] = ()

    syscalls_observed: int = 0
    entrypoints_invoked: int = 0
    exited_cleanly: bool = False
    timed_out: bool = False

    @property
    def ran(self) -> bool:
        """True when something actually executed. An empty set only means anything if so."""
        return self.available and self.syscalls_observed > 0

    @property
    def coverage_note(self) -> str:
        """The one-line qualifier that travels with every dynamic finding."""
        if not self.available:
            return f"no dynamic observation ({self.unavailable_reason})"
        if not self.ran:
            return "sandbox ran but observed no syscalls — treat the empty set as unknown"
        state = "timed out" if self.timed_out else ("exited cleanly" if self.exited_cleanly else "terminated")
        return (
            f"{self.syscalls_observed} syscalls observed across "
            f"{self.entrypoints_invoked} entrypoint(s); {state}"
        )

    @property
    def decoy_reads(self) -> tuple[Observation, ...]:
        """Reads of planted decoy credentials — unambiguous by construction."""
        return tuple(o for o in self.observations if o.decoy)


def find_binary() -> str | None:
    """Locate the runner: explicit override, PATH, then the local cargo build."""
    override = os.environ.get(BINARY_ENV)
    if override:
        return override if Path(override).is_file() else None

    found = shutil.which(BINARY_NAME)
    if found:
        return found

    for build in ("release", "debug"):
        local = Path("sandbox/target") / build / BINARY_NAME
        if local.is_file():
            return str(local)
    return None


def unavailable(reason: str) -> Dynamic:
    return Dynamic(available=False, unavailable_reason=reason)


def availability() -> Dynamic:
    """Why the sandbox would or would not run here, without running anything."""
    if platform.system() != "Linux":
        return unavailable(
            f"{platform.system()} — Landlock and seccomp are Linux features; "
            "static-only analysis on this platform"
        )
    binary = find_binary()
    if binary is None:
        return unavailable(f"{BINARY_NAME} not found — build it with `cargo build --release` in sandbox/")
    return Dynamic(available=True)


def parse_report(payload: str) -> Dynamic:
    """Parse the runner's JSON into B_dynamic.

    Unknown capability strings are skipped rather than raising: a newer runner emitting a
    capability this build does not know about should degrade, not crash.
    """
    try:
        doc = json.loads(payload or "{}")
    except json.JSONDecodeError as exc:
        return unavailable(f"sandbox emitted invalid JSON: {exc}")

    result = Dynamic(available=True)

    for raw in doc.get("observations", []):
        try:
            cap = Capability(raw["capability"])
        except (ValueError, KeyError):
            continue
        obs = Observation(
            capability=cap,
            syscall=str(raw.get("syscall", "")),
            target=str(raw.get("target", "")),
            decoy=bool(raw.get("decoy", False)),
        )
        result.observations = result.observations + (obs,)
        result.capabilities.add(cap)

    for name, evidence in (doc.get("evidence") or {}).items():
        try:
            result.evidence[Capability(name)] = str(evidence)
        except ValueError:
            continue

    coverage = doc.get("coverage") or {}
    result.syscalls_observed = int(coverage.get("syscalls_observed", 0))
    result.entrypoints_invoked = int(coverage.get("entrypoints_invoked", 0))
    result.exited_cleanly = bool(coverage.get("exited_cleanly", False))
    result.timed_out = bool(coverage.get("timed_out", False))
    result.limitations = tuple(str(x) for x in (doc.get("limitations") or []))

    return result


def observe(artifact_root: Path, *, timeout: int = DEFAULT_TIMEOUT) -> Dynamic:
    """Run the artifact under the sandbox and return B_dynamic."""
    state = availability()
    if not state.available:
        return state

    binary = find_binary()
    # Absolute: Landlock rules are resolved inside the runner, and a relative path there
    # resolves against the runner's cwd rather than the caller's. Passing a relative path
    # silently produced a ruleset that confined the driver away from the artifact — the
    # trace still ran, and reported an identical empty result for every sample.
    target = str(Path(artifact_root).resolve())
    try:
        proc = subprocess.run(
            [binary, target, "--timeout", str(timeout)],
            capture_output=True,
            text=True,
            timeout=timeout + 15,
        )
    except subprocess.TimeoutExpired:
        return unavailable("sandbox runner exceeded its own timeout")
    except OSError as exc:
        return unavailable(f"could not launch sandbox runner: {exc}")

    if proc.returncode != 0 and not proc.stdout.strip():
        detail = (proc.stderr or "").strip().splitlines()
        return unavailable(f"sandbox exited {proc.returncode}: {detail[0] if detail else 'no output'}")

    return parse_report(proc.stdout)

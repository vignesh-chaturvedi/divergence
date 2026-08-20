"""Validated bridge to the optional Linux dynamic-observation runner."""

from __future__ import annotations

import json
import os
import platform
import shutil
import signal
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, TypeGuard

from divergence.core.vocabulary import Capability

BINARY_ENV = "DIVERGENCE_SANDBOX_BIN"
BINARY_NAME = "divergence-sandbox"
DEFAULT_TIMEOUT = 30
REPORT_SCHEMA = "divergence.sandbox/1"
PROBE_SCHEMA = "divergence.sandbox.probe/1"


@dataclass(frozen=True, slots=True)
class Observation:
    """One attempted syscall, including whether the kernel completed it."""

    capability: Capability
    syscall: str
    target: str
    decoy: bool = False
    succeeded: bool = False
    result: int = -1


@dataclass
class Dynamic:
    """B_dynamic plus the coverage and enforcement state that qualify it."""

    available: bool = False
    unavailable_reason: str = ""
    runner_version: str = ""
    capabilities: set[Capability] = field(default_factory=set)
    observations: tuple[Observation, ...] = ()
    evidence: dict[Capability, str] = field(default_factory=dict)
    limitations: tuple[str, ...] = ()

    syscalls_observed: int = 0
    observations_dropped: int = 0
    entrypoints_invoked: int = 0
    entrypoints_completed: int = 0
    entrypoints_failed: int = 0
    confinement_enforced: bool = False
    exited_cleanly: bool = False
    exit_code: int = -1
    timed_out: bool = False

    @property
    def ran(self) -> bool:
        """True only when confined artifact entrypoint execution is evidenced."""
        return self.available and self.entrypoints_invoked > 0 and self.syscalls_observed > 0

    @property
    def coverage_note(self) -> str:
        """The concise qualifier carried by every dynamic finding."""
        if not self.available:
            return f"no dynamic observation ({self.unavailable_reason})"
        if not self.ran:
            return (
                "sandbox observed no confirmed entrypoint execution — treat the result as unknown"
            )
        state = (
            "timed out"
            if self.timed_out
            else ("exited cleanly" if self.exited_cleanly else f"exited {self.exit_code}")
        )
        succeeded = sum(observation.succeeded for observation in self.observations)
        attempted = len(self.observations)
        dropped = (
            f"; {self.observations_dropped} observation(s) truncated"
            if self.observations_dropped
            else ""
        )
        return (
            f"{self.syscalls_observed} syscalls observed across {self.entrypoints_invoked} entrypoint(s) "
            f"({self.entrypoints_completed} completed, {self.entrypoints_failed} failed); "
            f"{succeeded}/{attempted} recorded operations succeeded; {state}{dropped}"
        )

    @property
    def decoy_reads(self) -> tuple[Observation, ...]:
        """Successful reads of exact planted files; blocked credential attempts are excluded."""
        return tuple(
            observation
            for observation in self.observations
            if observation.decoy and observation.succeeded
        )


def find_binary() -> str | None:
    """Locate the runner: explicit override, PATH, then the local Cargo build."""
    override = os.environ.get(BINARY_ENV)
    if override:
        path = Path(override)
        return str(path.resolve()) if path.is_file() else None

    found = shutil.which(BINARY_NAME)
    if found:
        return found

    for build in ("release", "debug"):
        local = Path("sandbox/target") / build / BINARY_NAME
        if local.is_file():
            return str(local.resolve())
    return None


def unavailable(reason: str) -> Dynamic:
    return Dynamic(available=False, unavailable_reason=reason)


def _load_json_object(payload: str, *, source: str) -> tuple[dict[str, Any] | None, str]:
    try:
        document = json.loads(payload)
    except (json.JSONDecodeError, TypeError) as exc:
        return None, f"{source} emitted invalid JSON: {exc}"
    if not isinstance(document, dict):
        return None, f"{source} JSON must be an object"
    return document, ""


def _is_int(value: object) -> TypeGuard[int]:
    return isinstance(value, int) and not isinstance(value, bool)


def _validate_probe(payload: str) -> str:
    document, error = _load_json_object(payload, source="sandbox probe")
    if document is None:
        return error
    if document.get("schema") != PROBE_SCHEMA:
        return f"unsupported sandbox probe schema: {document.get('schema')!r}"
    if document.get("platform") != "linux":
        return f"sandbox probe reported platform {document.get('platform')!r}"
    if not isinstance(document.get("runner_version"), str) or not document["runner_version"]:
        return "sandbox probe omitted runner_version"
    required = document.get("required_landlock_abi")
    actual = document.get("landlock_abi")
    if not _is_int(required) or required < 4 or not _is_int(actual) or actual < required:
        return f"Landlock ABI {actual!r} does not meet required ABI {required!r}"
    if document.get("seccomp_available") is not True:
        return "sandbox seccomp deny filter is unavailable"
    if document.get("unprivileged_identity") is not True:
        reason = document.get("identity_reason")
        return (
            f"sandbox launcher identity is privileged: {reason}"
            if isinstance(reason, str) and reason
            else "sandbox did not confirm an unprivileged launcher identity"
        )
    if document.get("available") is not True:
        return "sandbox probe did not confirm all required confinement features"
    return ""


def availability() -> Dynamic:
    """Probe the locked P5 confinement requirements without executing an artifact."""
    if platform.system() != "Linux":
        return unavailable(
            f"{platform.system()} — Landlock, seccomp, and ptrace require Linux; "
            "static-only analysis on this platform"
        )
    binary = find_binary()
    if binary is None:
        return unavailable(
            f"{BINARY_NAME} not found — build it with `cargo build --release` in sandbox/"
        )
    try:
        probe = subprocess.run(
            [binary, "--probe"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return unavailable(f"sandbox probe failed: {exc}")
    if probe.returncode != 0:
        detail = (probe.stderr or "").strip().splitlines()
        return unavailable(
            f"sandbox probe exited {probe.returncode}: {detail[0] if detail else 'no detail'}"
        )
    reason = _validate_probe(probe.stdout)
    return unavailable(reason) if reason else Dynamic(available=True, confinement_enforced=True)


def _contract_error(message: str) -> Dynamic:
    return unavailable(f"invalid sandbox report: {message}")


def parse_report(payload: str) -> Dynamic:
    """Validate and parse the complete runner contract without leaking exceptions."""
    document, error = _load_json_object(payload or "", source="sandbox")
    if document is None:
        return unavailable(error)
    if document.get("schema") != REPORT_SCHEMA:
        return _contract_error(f"unsupported schema {document.get('schema')!r}")
    runner_version = document.get("runner_version")
    if not isinstance(runner_version, str) or not runner_version:
        return _contract_error("runner_version must be a non-empty string")

    raw_capabilities = document.get("capabilities")
    raw_observations = document.get("observations")
    raw_evidence = document.get("evidence")
    raw_limitations = document.get("limitations")
    coverage = document.get("coverage")
    if not isinstance(raw_capabilities, list) or not all(
        isinstance(value, str) for value in raw_capabilities
    ):
        return _contract_error("capabilities must be a list of strings")
    if not isinstance(raw_observations, list):
        return _contract_error("observations must be a list")
    if not isinstance(raw_evidence, dict) or not all(
        isinstance(name, str) and isinstance(value, str) for name, value in raw_evidence.items()
    ):
        return _contract_error("evidence must map strings to strings")
    if not isinstance(raw_limitations, list) or not all(
        isinstance(value, str) for value in raw_limitations
    ):
        return _contract_error("limitations must be a list of strings")
    if not isinstance(coverage, dict):
        return _contract_error("coverage must be an object")

    integer_fields = (
        "syscalls_observed",
        "observations_dropped",
        "entrypoints_invoked",
        "entrypoints_completed",
        "entrypoints_failed",
        "exit_code",
    )
    boolean_fields = ("confinement_enforced", "exited_cleanly", "timed_out")
    for name in integer_fields:
        if not _is_int(coverage.get(name)):
            return _contract_error(f"coverage.{name} must be an integer")
    for name in boolean_fields:
        if not isinstance(coverage.get(name), bool):
            return _contract_error(f"coverage.{name} must be a boolean")
    if any(coverage[name] < 0 for name in integer_fields if name != "exit_code"):
        return _contract_error("coverage counts cannot be negative")
    if (
        coverage["entrypoints_completed"] + coverage["entrypoints_failed"]
        != coverage["entrypoints_invoked"]
    ):
        return _contract_error("entrypoint coverage counts are inconsistent")
    if coverage["exited_cleanly"] and (coverage["exit_code"] != 0 or coverage["timed_out"]):
        return _contract_error("clean exit contradicts exit_code or timeout")

    result = Dynamic(
        available=True,
        runner_version=runner_version,
        limitations=tuple(raw_limitations),
        syscalls_observed=coverage["syscalls_observed"],
        observations_dropped=coverage["observations_dropped"],
        entrypoints_invoked=coverage["entrypoints_invoked"],
        entrypoints_completed=coverage["entrypoints_completed"],
        entrypoints_failed=coverage["entrypoints_failed"],
        confinement_enforced=coverage["confinement_enforced"],
        exited_cleanly=coverage["exited_cleanly"],
        exit_code=coverage["exit_code"],
        timed_out=coverage["timed_out"],
    )

    for name in raw_capabilities:
        try:
            result.capabilities.add(Capability(name))
        except ValueError:
            continue

    parsed_observations = []
    for index, raw in enumerate(raw_observations):
        if not isinstance(raw, dict):
            return _contract_error(f"observations[{index}] must be an object")
        capability = raw.get("capability")
        syscall = raw.get("syscall")
        target = raw.get("target")
        decoy = raw.get("decoy")
        succeeded = raw.get("succeeded")
        syscall_result = raw.get("result")
        if (
            not isinstance(capability, str)
            or not isinstance(syscall, str)
            or not isinstance(target, str)
        ):
            return _contract_error(f"observations[{index}] has invalid string fields")
        if (
            not isinstance(decoy, bool)
            or not isinstance(succeeded, bool)
            or not _is_int(syscall_result)
        ):
            return _contract_error(f"observations[{index}] has invalid outcome fields")
        if decoy and not succeeded:
            return _contract_error(f"observations[{index}] labels a failed attempt as a decoy read")
        if capability not in raw_capabilities:
            return _contract_error(f"observations[{index}] capability is absent from capabilities")
        try:
            cap = Capability(capability)
        except ValueError:
            continue
        parsed_observations.append(
            Observation(
                capability=cap,
                syscall=syscall,
                target=target,
                decoy=decoy,
                succeeded=succeeded,
                result=syscall_result,
            )
        )
    result.observations = tuple(parsed_observations)

    for name, evidence in raw_evidence.items():
        try:
            result.evidence[Capability(name)] = evidence
        except ValueError:
            continue

    if not result.confinement_enforced:
        result.available = False
        result.unavailable_reason = "runner did not fully enforce Landlock v4 and seccomp"
    return result


def observe(
    artifact_root: Path,
    *,
    timeout: int = DEFAULT_TIMEOUT,
    entrypoint: str | None = None,
) -> Dynamic:
    """Run an artifact in its own process group and return validated B_dynamic."""
    if timeout <= 0 or timeout > 300:
        return unavailable("sandbox timeout must be between 1 and 300 seconds")
    target_path = Path(artifact_root)
    if not target_path.is_dir():
        return unavailable(f"artifact root is not a directory: {target_path}")
    state = availability()
    if not state.available:
        return state
    binary = find_binary()
    if binary is None:  # `availability()` and launch are intentionally race-safe.
        return unavailable(f"{BINARY_NAME} disappeared after probe")

    command = [binary, str(target_path.resolve()), "--timeout", str(timeout)]
    if entrypoint:
        command.extend(("--entrypoint", entrypoint))
    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        stdout, stderr = process.communicate(timeout=timeout + 10)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (OSError, UnboundLocalError):
            pass
        process.communicate()
        return unavailable("sandbox runner exceeded its own timeout and was killed")
    except OSError as exc:
        return unavailable(f"could not launch sandbox runner: {exc}")

    parsed = parse_report(stdout)
    if not parsed.available:
        if process.returncode != 0 and not stdout.strip():
            detail = (stderr or "").strip().splitlines()
            return unavailable(
                f"sandbox exited {process.returncode}: {detail[0] if detail else 'no output'}"
            )
        return parsed
    if process.returncode != 0:
        return unavailable(f"sandbox exited {process.returncode} despite an available report")
    return parsed

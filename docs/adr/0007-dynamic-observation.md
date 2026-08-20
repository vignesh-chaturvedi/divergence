# ADR 0007 — What B_dynamic proves, and what it cannot

**Status:** accepted · **Phase:** P5 · **Date:** 2026-08-20

## Context

Static analysis loses to obfuscation. A base64-assembled socket call, a hex-decoded exec,
a command built from fragments — each defeats reachability analysis, and none of them
defeats execution under observation.

## Decision: ptrace supervision, not seccomp-kill

§05 specifies seccomp-bpf in **trace** mode: record everything, block nothing except the
genuinely destructive. `SECCOMP_RET_TRACE` requires a ptrace supervisor regardless, so the
supervisor is the substance and a seccomp filter is an optimisation over it. The supervisor
is implemented; the filter is not yet, and the crate says so.

## Decision: a driver, because importing is not running

An MCP server's payload lives inside a tool handler. Importing the module never calls it,
so "run `server.py`" observes process startup and nothing else — then reports a clean
artifact. **That is the worst available failure mode: it is indistinguishable from a real
negative.**

`driver/drive.py` stubs the MCP SDK, collects every registered tool, and calls each with
synthesised arguments. §05 anticipated this: "Drive it with the benchmark's own inputs."

## Decision: instrumentation must not appear in the result

Three false positives came from the tool measuring, not the artifact:

- `Command::exec` walks `PATH`, issuing a failed `execve` per candidate — four recorded
  execs before any artifact code ran, putting `proc_spawn` on **every sample in the
  corpus**. Fixed by resolving the interpreter to an absolute path once.
- The driver's own module reads registered as `fs_read`.
- A bare `clone` is also how threads start, so it is no longer reported at all. Only an
  `execve` proves a new program ran — under-claiming beats inventing.

A scanner that manufactures findings through its own measurement is the failure this
project exists to eliminate, arrived at by a more expensive route.

## Correction: §05 overstates the decoy argument

The spec says of decoy credentials: *"Anything that reads them is caught red-handed with no
ambiguity to adjudicate."* That is too strong, and the corpus disproves it. A credential
manager reads `~/.ssh` because managing credentials is its declared job, and the decoy is
planted at exactly the path it legitimately opens. Firing unconditionally would flag
`trap-priv-002`.

The core rule settles it: **a finding is the gap, not the capability.** A decoy read is
risk when credential access was not already visible in B_static, and posture when it was.
The decoy still earns its place — it makes the read observable and supplies a concrete path
as evidence.

## Results — the P5 gate

`divergence-bench sandbox-gate`, on the obfuscated stratum:

| Sample | B_static | Revealed by execution |
|---|---|---|
| obf-001-b64-attr-egress | *(none)* | **net_outbound** |
| obf-002-fragment-assembled-exec | *(none)* | **proc_spawn** |
| obf-003-hex-exec-credential-read | dynamic_eval | **secrets_read** (decoy) |
| obf-004-skill-shell-indirection | proc_spawn | — |
| obf-005-reversed-import-egress | dynamic_eval | **net_outbound** |
| obf-006-benign-base64-decoder *(control)* | *(none)* | — |

**4 of 5 payloads caught (80%)**, against a gate of 50%, and the control produced no risk
finding.

`obf-004` is missed for an environmental reason worth stating: `curl` is not installed in
the test image, so the egress never executes. Nothing static or dynamic can observe a
branch that does not run — which is precisely why coverage travels with every finding.

## Known limits, all reported rather than hidden

- **`env_read` is invisible.** Environment access is a memory read, not a syscall. It can
  never appear in B_dynamic, so its absence is never evidence.
- **Coverage bounds every claim.** An empty capability set means "nothing ran" or "nothing
  happened", and those are opposite conclusions. `Dynamic.ran` distinguishes them and the
  coverage note is attached to every finding.
- **An artifact re-executing the same interpreter is not counted** as a process spawn, a
  side effect of suppressing the driver's own exec.
- **The seccomp filter is not yet installed**; ptrace alone carries the observation.

## Containment held

The crate is consumed over JSON and never linked. On macOS `availability()` returns a
reason and the pipeline continues static-only — verified by tests that run on both
platforms. §05's insulation requirement is met: the sandbox cannot take the rest down.

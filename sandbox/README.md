# divergence-sandbox

Boots an MCP server or executes a skill's scripts under kernel-enforced confinement and
records what they actually touch — B_dynamic.

**This crate is an optional dependency.** The Python core detects its absence and degrades
to static-only analysis with a clear notice. That insulation is deliberate: if the systems
work overruns, it must cost a version number rather than the whole project.

## Linux only

Landlock and seccomp-bpf are Linux kernel features. macOS and Windows degrade to
static-only, stated plainly rather than silently.

Requires **Linux kernel 6.7+** (Landlock ABI v4), seccomp-bpf, ptrace, and an
unprivileged caller with no retained Linux capabilities. The runner deliberately refuses
uid/gid 0, setuid/setgid identities, privileged group membership, and ambient/permitted/
effective/inheritable capabilities rather than trying to sandbox a privileged launcher.

## Design

- **Filesystem** — Landlock restricts reads to the staged artifact and runtime, writes to a
  private scratch directory, and exposes fake credentials only through a sanitized private
  `HOME`. A decoy is reported as read only when the exact planted path opened successfully.
- **Syscalls** — ptrace records selected syscall entry and exit results. A mandatory
  seccomp-bpf filter denies network operations, tracing and namespace escapes, new mount
  APIs, cross-process access, privileged kernel surfaces, and metadata mutation outside
  Landlock's coverage. Reports distinguish a denied attempt from a completed operation.
- **Network** — Landlock ABI v4 denies TCP connect/bind, while seccomp independently denies
  connect, bind, listen, socket sends, raw sockets, and unsupported address families. A
  private network namespace is added when the host permits it, but correctness does not
  depend on namespace creation and there is no live sinkhole.
- **Process state** — the child receives an allowlisted environment, minimal file
  descriptors, resource limits, a private session, a parent-death signal, and full
  descendant tracing/cleanup with a wall-clock deadline.
- **Normalisation** — the raw trace collapses into the same capability vocabulary A4
  emits, so the divergence engine consumes B_dynamic without special-casing.

## Coverage is part of the result

Dynamic analysis only observes paths that execute. A tool whose malicious branch needs
specific arguments looks clean. Observed coverage is reported alongside every finding —
it is part of the result, not a footnote.

The current driver covers Python entrypoints. Environment-variable reads are memory
operations and cannot be observed, and in-process driver coverage is not tamper-proof;
both limitations are carried in every report. Artifact stdout/stderr are redirected away
from the report channel so untrusted output cannot corrupt JSON.

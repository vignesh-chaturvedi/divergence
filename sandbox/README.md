# divergence-sandbox

Boots an MCP server or executes a skill's scripts under kernel-enforced confinement and
records what they actually touch — B_dynamic.

**This crate is an optional dependency.** The Python core detects its absence and degrades
to static-only analysis with a clear notice. That insulation is deliberate: if the systems
work overruns, it must cost a version number rather than the whole project.

## Linux only

Landlock and seccomp-bpf are Linux kernel features. macOS and Windows degrade to
static-only, stated plainly rather than silently.

Requires **kernel 5.13+** for Landlock; 6.7+ (ABI v4) additionally restricts TCP.

## Design

- **Filesystem** — Landlock restricts the process to an overlay containing *decoy*
  credentials: a fake `~/.ssh`, a fake token file. Anything that reads them is caught with
  no ambiguity to adjudicate.
- **Syscalls** — seccomp-bpf in **trace** mode, not kill mode. Record everything; block
  nothing except the genuinely destructive. The goal is observation, not defence.
- **Network** — an isolated namespace with a sinkhole. Every attempted egress is logged
  with its destination and nothing leaves the host.
- **Normalisation** — the raw trace collapses into the same capability vocabulary A4
  emits, so the divergence engine consumes B_dynamic without special-casing.

## Coverage is part of the result

Dynamic analysis only observes paths that execute. A tool whose malicious branch needs
specific arguments looks clean. Observed coverage is reported alongside every finding —
it is part of the result, not a footnote.

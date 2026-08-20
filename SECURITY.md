# Security policy

## Supported versions

Until the first public release, only the current `main` branch receives security fixes.
After release, the latest minor release will be supported.

Version 1.1.0 is currently a release candidate. No PyPI package, signed release tag, or
GitHub release is represented as official until the protected publication steps in
`docs/RELEASING.md` are complete.

## Security boundary

Static analysis does not execute the target artifact. Dynamic analysis is a separate,
explicit Linux-only opt-in and must fail closed if its Landlock, seccomp, identity,
environment, resource, or process-cleanup boundary cannot be established. The current
containment evidence is from unprivileged Linux arm64; Linux x86-64 candidate-workflow
reproduction remains a release gate. See ADR 0011 for the verified boundary and its
network-namespace limitation.

A9 adjudication is also opt-in. Divergence sends only normalized finding evidence to the
operator-supplied `DIVERGENCE_ADJUDICATOR_COMMAND`; any network, vendor, retention, or model
behavior belongs to that external command and must be reviewed by its operator.

## Reporting a vulnerability

Please use GitHub's private **Report a vulnerability** form under the repository's
Security tab. Do not include secrets, real MCP client configurations, credentials, or
unredacted scanner output in a public issue.

Include the affected version or commit, operating system, a minimal reproduction, and
the security impact. You should receive an acknowledgement within seven days. No
response-time or bounty guarantee is offered.

The corpus contains inert malicious simulations. A finding that a fixture can affect the
host, escape confinement, contact a non-reserved endpoint, expose a real secret, or otherwise
is unsafe to execute is security-sensitive; report it privately before opening a public
benchmark issue.

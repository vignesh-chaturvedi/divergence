# Verify fail-closed containment on Linux

Status: resolved

The hardened sandbox was run on unprivileged Linux arm64 and its environment, network,
filesystem, timeout, resource, and process-tree boundaries were proved from inside the
child. Raw counts, Wilson 95% intervals, control results, and per-sample coverage are
tracked. ADR 0011 closes the gate without rehabilitating the unsafe ptrace-only 4/5 run.

## Comments

The hardened gate passed on unprivileged Linux arm64. It verified root refusal and child
identity, `env_clear` with a private `HOME`, exact planted decoys, Landlock ABI v4,
seccomp denial, ptrace-normalized results, resource limits, and full process-group cleanup.
Docker returned `EPERM` for network-namespace creation; Landlock and seccomp independently
enforced verified egress denial. ADR 0011 records the accepted boundary and limitation.

## Answer

The recovery gate caught 24/25 obfuscated positives (96%; Wilson 95% CI 80.5%–99.3%)
with all five matched controls clean. The complete dynamic row reached 49/50 recall with
0/35 trap false positives, 100% precision, and per-sample coverage; runtime entrypoints
were confirmed for 83/110 fixtures. The release-candidate workflow must still reproduce
the distributable runner and checks on Linux x86-64.

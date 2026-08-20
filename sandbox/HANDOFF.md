# P5 handoff — where the sandbox work stopped

**Status: corpus done and verified. Rust crate written but NEVER COMPILED.**

## Done and verified

- **Obfuscated stratum, 6 samples** under `corpus/samples/*/obfuscated/`. All validate.
  Confirmed the property that justifies the stratum — static analysis under-reports:

  | sample | B_static | B_dynamic should add |
  |---|---|---|
  | obf-001-b64-attr-egress | *(none)* | net_outbound |
  | obf-002-fragment-assembled-exec | *(none)* | proc_spawn |
  | obf-003-hex-exec-credential-read | dynamic_eval | secrets_read |
  | obf-004-skill-shell-indirection | proc_spawn | net_outbound |
  | obf-005-reversed-import-egress | dynamic_eval | net_outbound |
  | obf-006-benign-base64-decoder | *(none)* | **nothing — control** |

  obf-006 is a deliberate control: base64-heavy and benign, so the stratum cannot be beaten
  by "flag anything that decodes". Same lesson as the FP traps, applied to dynamic analysis.

- `evasion` field wired through model, loader, and validator (obfuscated samples must
  declare how they hide).
- `CLAUDE.md` status corrected — the v1 checkpoint update had silently failed to apply
  earlier (a regex that never matched). Now says P5.
- Two tests loosened from `== 80` to `>= 80`; the P0 strata stay fixed at 25/35/20 and
  obfuscated is additive. 219 tests pass.

## NOT done — resume here

**The crate has never been through a compiler.** `sandbox/src/*.rs` is ~700 lines written
straight through. Expect real compile errors, especially in:

- `confine.rs` — the `landlock` 0.4 builder API (`Ruleset`/`RulesetCreated` types are
  consumed-and-returned; my `ruleset = ruleset.add_rules(...)` chain may not typecheck)
- `trace.rs` — `nix` 0.29 `WaitStatus`/`ptrace` signatures
- `arch.rs` — the `#[cfg]` blocks return from inside `syscall_entry`; needs checking that
  both arms compile in isolation

First command to run:

```bash
docker run --rm -v "$PWD":/w -w /w/sandbox rust:latest cargo build 2>&1 | head -60
```

Then iterate. `--cap-add SYS_ADMIN` is only needed for the netns work, not for build or
for Landlock/ptrace.

## Still outstanding after the crate compiles

1. Smoke-test against `obf-001` — does it observe the connect that static missed?
2. Python bridge: detect the binary, degrade cleanly when absent (macOS must stay working)
3. Rule-table row 6: `B_dynamic ⊄ B_static` in `core/engine.py`
4. Per-finding coverage reporting (§05: coverage is part of the result, not a footnote)
5. Benchmark integration + the P5 gate: catch ≥50% of what static missed
6. Phase report `build-plan/reports/phase-07-p5-sandbox.html`

## Known design gaps, already recorded in the source

- `env_read` is a memory access, not a syscall — invisible to B_dynamic by construction.
  Reported as an explicit limitation so an absence is never read as evidence.
- seccomp-bpf trace-mode filter not yet added; the ptrace supervisor is the substance and
  the filter is an optimisation over it.

//! `divergence-sandbox` — observe what an artifact actually touches.
//!
//! Boots a target under kernel-enforced confinement, records the syscalls it makes, and
//! emits B_dynamic as JSON in the same capability vocabulary A4 uses.
//!
//! The crate is an **optional** dependency of the Python core. It is consumed over this
//! JSON interface and never linked, so its absence degrades the pipeline to static-only
//! rather than breaking it.

mod arch;
mod capability;
mod confine;
mod report;
mod trace;

use clap::Parser;
use nix::sys::ptrace;
use nix::sys::signal::{raise, Signal};
use nix::unistd::{fork, ForkResult};
use std::path::PathBuf;
use std::process::Command;

use report::Report;

/// The driver is compiled into the binary. A sandbox that depends on finding a script
/// beside itself is a sandbox that silently observes nothing when the layout changes.
const DRIVER: &str = include_str!("../driver/drive.py");

/// Resolve the interpreter to an absolute path once.
///
/// `Command::exec` otherwise walks PATH, issuing a failed `execve` per candidate — four
/// recorded execs before any artifact code runs. Resolving here means exactly one.
fn interpreter() -> String {
    for candidate in [
        "/usr/local/bin/python3",
        "/usr/bin/python3",
        "/bin/python3",
        "/usr/local/bin/python",
        "/usr/bin/python",
    ] {
        if std::path::Path::new(candidate).is_file() {
            return candidate.to_string();
        }
    }
    "python3".to_string()
}

#[derive(Parser, Debug)]
#[command(name = "divergence-sandbox", version, about = "Observe B_dynamic under confinement")]
struct Args {
    /// Artifact root to observe. Not required with --probe.
    artifact: Option<PathBuf>,

    /// Entrypoint to run, relative to the artifact root.
    #[arg(long)]
    entrypoint: Option<String>,

    /// Wall-clock budget. Dynamic analysis that hangs reports nothing.
    #[arg(long, default_value = "20")]
    timeout: u64,

    /// Where to plant decoy credentials. Defaults to a temp dir.
    #[arg(long)]
    overlay: Option<PathBuf>,

    /// Report kernel feature availability and exit.
    #[arg(long)]
    probe: bool,
}

fn main() {
    let args = Args::parse();

    if args.probe {
        let abi = confine::landlock_abi();
        println!(
            "{}",
            serde_json::json!({
                "schema": "divergence.sandbox/1",
                "landlock_abi": abi,
                "landlock_available": abi > 0,
                "platform": std::env::consts::OS,
                "arch": std::env::consts::ARCH,
            })
        );
        return;
    }

    let artifact = match args.artifact.clone() {
        Some(p) => p,
        None => {
            eprintln!("error: an artifact path is required unless --probe is given");
            std::process::exit(2);
        }
    };

    let mut report = Report::new();

    let abi = confine::landlock_abi();
    if abi <= 0 {
        report.limitations.push(
            "landlock unavailable on this kernel — filesystem confinement not enforced".into(),
        );
    }

    // Environment reads are memory accesses, not syscalls. Stated up front so an absent
    // env_read in B_dynamic is never mistaken for evidence that none happened.
    report
        .limitations
        .push("env_read is not observable via syscalls; absent from B_dynamic by construction".into());

    let overlay = args
        .overlay
        .unwrap_or_else(|| std::env::temp_dir().join("divergence-overlay"));
    match confine::plant_decoys(&overlay) {
        Ok(planted) => {
            report
                .limitations
                .push(format!("{} decoy credential(s) planted under {}", planted.len(), overlay.display()));
        }
        Err(e) => report.limitations.push(format!("could not plant decoys: {e}")),
    }

    // Write the driver somewhere the confined child can still read it.
    let driver_path = overlay.join("drive.py");
    if let Err(e) = std::fs::write(&driver_path, DRIVER) {
        report.limitations.push(format!("could not stage driver: {e}"));
        emit(&report);
        return;
    }

    report.coverage.entrypoints_invoked = 1;
    run_traced(&artifact, &driver_path, args.timeout, &overlay, &mut report);
    emit(&report);
}

fn run_traced(artifact: &PathBuf, driver: &PathBuf, timeout: u64, overlay: &PathBuf, report: &mut Report) {
    let interp = interpreter();
    let interp_child = interp.clone();
    match unsafe { fork() } {
        Ok(ForkResult::Child) => {
            // Ask to be traced, then stop so the parent can install options before exec.
            let _ = ptrace::traceme();

            // Landlock after fork, before exec: the ruleset survives exec and cannot be
            // relaxed, which is the property that makes it worth applying at all.
            let artifact_path = artifact.clone();
            let tmp = std::env::temp_dir();
            let _ = confine::restrict_filesystem(
                &[artifact_path.as_path(), std::path::Path::new("/usr"), std::path::Path::new("/lib"), overlay.as_path()],
                &[tmp.as_path()],
            );

            let _ = raise(Signal::SIGSTOP);

            let err = Command::new(&interp_child)
                .arg(driver)
                .arg(artifact)
                .current_dir(artifact)
                .env("HOME", overlay)
                .env("PYTHONDONTWRITEBYTECODE", "1")
                .exec_replace();
            eprintln!("exec failed: {err}");
            std::process::exit(127);
        }
        Ok(ForkResult::Parent { child }) => {
            let _ = nix::sys::wait::waitpid(child, None);
            trace::supervise(child, report, timeout, &interp);
        }
        Err(e) => {
            report.limitations.push(format!("fork failed: {e}"));
        }
    }
}

/// `Command::exec` lives on the Unix extension trait; wrapped for readability.
trait ExecReplace {
    fn exec_replace(&mut self) -> std::io::Error;
}
impl ExecReplace for Command {
    fn exec_replace(&mut self) -> std::io::Error {
        use std::os::unix::process::CommandExt;
        self.exec()
    }
}

fn emit(report: &Report) {
    println!("{}", serde_json::to_string_pretty(report).unwrap());
}

#![cfg(target_os = "linux")]

use serde_json::Value;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

struct Artifact {
    root: PathBuf,
}

impl Artifact {
    fn new(files: &[(&str, &str)]) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "divergence-sandbox-test-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&root).unwrap();
        for (name, source) in files {
            fs::write(root.join(name), source).unwrap();
        }
        Self { root }
    }
}

impl Drop for Artifact {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn run(artifact: &Artifact, entrypoint: Option<&str>) -> Value {
    run_with_timeout(artifact, entrypoint, 10)
}

fn run_with_timeout(artifact: &Artifact, entrypoint: Option<&str>, timeout: u64) -> Value {
    run_with_environment(artifact, entrypoint, timeout, &[])
}

fn run_with_environment(
    artifact: &Artifact,
    entrypoint: Option<&str>,
    timeout: u64,
    environment: &[(&str, &str)],
) -> Value {
    let mut command = Command::new(env!("CARGO_BIN_EXE_divergence-sandbox"));
    command
        .arg(&artifact.root)
        .args(["--timeout", &timeout.to_string()]);
    command.envs(environment.iter().copied());
    if let Some(entrypoint) = entrypoint {
        command.args(["--entrypoint", entrypoint]);
    }
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "runner failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.trim_start().starts_with('{'));
    assert!(!stdout.contains("ARTIFACT-STDOUT-MUST-NOT-LEAK"));
    serde_json::from_str(&stdout).unwrap()
}

fn observed(report: &Value, capability: &str) -> bool {
    report["observations"]
        .as_array()
        .unwrap()
        .iter()
        .any(|observation| observation["capability"] == capability)
}

#[test]
fn exact_home_decoy_read_is_successful_and_stdout_is_separate() {
    let artifact = Artifact::new(&[(
        "read_key.py",
        "from pathlib import Path\nprint('ARTIFACT-STDOUT-MUST-NOT-LEAK')\n(Path.home() / '.ssh' / 'id_rsa').read_text()\n",
    )]);
    let report = run(&artifact, None);
    let observations = report["observations"].as_array().unwrap();
    assert!(observations.iter().any(|observation| {
        observation["capability"] == "secrets_read"
            && observation["decoy"] == true
            && observation["succeeded"] == true
            && observation["target"]
                .as_str()
                .unwrap()
                .ends_with("/home/.ssh/id_rsa")
    }));
}

#[test]
fn connect_is_observed_as_a_blocked_attempt_and_entrypoint_is_honored() {
    let artifact = Artifact::new(&[
        (
            "network.py",
            "import socket\ntry:\n socket.create_connection(('127.0.0.1', 9), timeout=1)\nexcept OSError:\n pass\ns = socket.socket()\ntry:\n s.bind(('127.0.0.1', 0))\nexcept OSError:\n pass\n",
        ),
        ("quiet.py", "value = 1\n"),
    ]);
    let report = run(&artifact, Some("network.py"));
    assert_eq!(report["coverage"]["entrypoints_invoked"], 1);
    let observations = report["observations"].as_array().unwrap();
    assert!(observations.iter().any(|observation| {
        observation["capability"] == "net_outbound"
            && observation["syscall"] == "connect"
            && observation["succeeded"] == false
    }));
    assert!(observations.iter().any(|observation| {
        observation["capability"] == "net_listen"
            && observation["syscall"] == "bind"
            && observation["succeeded"] == false
    }));
}

#[test]
fn timeout_kills_root_and_descendant_without_blocking_the_supervisor() {
    let artifact = Artifact::new(&[(
        "hang.py",
        "import os\nif os.fork() == 0:\n while True: pass\nelse:\n while True: pass\n",
    )]);
    let started = Instant::now();
    let report = run_with_timeout(&artifact, None, 1);
    assert!(started.elapsed() < Duration::from_secs(5));
    assert_eq!(report["coverage"]["timed_out"], true);
    assert_eq!(report["coverage"]["confinement_enforced"], true);
    assert_eq!(report["coverage"]["exited_cleanly"], false);
}

#[test]
fn ambient_environment_is_cleared_before_artifact_execution() {
    let artifact = Artifact::new(&[(
        "environment.py",
        "import os, socket\nif os.getenv('DIVERGENCE_AMBIENT_TEST_SECRET'):\n try:\n  socket.create_connection(('127.0.0.1', 9), timeout=1)\n except OSError:\n  pass\n",
    )]);
    let report = run_with_environment(
        &artifact,
        None,
        10,
        &[("DIVERGENCE_AMBIENT_TEST_SECRET", "must-not-cross-boundary")],
    );
    assert!(!observed(&report, "net_outbound"));
    assert_eq!(report["coverage"]["entrypoints_completed"], 1);
}

#[test]
fn ordinary_python_thread_uses_the_traced_clone_fallback() {
    let artifact = Artifact::new(&[(
        "threaded.py",
        "import threading\nresult = []\nworker = threading.Thread(target=lambda: result.append('ok'))\nworker.start()\nworker.join()\nassert result == ['ok']\n",
    )]);
    let report = run(&artifact, None);
    assert_eq!(report["coverage"]["entrypoints_invoked"], 1);
    assert_eq!(report["coverage"]["entrypoints_completed"], 1);
    assert_eq!(report["coverage"]["entrypoints_failed"], 0);
}

#[test]
fn host_file_content_and_metadata_stay_outside_the_boundary() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let host_file = std::env::temp_dir().join(format!(
        "divergence-sandbox-host-boundary-{}-{nonce}",
        std::process::id()
    ));
    fs::write(&host_file, "host-only sentinel").unwrap();
    fs::set_permissions(&host_file, fs::Permissions::from_mode(0o600)).unwrap();

    let source = format!(
        "import os, pathlib, socket\np = pathlib.Path({path:?})\nexposed = False\ntry:\n exposed = p.read_text() == 'host-only sentinel'\nexcept OSError:\n pass\ntry:\n os.chmod(p, 0o777)\n exposed = True\nexcept OSError:\n pass\nif exposed:\n try:\n  socket.create_connection(('127.0.0.1', 9), timeout=1)\n except OSError:\n  pass\n",
        path = host_file.to_string_lossy()
    );
    let artifact = Artifact::new(&[("host_boundary.py", &source)]);
    let report = run(&artifact, None);

    assert!(!observed(&report, "net_outbound"));
    assert_eq!(
        fs::metadata(&host_file).unwrap().permissions().mode() & 0o777,
        0o600
    );
    fs::remove_file(host_file).unwrap();
}

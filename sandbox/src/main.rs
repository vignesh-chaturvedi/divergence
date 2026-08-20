//! Linux-only dynamic observation runner. The non-Linux binary is an explicit probe stub
//! so `cargo check` remains meaningful on development machines.

#[cfg(target_os = "linux")]
mod arch;
#[cfg(target_os = "linux")]
mod capability;
#[cfg(target_os = "linux")]
mod confine;
#[cfg(target_os = "linux")]
mod report;
#[cfg(target_os = "linux")]
mod seccomp;
#[cfg(target_os = "linux")]
mod trace;

#[cfg(not(target_os = "linux"))]
fn main() {
    if std::env::args().any(|argument| argument == "--probe") {
        println!(
            "{{\"schema\":\"divergence.sandbox.probe/1\",\"runner_version\":\"{}\",\"platform\":\"{}\",\"available\":false,\"reason\":\"Landlock, seccomp, and ptrace confinement require Linux\"}}",
            env!("CARGO_PKG_VERSION"),
            std::env::consts::OS
        );
    } else {
        eprintln!("divergence-sandbox requires Linux; use static-only analysis on this platform");
    }
    std::process::exit(2);
}

#[cfg(target_os = "linux")]
mod linux {
    use clap::Parser;
    use nix::fcntl::{fcntl, FcntlArg, FdFlag, OFlag};
    use nix::sched::{unshare, CloneFlags};
    use nix::sys::ptrace;
    use nix::sys::signal::{kill, raise, Signal};
    use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
    use nix::unistd::{dup2, fork, pipe2, ForkResult, Pid};
    use serde::{Deserialize, Serialize};
    use std::fs::{File, OpenOptions};
    use std::io::{Read, Write};
    use std::os::fd::{AsRawFd, OwnedFd};
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::time::{Duration, Instant};

    use crate::confine::PrivateOverlay;
    use crate::report::Report;

    const DRIVER: &str = include_str!("../driver/drive.py");
    const DRIVER_COVERAGE_SCHEMA: &str = "divergence.sandbox.driver/1";

    #[derive(Parser, Debug)]
    #[command(
        name = "divergence-sandbox",
        version,
        about = "Observe B_dynamic under confinement"
    )]
    struct Args {
        /// Artifact root to observe. Not required with --probe.
        artifact: Option<PathBuf>,
        /// Python file, module stem, or registered handler name to invoke.
        #[arg(long)]
        entrypoint: Option<String>,
        /// Whole-run wall-clock budget in seconds.
        #[arg(long, default_value = "20")]
        timeout: u64,
        /// Existing parent directory in which to create a private run overlay.
        #[arg(long)]
        overlay: Option<PathBuf>,
        /// Report required kernel feature availability and exit.
        #[arg(long)]
        probe: bool,
    }

    #[derive(Debug, Serialize, Deserialize)]
    struct SetupMessage {
        ok: bool,
        confinement_enforced: bool,
        limitations: Vec<String>,
        error: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    struct DriverEnvelope {
        schema: String,
        entrypoints_invoked: usize,
        entrypoints_completed: usize,
        entrypoints_failed: usize,
    }

    pub fn main() -> i32 {
        let args = Args::parse();
        if args.probe {
            emit_probe();
            return 0;
        }
        if args.timeout == 0 || args.timeout > 300 {
            eprintln!("error: --timeout must be between 1 and 300 seconds");
            return 2;
        }

        let mut report = Report::new();
        report.limitations.push(
            "env_read is not observable via syscalls; absence is never evidence of no access"
                .into(),
        );
        report.limitations.push(
            "the current driver executes Python artifacts only; non-Python entrypoints are not covered"
                .into(),
        );
        report.limitations.push(
            "driver coverage metadata is emitted in-process and is not tamper-proof against a malicious artifact"
                .into(),
        );
        report.limitations.push(
            "decoys are exposed through the sanitized HOME; hardcoded host credential paths are denied and reported as attempts, not remapped to decoys"
                .into(),
        );
        report.limitations.push(
            "clone3 returns ENOSYS to prevent CLONE_UNTRACED escape; runtimes may fall back to the traced clone syscall"
                .into(),
        );
        report.limitations.push(
            "no PID namespace is used; descendants are instead traced, resource-limited, placed in a private session, and killed with their supervisor"
                .into(),
        );

        if let Err(error) = verify_unprivileged_identity() {
            report.limitations.push(error);
            emit(&report);
            return 3;
        }

        let artifact = match args.artifact.as_deref() {
            Some(path) => match path.canonicalize() {
                Ok(path) if path.is_dir() => path,
                Ok(_) => {
                    report
                        .limitations
                        .push("artifact root is not a directory".into());
                    emit(&report);
                    return 3;
                }
                Err(error) => {
                    report
                        .limitations
                        .push(format!("could not resolve artifact root: {error}"));
                    emit(&report);
                    return 3;
                }
            },
            None => {
                eprintln!("error: an artifact path is required unless --probe is given");
                return 2;
            }
        };
        let interpreter = match interpreter() {
            Some(path) => path,
            None => {
                report
                    .limitations
                    .push("no absolute Python interpreter was found".into());
                emit(&report);
                return 3;
            }
        };
        let overlay = match PrivateOverlay::create(args.overlay.as_deref(), DRIVER) {
            Ok(overlay) => overlay,
            Err(error) => {
                report
                    .limitations
                    .push(format!("could not create private overlay: {error}"));
                emit(&report);
                return 3;
            }
        };

        let deadline = Instant::now() + Duration::from_secs(args.timeout);
        let ran = run_traced(
            &artifact,
            &interpreter,
            &overlay,
            args.entrypoint.as_deref(),
            deadline,
            &mut report,
        );
        emit(&report);
        if ran {
            0
        } else {
            3
        }
    }

    fn interpreter() -> Option<PathBuf> {
        [
            "/usr/local/bin/python3",
            "/usr/bin/python3",
            "/bin/python3",
            "/usr/local/bin/python",
            "/usr/bin/python",
        ]
        .into_iter()
        .map(PathBuf::from)
        .find(|candidate| candidate.is_file())
    }

    fn emit_probe() {
        let abi = crate::confine::landlock_abi();
        let seccomp_available = probe_seccomp();
        let identity = verify_unprivileged_identity();
        println!(
            "{}",
            serde_json::json!({
                "schema": "divergence.sandbox.probe/1",
                "runner_version": env!("CARGO_PKG_VERSION"),
                "platform": std::env::consts::OS,
                "arch": std::env::consts::ARCH,
                "available": abi >= 4 && seccomp_available && identity.is_ok(),
                "landlock_abi": abi,
                "required_landlock_abi": 4,
                "seccomp_available": seccomp_available,
                "unprivileged_identity": identity.is_ok(),
                "identity_reason": identity.err(),
                "network_policy": "Landlock ABI v4 TCP deny plus seccomp socket/message deny",
            })
        );
    }

    fn verify_unprivileged_identity() -> Result<(), String> {
        let uid = unsafe { libc::getuid() };
        let effective_uid = unsafe { libc::geteuid() };
        let gid = unsafe { libc::getgid() };
        let effective_gid = unsafe { libc::getegid() };
        if uid == 0 || effective_uid == 0 || gid == 0 || effective_gid == 0 {
            return Err(
                "sandbox refuses uid/gid 0; run the scanner as an unprivileged user".into(),
            );
        }
        if uid != effective_uid || gid != effective_gid {
            return Err("sandbox refuses setuid/setgid or mismatched identities".into());
        }

        let group_count = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
        if group_count < 0 {
            return Err(format!(
                "could not verify supplementary groups: {}",
                std::io::Error::last_os_error()
            ));
        }
        let mut groups = vec![0 as libc::gid_t; group_count as usize];
        if group_count > 0
            && unsafe { libc::getgroups(group_count, groups.as_mut_ptr()) } != group_count
        {
            return Err(format!(
                "could not read supplementary groups: {}",
                std::io::Error::last_os_error()
            ));
        }
        if groups.contains(&0) {
            return Err("sandbox refuses membership in privileged group 0".into());
        }

        let status = std::fs::read_to_string("/proc/self/status")
            .map_err(|error| format!("could not verify process capabilities: {error}"))?;
        for field in ["CapInh:", "CapPrm:", "CapEff:", "CapAmb:"] {
            let raw = status
                .lines()
                .find_map(|line| line.strip_prefix(field))
                .map(str::trim)
                .ok_or_else(|| format!("process status omitted {field}"))?;
            let value = u64::from_str_radix(raw, 16)
                .map_err(|_| format!("process status has invalid {field} value"))?;
            if value != 0 {
                return Err(format!(
                    "sandbox refuses retained Linux capabilities ({field} {raw})"
                ));
            }
        }
        Ok(())
    }

    fn probe_seccomp() -> bool {
        match unsafe { fork() } {
            Ok(ForkResult::Child) => {
                let installed = crate::seccomp::install().is_ok();
                let socket = if installed {
                    unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) }
                } else {
                    -1
                };
                let connected = if socket >= 0 {
                    unsafe { libc::connect(socket, std::ptr::null(), 0) }
                } else {
                    0
                };
                let blocked = socket >= 0
                    && connected == -1
                    && std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM);
                if socket >= 0 {
                    unsafe { libc::close(socket) };
                }
                unsafe { libc::_exit(if installed && blocked { 0 } else { 1 }) }
            }
            Ok(ForkResult::Parent { child }) => {
                matches!(waitpid(child, None), Ok(WaitStatus::Exited(_, 0)))
            }
            Err(_) => false,
        }
    }

    fn run_traced(
        artifact: &Path,
        interpreter: &Path,
        overlay: &PrivateOverlay,
        entrypoint: Option<&str>,
        deadline: Instant,
        report: &mut Report,
    ) -> bool {
        let (setup_read, setup_write) = match pipe2(OFlag::O_CLOEXEC | OFlag::O_NONBLOCK) {
            Ok(pipe) => pipe,
            Err(error) => {
                report
                    .limitations
                    .push(format!("setup pipe failed: {error}"));
                return false;
            }
        };
        let (coverage_read, coverage_write) = match pipe2(OFlag::O_CLOEXEC) {
            Ok(pipe) => pipe,
            Err(error) => {
                report
                    .limitations
                    .push(format!("coverage pipe failed: {error}"));
                return false;
            }
        };
        let expected_parent = unsafe { libc::getpid() };

        match unsafe { fork() } {
            Ok(ForkResult::Child) => {
                drop(setup_read);
                drop(coverage_read);
                child(
                    artifact,
                    interpreter,
                    overlay,
                    entrypoint,
                    setup_write,
                    coverage_write,
                    expected_parent,
                    deadline.saturating_duration_since(Instant::now()),
                );
            }
            Ok(ForkResult::Parent { child }) => {
                drop(setup_write);
                drop(coverage_write);
                let setup = match read_setup(&setup_read, deadline) {
                    Ok(message) => message,
                    Err(error) => {
                        report.limitations.push(error);
                        kill_and_reap(child);
                        return false;
                    }
                };
                report.limitations.extend(setup.limitations);
                if !setup.ok || !setup.confinement_enforced {
                    report.limitations.push(
                        setup
                            .error
                            .unwrap_or_else(|| "child confinement was not enforced".into()),
                    );
                    kill_and_reap(child);
                    return false;
                }
                if let Err(error) = wait_for_initial_stop(child, deadline) {
                    report.limitations.push(error);
                    kill_and_reap(child);
                    return false;
                }
                report.coverage.confinement_enforced = true;
                if let Err(error) = crate::trace::supervise(
                    child,
                    report,
                    deadline,
                    &interpreter.to_string_lossy(),
                    &overlay.driver,
                    artifact,
                    &overlay.decoys,
                ) {
                    report.limitations.push(error);
                    report.coverage.confinement_enforced = false;
                    kill_and_reap(child);
                    return false;
                }
                read_driver_coverage(coverage_read, report);
                true
            }
            Err(error) => {
                report.limitations.push(format!("fork failed: {error}"));
                false
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn child(
        artifact: &Path,
        interpreter: &Path,
        overlay: &PrivateOverlay,
        entrypoint: Option<&str>,
        setup: OwnedFd,
        coverage: OwnedFd,
        expected_parent: libc::pid_t,
        budget: Duration,
    ) -> ! {
        let setup_fd = setup.as_raw_fd();
        let coverage_fd = coverage.as_raw_fd();

        if let Err(error) = prepare_fds(setup_fd, coverage_fd) {
            child_fail(setup_fd, error);
        }
        if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) } != 0
            || unsafe { libc::getppid() } != expected_parent
        {
            child_fail(
                setup_fd,
                "could not bind child lifetime to supervisor".into(),
            );
        }
        if unsafe { libc::setsid() } < 0 {
            child_fail(
                setup_fd,
                "could not create a private process session".into(),
            );
        }
        if let Err(error) = set_resource_limits(budget) {
            child_fail(setup_fd, error);
        }

        let mut limitations = Vec::new();
        if let Err(error) = unshare(CloneFlags::CLONE_NEWNET) {
            limitations.push(format!(
                "network namespace unavailable ({error}); Landlock v4 and seccomp still deny all network egress/listening"
            ));
        }
        if let Err(error) = crate::confine::restrict(artifact, overlay) {
            child_fail(setup_fd, error);
        }
        if let Err(error) = ptrace::traceme() {
            child_fail(setup_fd, format!("ptrace TRACEME failed: {error}"));
        }
        if let Err(error) = crate::seccomp::install() {
            child_fail(setup_fd, error);
        }

        let success = SetupMessage {
            ok: true,
            confinement_enforced: true,
            limitations,
            error: None,
        };
        if write_setup(setup_fd, &success).is_err() {
            unsafe { libc::_exit(126) }
        }
        drop(setup);
        if raise(Signal::SIGSTOP).is_err() {
            unsafe { libc::_exit(126) }
        }

        let mut command = Command::new(interpreter);
        command
            .arg(&overlay.driver)
            .arg(artifact)
            .current_dir(artifact)
            .env_clear()
            .env("HOME", &overlay.home)
            .env("TMPDIR", &overlay.scratch)
            .env("PATH", "/usr/local/bin:/usr/bin:/bin")
            .env("LANG", "C.UTF-8")
            .env("LC_ALL", "C.UTF-8")
            .env("PYTHONDONTWRITEBYTECODE", "1")
            .env("PYTHONNOUSERSITE", "1")
            .env("DIVERGENCE_DRIVER_FD", coverage_fd.to_string());
        if let Some(entrypoint) = entrypoint {
            command.arg(entrypoint);
        }
        let _error = command.exec_replace();
        unsafe { libc::_exit(127) }
    }

    fn prepare_fds(setup_fd: i32, coverage_fd: i32) -> Result<(), String> {
        let null = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/null")
            .map_err(|error| format!("open /dev/null: {error}"))?;
        for destination in [0, 1, 2] {
            dup2(null.as_raw_fd(), destination)
                .map_err(|error| format!("redirect fd {destination}: {error}"))?;
        }

        // Close-on-exec every inherited descriptor, then retain only the dedicated driver
        // coverage writer. The setup writer is already CLOEXEC and is closed before exec.
        const CLOSE_RANGE_CLOEXEC: libc::c_uint = 1 << 2;
        let result =
            unsafe { libc::syscall(libc::SYS_close_range, 3_u32, u32::MAX, CLOSE_RANGE_CLOEXEC) };
        if result < 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::ENOSYS) {
            return Err(format!(
                "close_range(CLOEXEC): {}",
                std::io::Error::last_os_error()
            ));
        }
        if result < 0 {
            for fd in 3..1024 {
                let _ = unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
            }
        }
        fcntl(coverage_fd, FcntlArg::F_SETFD(FdFlag::empty()))
            .map_err(|error| format!("retain coverage fd: {error}"))?;
        fcntl(setup_fd, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC))
            .map_err(|error| format!("protect setup fd: {error}"))?;
        Ok(())
    }

    fn set_resource_limits(budget: Duration) -> Result<(), String> {
        fn set(resource: libc::__rlimit_resource_t, value: libc::rlim_t) -> Result<(), String> {
            let limit = libc::rlimit {
                rlim_cur: value,
                rlim_max: value,
            };
            if unsafe { libc::setrlimit(resource, &limit) } == 0 {
                Ok(())
            } else {
                Err(format!(
                    "setrlimit({resource}): {}",
                    std::io::Error::last_os_error()
                ))
            }
        }
        set(libc::RLIMIT_CORE, 0)?;
        set(libc::RLIMIT_FSIZE, 16 * 1024 * 1024)?;
        set(libc::RLIMIT_NOFILE, 128)?;
        set(libc::RLIMIT_NPROC, 128)?;
        set(libc::RLIMIT_AS, 768 * 1024 * 1024)?;
        set(libc::RLIMIT_CPU, budget.as_secs().saturating_add(1))?;
        Ok(())
    }

    fn child_fail(setup_fd: i32, error: String) -> ! {
        let message = SetupMessage {
            ok: false,
            confinement_enforced: false,
            limitations: Vec::new(),
            error: Some(error),
        };
        let _ = write_setup(setup_fd, &message);
        unsafe { libc::_exit(126) }
    }

    fn write_setup(fd: i32, message: &SetupMessage) -> Result<(), String> {
        let mut payload = serde_json::to_vec(message).map_err(|error| error.to_string())?;
        payload.push(b'\n');
        let mut written = 0;
        while written < payload.len() {
            let count = unsafe {
                libc::write(
                    fd,
                    payload[written..].as_ptr().cast(),
                    payload.len() - written,
                )
            };
            if count > 0 {
                written += count as usize;
            } else {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(format!("write setup status: {error}"));
            }
        }
        Ok(())
    }

    fn read_setup(fd: &OwnedFd, deadline: Instant) -> Result<SetupMessage, String> {
        let mut payload = Vec::new();
        let mut buffer = [0_u8; 4096];
        loop {
            if Instant::now() >= deadline {
                return Err("child setup exceeded the sandbox timeout".into());
            }
            let count =
                unsafe { libc::read(fd.as_raw_fd(), buffer.as_mut_ptr().cast(), buffer.len()) };
            if count > 0 {
                payload.extend_from_slice(&buffer[..count as usize]);
                if payload.len() > 64 * 1024 {
                    return Err("child setup status exceeded 64 KiB".into());
                }
                if payload.contains(&b'\n') {
                    return serde_json::from_slice(&payload)
                        .map_err(|error| format!("invalid child setup status: {error}"));
                }
            } else if count == 0 {
                return Err("child exited before reporting confinement status".into());
            } else {
                let error = std::io::Error::last_os_error();
                if error.kind() != std::io::ErrorKind::WouldBlock
                    && error.kind() != std::io::ErrorKind::Interrupted
                {
                    return Err(format!("read child setup status: {error}"));
                }
                std::thread::sleep(Duration::from_millis(2));
            }
        }
    }

    fn wait_for_initial_stop(child: Pid, deadline: Instant) -> Result<(), String> {
        loop {
            if Instant::now() >= deadline {
                return Err("child did not reach its initial ptrace stop before timeout".into());
            }
            match waitpid(child, Some(WaitPidFlag::WNOHANG | WaitPidFlag::WUNTRACED)) {
                Ok(WaitStatus::Stopped(pid, Signal::SIGSTOP)) if pid == child => return Ok(()),
                Ok(WaitStatus::StillAlive) => std::thread::sleep(Duration::from_millis(2)),
                Ok(status) => return Err(format!("unexpected initial child status: {status:?}")),
                Err(error) => return Err(format!("wait for initial ptrace stop: {error}")),
            }
        }
    }

    fn kill_and_reap(child: Pid) {
        let _ = kill(child, Signal::SIGKILL);
        let _ = waitpid(child, None);
    }

    fn read_driver_coverage(fd: OwnedFd, report: &mut Report) {
        let mut payload = String::new();
        let mut file = File::from(fd).take(64 * 1024 + 1);
        if let Err(error) = file.read_to_string(&mut payload) {
            report
                .limitations
                .push(format!("could not read driver coverage: {error}"));
            return;
        }
        if payload.len() > 64 * 1024 {
            report
                .limitations
                .push("driver coverage exceeded 64 KiB and was discarded".into());
            return;
        }
        let envelope: DriverEnvelope = match serde_json::from_str(payload.trim()) {
            Ok(envelope) => envelope,
            Err(error) => {
                report.limitations.push(format!(
                    "driver did not emit valid coverage metadata: {error}"
                ));
                return;
            }
        };
        if envelope.schema != DRIVER_COVERAGE_SCHEMA
            || envelope.entrypoints_completed + envelope.entrypoints_failed
                != envelope.entrypoints_invoked
        {
            report
                .limitations
                .push("driver coverage metadata failed schema invariants".into());
            return;
        }
        report.coverage.entrypoints_invoked = envelope.entrypoints_invoked;
        report.coverage.entrypoints_completed = envelope.entrypoints_completed;
        report.coverage.entrypoints_failed = envelope.entrypoints_failed;
    }

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
        let stdout = std::io::stdout();
        let mut output = stdout.lock();
        if serde_json::to_writer_pretty(&mut output, report).is_ok() {
            let _ = writeln!(output);
        }
    }
}

#[cfg(target_os = "linux")]
fn main() {
    std::process::exit(linux::main());
}

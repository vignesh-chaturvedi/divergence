//! Syscall observation via ptrace.
//!
//! §05 specifies seccomp-bpf in **trace** mode rather than kill mode: record everything,
//! block nothing except the genuinely destructive. `SECCOMP_RET_TRACE` requires a ptrace
//! supervisor regardless, so the supervisor is the substance and the seccomp filter is an
//! optimisation over it. This implements the supervisor.
//!
//! **What this cannot see.** Environment reads are memory accesses, not syscalls, so
//! `env_read` never appears in B_dynamic. That is a real blind spot and it is reported as
//! a limitation rather than left for a reader to discover by noticing an absence.

use nix::sys::ptrace;
use nix::sys::signal::Signal;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::Pid;
use std::collections::HashMap;

use crate::arch::{read_cstring, read_sockaddr, syscall_entry};
use crate::capability::{is_decoy, Capability};
use crate::report::Report;

/// Syscall numbers we care about, resolved from libc so this stays correct on both
/// architectures — aarch64 and x86_64 do not agree on numbering.
fn interesting() -> HashMap<u64, &'static str> {
    let mut m = HashMap::new();
    macro_rules! add {
        ($($sys:ident => $name:expr),* $(,)?) => {
            $( m.insert(libc::$sys as u64, $name); )*
        };
    }
    add!(
        SYS_openat => "openat",
        SYS_connect => "connect",
        SYS_socket => "socket",
        SYS_sendto => "sendto",
        SYS_execve => "execve",
        SYS_execveat => "execveat",
        SYS_clone => "clone",
        SYS_unlinkat => "unlinkat",
        SYS_renameat => "renameat",
        SYS_mkdirat => "mkdirat",
    );
    // x86_64 has these legacy numbers; aarch64 does not define them at all.
    #[cfg(target_arch = "x86_64")]
    add!(SYS_open => "open", SYS_unlink => "unlink", SYS_fork => "fork", SYS_vfork => "vfork");
    m
}

const O_WRONLY: u64 = 0o1;
const O_RDWR: u64 = 0o2;
const O_CREAT: u64 = 0o100;
const O_TRUNC: u64 = 0o1000;
const O_APPEND: u64 = 0o2000;

fn classify_open(flags: u64) -> Capability {
    if flags & (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC | O_APPEND) != 0 {
        Capability::FsWrite
    } else {
        Capability::FsRead
    }
}

/// Paths every process touches at startup. Recording them would bury the signal.
fn is_noise(path: &str) -> bool {
    path.is_empty()
        || path.starts_with("/usr/lib")
        || path.starts_with("/lib")
        || path.starts_with("/proc/")
        || path.starts_with("/usr/share/")
        || path.starts_with("/etc/")
        || path.starts_with("/sys/")
        || path.starts_with("/dev/urandom")
        || path.starts_with("/etc/ld.so")
        || path.ends_with(".so")
        || path.contains("/site-packages/")
        || path.contains("/lib-dynload/")
        || path.contains("__pycache__")
        || path.ends_with(".pyc")
        || path.ends_with("/drive.py")
        || path.ends_with(".py")
}

/// Supervise a stopped, ptrace-attached child until it exits.
pub fn supervise(child: Pid, report: &mut Report, timeout_secs: u64, interpreter: &str) {
    let syscalls = interesting();
    // The runner execs the interpreter to start the driver. That exec is *our*
    // instrumentation, not the artifact's behaviour, and recording it would put
    // proc_spawn on every single sample — a false positive manufactured by the tool
    // measuring for it. Everything after the first exec is genuinely the artifact.
    let _ = &interpreter;
    let started = std::time::Instant::now();
    let mut in_syscall: HashMap<i32, bool> = HashMap::new();

    // Follow children: a payload that spawns a helper must not escape observation.
    let _ = ptrace::setoptions(
        child,
        ptrace::Options::PTRACE_O_TRACESYSGOOD
            | ptrace::Options::PTRACE_O_TRACEFORK
            | ptrace::Options::PTRACE_O_TRACEVFORK
            | ptrace::Options::PTRACE_O_TRACECLONE
            | ptrace::Options::PTRACE_O_TRACEEXEC,
    );
    let _ = ptrace::syscall(child, None);

    loop {
        if started.elapsed().as_secs() > timeout_secs {
            report.coverage.timed_out = true;
            let _ = ptrace::kill(child);
            break;
        }

        let status = match waitpid(None, None) {
            Ok(s) => s,
            Err(nix::errno::Errno::ECHILD) => break,
            Err(_) => continue,
        };

        match status {
            WaitStatus::Exited(pid, code) => {
                if pid == child {
                    report.coverage.exited_cleanly = true;
                    report.coverage.exit_code = code;
                    break;
                }
            }
            WaitStatus::PtraceSyscall(pid) => {
                let raw = pid.as_raw();
                let entering = !in_syscall.get(&raw).copied().unwrap_or(false);
                in_syscall.insert(raw, entering);

                if entering {
                    report.coverage.syscalls_observed += 1;
                    if let Some(entry) = syscall_entry(raw) {
                        if let Some(name) = syscalls.get(&entry.number) {
                            record(raw, name, &entry.args, report, interpreter);
                        }
                    }
                }
                let _ = ptrace::syscall(pid, None);
            }
            WaitStatus::Stopped(pid, sig) => {
                // Forward real signals; swallow the SIGTRAPs ptrace generates.
                let forward = if sig == Signal::SIGTRAP { None } else { Some(sig) };
                let _ = ptrace::syscall(pid, forward);
            }
            WaitStatus::PtraceEvent(pid, _, _) => {
                let _ = ptrace::syscall(pid, None);
            }
            WaitStatus::Signaled(pid, _, _) => {
                if pid == child {
                    break;
                }
            }
            _ => {}
        }
    }
}

fn record(pid: i32, name: &str, args: &[u64; 6], report: &mut Report, interpreter: &str) {
    match name {
        "openat" | "open" => {
            // openat(dirfd, path, flags); open(path, flags)
            let (path_arg, flag_arg) = if name == "openat" { (1, 2) } else { (0, 1) };
            let path = read_cstring(pid, args[path_arg], 4096);
            if is_noise(&path) {
                return;
            }
            if is_decoy(&path) {
                report.observe(Capability::SecretsRead, name, &path, true);
                return;
            }
            report.observe(classify_open(args[flag_arg]), name, &path, false);
        }
        "connect" | "sendto" => {
            // connect(fd, sockaddr, len); sendto(fd, buf, len, flags, sockaddr, len)
            let (addr_arg, len_arg) = if name == "connect" { (1, 2) } else { (4, 5) };
            if let Some(dest) = read_sockaddr(pid, args[addr_arg], args[len_arg] as usize) {
                if dest.starts_with("unix:") {
                    return; // local IPC is not egress
                }
                report.observe(Capability::NetOutbound, name, &dest, false);
            }
        }
        "socket" => {
            // Only inet sockets count; AF_UNIX is local IPC.
            if args[0] as i32 == libc::AF_INET || args[0] as i32 == libc::AF_INET6 {
                report.observe(Capability::NetOutbound, name, "inet socket", false);
            }
        }
        "execve" | "execveat" => {
            let path = read_cstring(pid, args[if name == "execve" { 0 } else { 1 }], 4096);

            // The runner execs the interpreter to start the driver, and the exec is retried
            // across every PATH entry until one resolves — four recorded execs before a
            // single line of artifact code runs. That is instrumentation, and reporting it
            // would put proc_spawn on every sample in the corpus: a false positive
            // manufactured by the tool doing the measuring.
            //
            // Known blind spot, stated rather than hidden: an artifact that re-executes
            // this same interpreter is not counted as a process spawn.
            if path == interpreter {
                return;
            }
            report.observe(Capability::ProcSpawn, name, &path, false);
        }
        "clone" | "fork" | "vfork" => {
            // A bare clone is also how threads start. Only an exec proves a new program
            // ran, so clone alone is not reported — under-claiming beats inventing.
        }
        "unlinkat" | "unlink" => {
            let path = read_cstring(pid, args[if name == "unlinkat" { 1 } else { 0 }], 4096);
            if !is_noise(&path) {
                report.observe(Capability::FsDelete, name, &path, false);
            }
        }
        "mkdirat" | "renameat" => {
            let path = read_cstring(pid, args[1], 4096);
            if !is_noise(&path) {
                report.observe(Capability::FsWrite, name, &path, false);
            }
        }
        _ => {}
    }
}

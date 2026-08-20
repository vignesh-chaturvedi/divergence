//! Syscall entry/exit observation via ptrace.

use nix::errno::Errno;
use nix::sys::ptrace;
use nix::sys::signal::{kill, Signal};
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::Pid;
use std::collections::{HashMap, HashSet};
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};

use crate::arch::{read_cstring, read_sockaddr, read_u64, syscall_entry, syscall_result};
use crate::capability::{is_decoy, is_secret_path, Capability};
use crate::report::Report;

fn interesting(number: u64) -> Option<&'static str> {
    macro_rules! syscall {
        ($constant:ident, $name:literal) => {
            if number == libc::$constant as u64 {
                return Some($name);
            }
        };
    }
    syscall!(SYS_openat, "openat");
    syscall!(SYS_openat2, "openat2");
    syscall!(SYS_connect, "connect");
    syscall!(SYS_sendto, "sendto");
    syscall!(SYS_sendmsg, "sendmsg");
    syscall!(SYS_sendmmsg, "sendmmsg");
    syscall!(SYS_bind, "bind");
    syscall!(SYS_listen, "listen");
    syscall!(SYS_execve, "execve");
    syscall!(SYS_execveat, "execveat");
    syscall!(SYS_clone3, "clone3");
    syscall!(SYS_unlinkat, "unlinkat");
    syscall!(SYS_renameat, "renameat");
    syscall!(SYS_renameat2, "renameat2");
    syscall!(SYS_mkdirat, "mkdirat");
    #[cfg(target_arch = "x86_64")]
    {
        syscall!(SYS_open, "open");
        syscall!(SYS_unlink, "unlink");
    }
    None
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

fn normalize_path(path: &str) -> String {
    let mut normalized = PathBuf::new();
    for component in Path::new(path).components() {
        match component {
            Component::ParentDir => {
                normalized.pop();
            }
            Component::CurDir => {}
            other => normalized.push(other.as_os_str()),
        }
    }
    normalized.to_string_lossy().into_owned()
}

fn is_noise(path: &str, driver: &Path, artifact: &Path) -> bool {
    let trimmed = path.trim_end_matches('/');
    path.is_empty()
        || path == driver.to_string_lossy()
        || driver
            .parent()
            .is_some_and(|root| trimmed == root.to_string_lossy())
        || trimmed == artifact.to_string_lossy()
        || path.starts_with("/usr/lib")
        || path.starts_with("/usr/local/lib")
        || path.starts_with("/lib")
        || path.starts_with("/proc/")
        || path.starts_with("/usr/share/")
        || path.starts_with("/etc/")
        || path.starts_with("/sys/")
        || path.starts_with("/dev/")
        || path.ends_with(".so")
        || path.contains("/site-packages/")
        || path.contains("/lib-dynload/")
        || path.contains("__pycache__")
        || path.ends_with(".pyc")
        || path.ends_with(".py")
}

#[derive(Debug)]
enum Pending {
    Ignore,
    Observe {
        capability: Capability,
        syscall: &'static str,
        target: String,
        decoy_candidate: bool,
        record_failure: bool,
    },
}

struct TraceContext<'a> {
    interpreter: &'a str,
    driver: &'a Path,
    artifact: &'a Path,
    planted: &'a [String],
}

fn prepare(
    pid: i32,
    name: &'static str,
    args: &[u64; 6],
    instrumentation_exec_seen: &mut bool,
    context: &TraceContext<'_>,
) -> Pending {
    match name {
        "openat" | "openat2" | "open" => {
            let (path_arg, flag_arg) = if name == "open" { (0, 1) } else { (1, 2) };
            let path = normalize_path(&read_cstring(pid, args[path_arg], 4096));
            let secret = is_secret_path(&path);
            if !secret && is_noise(&path, context.driver, context.artifact) {
                return Pending::Ignore;
            }
            let capability = if secret {
                Capability::SecretsRead
            } else if name == "openat2" {
                // The flags live in `struct open_how`. Under-claiming write as read affects
                // posture only; credential paths are still classified above.
                Capability::FsRead
            } else {
                classify_open(args[flag_arg])
            };
            Pending::Observe {
                capability,
                syscall: name,
                decoy_candidate: is_decoy(&path, context.planted),
                target: path,
                record_failure: secret,
            }
        }
        "connect" | "sendto" => {
            let (address_arg, length_arg) = if name == "connect" { (1, 2) } else { (4, 5) };
            let Some(target) = read_sockaddr(pid, args[address_arg], args[length_arg] as usize)
            else {
                return Pending::Ignore;
            };
            if target.starts_with("unix:") {
                return Pending::Ignore;
            }
            Pending::Observe {
                capability: Capability::NetOutbound,
                syscall: name,
                target,
                decoy_candidate: false,
                record_failure: true,
            }
        }
        "sendmsg" | "sendmmsg" => Pending::Observe {
            capability: Capability::NetOutbound,
            syscall: name,
            target: format!("socket fd {}", args[0]),
            decoy_candidate: false,
            record_failure: true,
        },
        "bind" => {
            let target = read_sockaddr(pid, args[1], args[2] as usize)
                .unwrap_or_else(|| format!("socket fd {}", args[0]));
            if target.starts_with("unix:") {
                return Pending::Ignore;
            }
            Pending::Observe {
                capability: Capability::NetListen,
                syscall: name,
                target,
                decoy_candidate: false,
                record_failure: true,
            }
        }
        "listen" => Pending::Observe {
            capability: Capability::NetListen,
            syscall: name,
            target: format!("socket fd {}", args[0]),
            decoy_candidate: false,
            record_failure: true,
        },
        "execve" | "execveat" => {
            let path_arg = if name == "execve" { 0 } else { 1 };
            let path = read_cstring(pid, args[path_arg], 4096);
            if !*instrumentation_exec_seen && path == context.interpreter {
                // Suppress exactly the runner's first interpreter exec. A later exec of the
                // same interpreter belongs to the artifact and is reported.
                *instrumentation_exec_seen = true;
                return Pending::Ignore;
            }
            Pending::Observe {
                capability: Capability::ProcSpawn,
                syscall: name,
                target: if path.is_empty() {
                    "fd-based exec".into()
                } else {
                    path
                },
                decoy_candidate: false,
                record_failure: false,
            }
        }
        "clone3" => {
            let Some(flags) = read_u64(pid, args[0]) else {
                return Pending::Ignore;
            };
            if flags & libc::CLONE_THREAD as u64 != 0 {
                return Pending::Ignore;
            }
            Pending::Observe {
                capability: Capability::ProcSpawn,
                syscall: name,
                target: format!("process clone flags 0x{flags:x}"),
                decoy_candidate: false,
                // clone3 is deliberately denied because its pointed-to flags cannot be
                // safely filtered for CLONE_UNTRACED in classic seccomp BPF. Reporting
                // this as an attempted spawn preserves intent without claiming success.
                record_failure: true,
            }
        }
        "unlinkat" | "unlink" => {
            let path = normalize_path(&read_cstring(
                pid,
                args[if name == "unlinkat" { 1 } else { 0 }],
                4096,
            ));
            if is_noise(&path, context.driver, context.artifact) {
                Pending::Ignore
            } else {
                Pending::Observe {
                    capability: Capability::FsDelete,
                    syscall: name,
                    target: path,
                    decoy_candidate: false,
                    record_failure: false,
                }
            }
        }
        "mkdirat" | "renameat" | "renameat2" => {
            let path = normalize_path(&read_cstring(pid, args[1], 4096));
            if is_noise(&path, context.driver, context.artifact) {
                Pending::Ignore
            } else {
                Pending::Observe {
                    capability: Capability::FsWrite,
                    syscall: name,
                    target: path,
                    decoy_candidate: false,
                    record_failure: false,
                }
            }
        }
        _ => Pending::Ignore,
    }
}

fn ptrace_options() -> ptrace::Options {
    ptrace::Options::PTRACE_O_TRACESYSGOOD
        | ptrace::Options::PTRACE_O_TRACEFORK
        | ptrace::Options::PTRACE_O_TRACEVFORK
        | ptrace::Options::PTRACE_O_TRACECLONE
        | ptrace::Options::PTRACE_O_TRACEEXEC
        | ptrace::Options::PTRACE_O_EXITKILL
}

fn resume(pid: Pid, signal: Option<Signal>) -> Result<(), String> {
    match ptrace::syscall(pid, signal) {
        Ok(()) | Err(Errno::ESRCH) => Ok(()),
        Err(error) => Err(format!("ptrace resume {pid}: {error}")),
    }
}

fn kill_all(active: &HashSet<Pid>) {
    for pid in active {
        let _ = kill(*pid, Signal::SIGKILL);
    }
}

/// Supervise the root tracee and every descendant. The wait loop is non-blocking so the
/// wall-clock deadline remains enforceable even when a tracee is stuck in a syscall.
pub fn supervise(
    child: Pid,
    report: &mut Report,
    deadline: Instant,
    interpreter: &str,
    driver: &Path,
    artifact: &Path,
    planted: &[String],
) -> Result<(), String> {
    ptrace::setoptions(child, ptrace_options())
        .map_err(|error| format!("ptrace options: {error}"))?;
    resume(child, None)?;

    let mut active = HashSet::from([child]);
    let mut pending: HashMap<i32, Pending> = HashMap::new();
    let mut instrumentation_exec_seen = false;
    let context = TraceContext {
        interpreter,
        driver,
        artifact,
        planted,
    };
    let mut terminating = false;
    let mut fatal_error = None;

    while !active.is_empty() {
        if !terminating && Instant::now() >= deadline {
            report.coverage.timed_out = true;
            terminating = true;
            kill_all(&active);
        }

        let flags = WaitPidFlag::WNOHANG | WaitPidFlag::__WALL;
        let status = match waitpid(None, Some(flags)) {
            Ok(WaitStatus::StillAlive) => {
                std::thread::sleep(Duration::from_micros(100));
                continue;
            }
            Ok(status) => status,
            Err(Errno::EINTR) => continue,
            Err(Errno::ECHILD) => break,
            Err(error) => {
                fatal_error = Some(format!("waitpid: {error}"));
                kill_all(&active);
                break;
            }
        };

        match status {
            WaitStatus::Exited(pid, code) => {
                active.remove(&pid);
                pending.remove(&pid.as_raw());
                if pid == child {
                    report.coverage.exit_code = code;
                    report.coverage.exited_cleanly = code == 0;
                }
            }
            WaitStatus::Signaled(pid, signal, _) => {
                active.remove(&pid);
                pending.remove(&pid.as_raw());
                if pid == child {
                    report.coverage.exit_code = 128 + signal as i32;
                    report.coverage.exited_cleanly = false;
                }
            }
            WaitStatus::PtraceSyscall(pid) => {
                active.insert(pid);
                let raw = pid.as_raw();
                if let Some(operation) = pending.remove(&raw) {
                    let Some(result) = syscall_result(raw) else {
                        fatal_error = Some(format!("could not read syscall result for {pid}"));
                        terminating = true;
                        kill_all(&active);
                        continue;
                    };
                    if let Pending::Observe {
                        capability,
                        syscall,
                        target,
                        decoy_candidate,
                        record_failure,
                    } = operation
                    {
                        let succeeded = result >= 0;
                        if succeeded || record_failure {
                            report.observe(
                                capability,
                                syscall,
                                &target,
                                decoy_candidate && succeeded,
                                succeeded,
                                result,
                            );
                        }
                    }
                } else {
                    report.coverage.syscalls_observed += 1;
                    let operation = syscall_entry(raw)
                        .and_then(|entry| {
                            interesting(entry.number).map(|name| {
                                prepare(
                                    raw,
                                    name,
                                    &entry.args,
                                    &mut instrumentation_exec_seen,
                                    &context,
                                )
                            })
                        })
                        .unwrap_or(Pending::Ignore);
                    pending.insert(raw, operation);
                }
                if let Err(error) = resume(pid, None) {
                    fatal_error = Some(error);
                    terminating = true;
                    kill_all(&active);
                }
            }
            WaitStatus::Stopped(pid, signal) => {
                let is_new = active.insert(pid);
                if is_new {
                    if let Err(error) = ptrace::setoptions(pid, ptrace_options()) {
                        fatal_error = Some(format!("ptrace options for descendant {pid}: {error}"));
                        terminating = true;
                        kill_all(&active);
                        continue;
                    }
                }
                let forward = if signal == Signal::SIGTRAP || signal == Signal::SIGSTOP {
                    None
                } else {
                    Some(signal)
                };
                if let Err(error) = resume(pid, forward) {
                    fatal_error = Some(error);
                    terminating = true;
                    kill_all(&active);
                }
            }
            WaitStatus::PtraceEvent(pid, _, _) => {
                active.insert(pid);
                if let Err(error) = resume(pid, None) {
                    fatal_error = Some(error);
                    terminating = true;
                    kill_all(&active);
                }
            }
            _ => {}
        }
    }

    fatal_error.map_or(Ok(()), Err)
}

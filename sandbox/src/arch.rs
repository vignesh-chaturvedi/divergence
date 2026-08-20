//! Register access across architectures.
//!
//! `nix`'s `ptrace::getregs` is x86-only. aarch64 has no `PTRACE_GETREGS` at all — it uses
//! `PTRACE_GETREGSET` with `NT_PRSTATUS` — and this project's own development machine is
//! aarch64, so supporting both is not hypothetical portability work.

use libc::{c_void, iovec, pid_t};

const PTRACE_GETREGSET: i32 = 0x4204;
const NT_PRSTATUS: i32 = 1;

/// One syscall-entry stop, normalised across architectures.
#[derive(Debug, Clone, Copy)]
pub struct SyscallEntry {
    pub number: u64,
    pub args: [u64; 6],
}

#[cfg(target_arch = "aarch64")]
#[repr(C)]
#[derive(Default, Clone, Copy)]
struct UserRegs {
    regs: [u64; 31],
    sp: u64,
    pc: u64,
    pstate: u64,
}

#[cfg(target_arch = "x86_64")]
#[repr(C)]
#[derive(Default, Clone, Copy)]
struct UserRegs {
    r15: u64,
    r14: u64,
    r13: u64,
    r12: u64,
    rbp: u64,
    rbx: u64,
    r11: u64,
    r10: u64,
    r9: u64,
    r8: u64,
    rax: u64,
    rcx: u64,
    rdx: u64,
    rsi: u64,
    rdi: u64,
    orig_rax: u64,
    rip: u64,
    cs: u64,
    eflags: u64,
    rsp: u64,
    ss: u64,
    fs_base: u64,
    gs_base: u64,
    ds: u64,
    es: u64,
    fs: u64,
    gs: u64,
}

fn read_regs(pid: pid_t) -> Option<UserRegs> {
    let mut regs = UserRegs::default();
    let mut io = iovec {
        iov_base: &mut regs as *mut _ as *mut c_void,
        iov_len: std::mem::size_of::<UserRegs>(),
    };
    let rc = unsafe {
        libc::ptrace(
            PTRACE_GETREGSET as _,
            pid,
            NT_PRSTATUS as *mut c_void,
            &mut io as *mut _ as *mut c_void,
        )
    };
    if rc < 0 {
        return None;
    }
    Some(regs)
}

/// Read the syscall number and arguments at a syscall-entry stop.
pub fn syscall_entry(pid: pid_t) -> Option<SyscallEntry> {
    let r = read_regs(pid)?;

    #[cfg(target_arch = "aarch64")]
    {
        // aarch64 Linux: syscall number in x8, arguments in x0..x5.
        Some(SyscallEntry {
            number: r.regs[8],
            args: [
                r.regs[0], r.regs[1], r.regs[2], r.regs[3], r.regs[4], r.regs[5],
            ],
        })
    }

    #[cfg(target_arch = "x86_64")]
    {
        // x86_64 Linux: number in orig_rax, arguments in rdi, rsi, rdx, r10, r8, r9.
        Some(SyscallEntry {
            number: r.orig_rax,
            args: [r.rdi, r.rsi, r.rdx, r.r10, r.r8, r.r9],
        })
    }
}

/// Read the signed syscall return value at a syscall-exit stop. Linux encodes `-errno`
/// directly in this register, so callers can distinguish a blocked attempt from access
/// that actually occurred.
pub fn syscall_result(pid: pid_t) -> Option<i64> {
    let r = read_regs(pid)?;

    #[cfg(target_arch = "aarch64")]
    {
        Some(r.regs[0] as i64)
    }

    #[cfg(target_arch = "x86_64")]
    {
        Some(r.rax as i64)
    }
}

/// Read a NUL-terminated string out of the tracee's address space.
///
/// `process_vm_readv` rather than repeated `PTRACE_PEEKDATA`: one syscall instead of one
/// per word, and the paths being read are the whole point of the trace.
pub fn read_cstring(pid: pid_t, addr: u64, max: usize) -> String {
    if addr == 0 {
        return String::new();
    }
    let mut buf = vec![0u8; max];
    let local = iovec {
        iov_base: buf.as_mut_ptr() as *mut c_void,
        iov_len: max,
    };
    let remote = iovec {
        iov_base: addr as *mut c_void,
        iov_len: max,
    };
    let n = unsafe { libc::process_vm_readv(pid, &local, 1, &remote, 1, 0) };
    if n <= 0 {
        return String::new();
    }
    let bytes = &buf[..n as usize];
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

/// Read one native-endian `u64` from the tracee. `clone3` places its flag word in a
/// pointed-to structure rather than a register, so this is needed to distinguish process
/// creation from thread creation without allowing the syscall to escape the filter.
pub fn read_u64(pid: pid_t, addr: u64) -> Option<u64> {
    if addr == 0 {
        return None;
    }
    let mut value = 0_u64;
    let local = iovec {
        iov_base: (&mut value as *mut u64).cast(),
        iov_len: std::mem::size_of::<u64>(),
    };
    let remote = iovec {
        iov_base: (addr as *mut u64).cast(),
        iov_len: std::mem::size_of::<u64>(),
    };
    let read = unsafe { libc::process_vm_readv(pid, &local, 1, &remote, 1, 0) };
    (read == std::mem::size_of::<u64>() as isize).then_some(value)
}

/// Decode a `sockaddr` in the tracee into a printable destination.
pub fn read_sockaddr(pid: pid_t, addr: u64, len: usize) -> Option<String> {
    if addr == 0 || len < 4 {
        return None;
    }
    let size = len.min(128);
    let mut buf = vec![0u8; size];
    let local = iovec {
        iov_base: buf.as_mut_ptr() as *mut c_void,
        iov_len: size,
    };
    let remote = iovec {
        iov_base: addr as *mut c_void,
        iov_len: size,
    };
    if unsafe { libc::process_vm_readv(pid, &local, 1, &remote, 1, 0) } <= 0 {
        return None;
    }

    let family = u16::from_ne_bytes([buf[0], buf[1]]);
    match family as i32 {
        libc::AF_INET if size >= 8 => {
            let port = u16::from_be_bytes([buf[2], buf[3]]);
            Some(format!(
                "{}.{}.{}.{}:{}",
                buf[4], buf[5], buf[6], buf[7], port
            ))
        }
        libc::AF_INET6 if size >= 24 => {
            let port = u16::from_be_bytes([buf[2], buf[3]]);
            Some(format!("[ipv6]:{}", port))
        }
        libc::AF_UNIX => {
            let end = buf[2..].iter().position(|&b| b == 0).unwrap_or(0);
            Some(format!(
                "unix:{}",
                String::from_utf8_lossy(&buf[2..2 + end])
            ))
        }
        _ => Some(format!("af{}", family)),
    }
}

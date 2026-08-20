//! A deny filter that closes escape paths ptrace observation alone cannot contain.

use seccompiler::{
    apply_filter, BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition,
    SeccompFilter, SeccompRule,
};
use std::collections::BTreeMap;
use std::convert::TryInto;

fn condition(
    argument: u8,
    operation: SeccompCmpOp,
    value: u64,
) -> Result<SeccompCondition, String> {
    SeccompCondition::new(argument, SeccompCmpArgLen::Qword, operation, value)
        .map_err(|error| format!("seccomp condition: {error}"))
}

fn rule(conditions: Vec<SeccompCondition>) -> Result<SeccompRule, String> {
    SeccompRule::new(conditions).map_err(|error| format!("seccomp rule: {error}"))
}

fn apply_rules(
    rules: BTreeMap<i64, Vec<SeccompRule>>,
    match_action: SeccompAction,
) -> Result<(), String> {
    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Allow,
        match_action,
        std::env::consts::ARCH
            .try_into()
            .map_err(|error| format!("seccomp architecture: {error}"))?,
    )
    .map_err(|error| format!("seccomp filter: {error}"))?;
    let program: BpfProgram = filter
        .try_into()
        .map_err(|error| format!("seccomp compile: {error}"))?;
    apply_filter(&program).map_err(|error| format!("seccomp apply: {error}"))
}

/// Install a fail-closed denylist. Landlock independently denies TCP connect/bind; the
/// socket and message rules here cover UDP, raw sockets, abstract Unix sockets, and old
/// kernels that would otherwise make network restrictions ambiguous.
pub fn install() -> Result<(), String> {
    let pid = unsafe { libc::getpid() } as u64;
    let tid = unsafe { libc::syscall(libc::SYS_gettid) } as u64;
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();

    macro_rules! deny {
        ($($syscall:ident),* $(,)?) => {
            $(rules.insert(libc::$syscall, Vec::new());)*
        };
    }

    // Network egress and listening. AF_UNIX socketpair remains usable, but communication
    // with any external socket is denied because connect/send/bind/listen are denied.
    rules.insert(
        libc::SYS_socket,
        vec![
            // Permit only Unix, IPv4, and IPv6 socket creation. Inet stream/datagram
            // sockets are harmless until connect/bind/send, which are blocked below and
            // provide the precise outbound-versus-listen observation point.
            rule(vec![
                condition(0, SeccompCmpOp::Ne, libc::AF_UNIX as u64)?,
                condition(0, SeccompCmpOp::Ne, libc::AF_INET as u64)?,
                condition(0, SeccompCmpOp::Ne, libc::AF_INET6 as u64)?,
            ])?,
            // Linux stores the base socket type in the low nibble; deny raw sockets even
            // in an otherwise permitted family.
            rule(vec![condition(
                1,
                SeccompCmpOp::MaskedEq(0x0f),
                libc::SOCK_RAW as u64,
            )?])?,
        ],
    );
    deny!(
        SYS_connect,
        SYS_bind,
        SYS_listen,
        SYS_sendto,
        SYS_sendmsg,
        SYS_sendmmsg
    );

    // Namespace, kernel, tracing, cross-process, and privileged mutation surfaces.
    deny!(
        SYS_setns,
        SYS_unshare,
        SYS_mount,
        SYS_umount2,
        SYS_pivot_root,
        SYS_ptrace,
        SYS_process_vm_readv,
        SYS_process_vm_writev,
        SYS_pidfd_getfd,
        SYS_kcmp,
        SYS_process_madvise,
        SYS_process_mrelease,
        SYS_open_by_handle_at,
        SYS_bpf,
        SYS_perf_event_open,
        SYS_userfaultfd,
        SYS_keyctl,
        SYS_add_key,
        SYS_request_key,
        SYS_reboot,
        SYS_kexec_load,
        SYS_kexec_file_load,
        SYS_init_module,
        SYS_finit_module,
        SYS_delete_module,
        SYS_io_uring_setup,
        SYS_io_uring_enter,
        SYS_io_uring_register,
        SYS_pidfd_send_signal
    );

    // The new mount API must be denied alongside mount(2); otherwise a privileged caller
    // could assemble a mount through file descriptors without touching SYS_mount.
    deny!(
        SYS_fsopen,
        SYS_fsconfig,
        SYS_fsmount,
        SYS_fspick,
        SYS_move_mount,
        SYS_open_tree,
        SYS_mount_setattr
    );

    // Landlock intentionally does not mediate every metadata operation. Deny mutation
    // syscalls that could otherwise change same-user files outside the allowed tree, plus
    // device-node creation and identity/capability changes.
    deny!(
        SYS_fchmod,
        SYS_fchmodat,
        SYS_fchown,
        SYS_fchownat,
        SYS_setxattr,
        SYS_lsetxattr,
        SYS_fsetxattr,
        SYS_removexattr,
        SYS_lremovexattr,
        SYS_fremovexattr,
        SYS_utimensat,
        SYS_mknodat,
        SYS_setuid,
        SYS_setgid,
        SYS_setreuid,
        SYS_setregid,
        SYS_setresuid,
        SYS_setresgid,
        SYS_setfsuid,
        SYS_setfsgid,
        SYS_setgroups,
        SYS_capset
    );

    #[cfg(target_arch = "x86_64")]
    deny!(
        SYS_chmod,
        SYS_chown,
        SYS_lchown,
        SYS_mknod,
        SYS_utime,
        SYS_utimes,
        SYS_futimesat,
        SYS_iopl,
        SYS_ioperm
    );

    // A traced child must not request CLONE_UNTRACED or manufacture a namespace through
    // clone(2). Plain process/thread creation remains traced and resource-limited.
    let forbidden_clone_flags = [
        libc::CLONE_UNTRACED,
        libc::CLONE_NEWCGROUP,
        libc::CLONE_NEWIPC,
        libc::CLONE_NEWNET,
        libc::CLONE_NEWNS,
        libc::CLONE_NEWPID,
        libc::CLONE_NEWUSER,
        libc::CLONE_NEWUTS,
    ];
    rules.insert(
        libc::SYS_clone,
        forbidden_clone_flags
            .into_iter()
            .map(|flag| {
                rule(vec![condition(
                    0,
                    SeccompCmpOp::MaskedEq(flag as u64),
                    flag as u64,
                )?])
            })
            .collect::<Result<Vec<_>, String>>()?,
    );

    // Signals are limited to this process/thread. This prevents same-UID host processes
    // from becoming targets while preserving Python's own signal handling.
    rules.insert(
        libc::SYS_kill,
        vec![rule(vec![condition(0, SeccompCmpOp::Ne, pid)?])?],
    );
    rules.insert(
        libc::SYS_tkill,
        vec![rule(vec![condition(0, SeccompCmpOp::Ne, tid)?])?],
    );
    rules.insert(
        libc::SYS_tgkill,
        vec![
            rule(vec![condition(0, SeccompCmpOp::Ne, pid)?])?,
            rule(vec![condition(1, SeccompCmpOp::Ne, tid)?])?,
        ],
    );

    // glibc probes clone3 before falling back to clone for ordinary Python threads. Make
    // clone3 look unavailable instead of returning EPERM: direct use is still impossible,
    // while the safe, inspectable legacy clone path remains usable. This needs its own
    // stacked filter because seccompiler gives one match action to each filter.
    let mut clone3_rules = BTreeMap::new();
    clone3_rules.insert(libc::SYS_clone3, Vec::new());
    apply_rules(clone3_rules, SeccompAction::Errno(libc::ENOSYS as u32))?;
    apply_rules(rules, SeccompAction::Errno(libc::EPERM as u32))
}

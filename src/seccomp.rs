//! Seccomp denylist (DESIGN §5). Defence in depth on top of "no caps + NNP +
//! userns + Landlock"; default action is allow.
//!
//! The policy compiles to a *stack* of programs because a `seccompiler`
//! filter has a single match action and cannot condition on the syscall
//! number itself:
//!
//! 1. main deny filter — `EPERM` for the invariant-2 list, DESIGN D9
//!    additions, `clone` with any `CLONE_NEW*` bit, `ioctl` TIOCSTI/TIOCLINUX/
//!    TIOCSETD, plus the policy's `extra_deny`;
//! 2. `clone3` → `ENOSYS` (its flags live in user memory; libc falls back to
//!    `clone`, which filter 1 can inspect);
//! 3. x86_64 only: any syscall number with the x32 bit → kill (denylist bypass).
//!
//! The kernel applies the most restrictive result across stacked filters.

use std::collections::{BTreeMap, BTreeSet};

#[cfg(target_arch = "x86_64")]
use seccompiler::sock_filter;
use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
    SeccompRule, TargetArch,
};

#[derive(Debug, thiserror::Error)]
pub enum SeccompError {
    #[error("seccomp.extra_deny: unknown syscall {0:?} for this architecture")]
    UnknownSyscall(String),
    #[error("seccomp filter construction failed: {0}")]
    Build(String),
    #[error("installing seccomp filter failed: {0}")]
    Install(String),
}

macro_rules! syscall_table {
    ($($name:ident),* $(,)?) => {
        &[$((stringify!($name), libc::$name as i64)),*]
    };
}

/// Syscalls present on both x86_64 and aarch64 that hisn knows by name.
/// (`extra_deny` accepts exactly these plus [`ARCH_SPECIFIC`].)
const COMMON: &[(&str, i64)] = syscall_table![
    SYS_mount,
    SYS_umount2,
    SYS_pivot_root,
    SYS_chroot,
    SYS_unshare,
    SYS_setns,
    SYS_open_tree,
    SYS_move_mount,
    SYS_fsopen,
    SYS_fsconfig,
    SYS_fsmount,
    SYS_fspick,
    SYS_mount_setattr,
    SYS_ptrace,
    SYS_bpf,
    SYS_keyctl,
    SYS_add_key,
    SYS_request_key,
    SYS_io_uring_setup,
    SYS_io_uring_enter,
    SYS_io_uring_register,
    SYS_perf_event_open,
    SYS_kexec_load,
    SYS_kexec_file_load,
    SYS_reboot,
    SYS_swapon,
    SYS_swapoff,
    SYS_init_module,
    SYS_finit_module,
    SYS_delete_module,
    SYS_process_vm_readv,
    SYS_process_vm_writev,
    SYS_pidfd_getfd,
    SYS_kcmp,
    SYS_open_by_handle_at,
    SYS_name_to_handle_at,
    SYS_userfaultfd,
    SYS_quotactl,
    SYS_acct,
    SYS_syslog,
    SYS_settimeofday,
    SYS_clock_settime,
    SYS_clock_adjtime,
    SYS_adjtimex,
    SYS_personality,
    SYS_clone,
    SYS_clone3,
    SYS_ioctl,
    SYS_sethostname,
    SYS_setdomainname,
    SYS_mknodat,
    SYS_vhangup,
    SYS_lookup_dcookie,
    SYS_pidfd_open,
    SYS_pidfd_send_signal,
    SYS_memfd_create,
    SYS_mbind,
    SYS_move_pages,
    SYS_migrate_pages,
    SYS_set_mempolicy,
    SYS_unlinkat,
    SYS_symlinkat,
    SYS_socket,
    SYS_connect,
    SYS_getpid,
];

#[cfg(target_arch = "x86_64")]
const ARCH_SPECIFIC: &[(&str, i64)] = syscall_table![
    SYS_ioperm,
    SYS_iopl,
    SYS_modify_ldt,
    SYS__sysctl,
    SYS_uselib,
    SYS_mknod,
    SYS_umount2,
];
#[cfg(target_arch = "aarch64")]
const ARCH_SPECIFIC: &[(&str, i64)] = syscall_table![];

/// Names (without the `SYS_` prefix) denied unconditionally with `EPERM`:
/// brief invariant 2 plus DESIGN D9 additions.
pub const BASE_DENY: &[&str] = &[
    // Invariant 2
    "mount",
    "umount2",
    "pivot_root",
    "unshare",
    "setns",
    "open_tree",
    "move_mount",
    "fsopen",
    "fsconfig",
    "fsmount",
    "fspick",
    "ptrace",
    "bpf",
    "keyctl",
    "io_uring_setup",
    "io_uring_enter",
    "io_uring_register",
    "perf_event_open",
    "kexec_load",
    "kexec_file_load",
    "reboot",
    "swapon",
    "swapoff",
    "init_module",
    "finit_module",
    "delete_module",
    // Needed to make the list meaningful (mount_setattr/chroot are mount-API siblings)
    "mount_setattr",
    "chroot",
    "add_key",
    "request_key",
    // DESIGN D9
    "process_vm_readv",
    "process_vm_writev",
    "pidfd_getfd",
    "kcmp",
    "open_by_handle_at",
    "name_to_handle_at",
    "userfaultfd",
    "quotactl",
    "acct",
    "lookup_dcookie",
    "syslog",
    "settimeofday",
    "clock_settime",
    "clock_adjtime",
    "adjtimex",
    "personality",
];

/// Extra names denied on x86_64 only (legacy / port-I/O interfaces).
#[cfg(target_arch = "x86_64")]
pub const ARCH_DENY: &[&str] = &["ioperm", "iopl", "modify_ldt", "_sysctl", "uselib"];
#[cfg(not(target_arch = "x86_64"))]
pub const ARCH_DENY: &[&str] = &[];

const CLONE_NEW_BITS: [u64; 7] = [
    0x0002_0000, // NEWNS
    0x0200_0000, // NEWCGROUP
    0x0400_0000, // NEWUTS
    0x0800_0000, // NEWIPC
    0x1000_0000, // NEWUSER
    0x2000_0000, // NEWPID
    0x4000_0000, // NEWNET
];
const TIOCSTI: u64 = 0x5412;
const TIOCLINUX: u64 = 0x541C;
const TIOCSETD: u64 = 0x5423;

#[cfg(target_arch = "x86_64")]
const TARGET: TargetArch = TargetArch::x86_64;
#[cfg(target_arch = "aarch64")]
const TARGET: TargetArch = TargetArch::aarch64;

fn lookup(name: &str) -> Option<i64> {
    let full = format!("SYS_{name}");
    COMMON
        .iter()
        .chain(ARCH_SPECIFIC)
        .find(|(n, _)| *n == full)
        .map(|(_, nr)| *nr)
}

fn nr_of(name: &str) -> i64 {
    lookup(name).unwrap_or_else(|| panic!("hisn bug: {name} missing from the syscall table"))
}

fn cond(arg: u8, len: SeccompCmpArgLen, op: SeccompCmpOp, v: u64) -> SeccompCondition {
    SeccompCondition::new(arg, len, op, v).expect("static condition is valid")
}

fn rule(c: SeccompCondition) -> SeccompRule {
    SeccompRule::new(vec![c]).expect("single-condition rule is valid")
}

/// The set of unconditionally denied syscall names (base + arch + extra).
pub fn denied_names(extra_deny: &[String]) -> Result<BTreeSet<String>, SeccompError> {
    let mut set: BTreeSet<String> = BASE_DENY
        .iter()
        .chain(ARCH_DENY)
        .map(|s| (*s).to_owned())
        .collect();
    for e in extra_deny {
        if lookup(e).is_none() {
            return Err(SeccompError::UnknownSyscall(e.clone()));
        }
        set.insert(e.clone());
    }
    Ok(set)
}

fn compile(f: SeccompFilter) -> Result<BpfProgram, SeccompError> {
    BpfProgram::try_from(f).map_err(|e| SeccompError::Build(e.to_string()))
}

fn build_main(denied: &BTreeSet<String>) -> Result<BpfProgram, SeccompError> {
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    for name in denied {
        // An empty rule vector means "match unconditionally".
        rules.insert(nr_of(name), vec![]);
    }
    // clone: deny when any CLONE_NEW* bit is set (one rule per bit; OR'd).
    rules.insert(
        nr_of("clone"),
        CLONE_NEW_BITS
            .iter()
            .map(|b| {
                rule(cond(
                    0,
                    SeccompCmpArgLen::Qword,
                    SeccompCmpOp::MaskedEq(*b),
                    *b,
                ))
            })
            .collect(),
    );
    // ioctl: terminal injection / line-discipline requests (cmd is 32-bit).
    rules.insert(
        nr_of("ioctl"),
        [TIOCSTI, TIOCLINUX, TIOCSETD]
            .iter()
            .map(|c| rule(cond(1, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, *c)))
            .collect(),
    );
    compile(
        SeccompFilter::new(
            rules,
            SeccompAction::Allow,
            SeccompAction::Errno(libc::EPERM as u32),
            TARGET,
        )
        .map_err(|e| SeccompError::Build(e.to_string()))?,
    )
}

fn build_clone3() -> Result<BpfProgram, SeccompError> {
    let mut rules = BTreeMap::new();
    rules.insert(nr_of("clone3"), vec![]);
    compile(
        SeccompFilter::new(
            rules,
            SeccompAction::Allow,
            SeccompAction::Errno(libc::ENOSYS as u32),
            TARGET,
        )
        .map_err(|e| SeccompError::Build(e.to_string()))?,
    )
}

/// x32 ABI guard: `nr >= 0x4000_0000` → kill. Hand-assembled because the
/// condition is on the syscall number, which `seccompiler` rules cannot test.
#[cfg(target_arch = "x86_64")]
fn build_x32_guard() -> BpfProgram {
    const BPF_LD_W_ABS: u16 = 0x20;
    const BPF_JGE_K: u16 = 0x35;
    const BPF_RET_K: u16 = 0x06;
    let ins = |code, jt, jf, k| sock_filter { code, jt, jf, k };
    vec![
        ins(BPF_LD_W_ABS, 0, 0, 0), // A = seccomp_data.nr
        ins(BPF_JGE_K, 0, 1, 0x4000_0000),
        ins(BPF_RET_K, 0, 0, libc::SECCOMP_RET_KILL_PROCESS),
        ins(BPF_RET_K, 0, 0, libc::SECCOMP_RET_ALLOW),
    ]
}

/// Build the filter stack for `extra_deny`. Validates names.
pub fn build(extra_deny: &[String]) -> Result<Vec<BpfProgram>, SeccompError> {
    let denied = denied_names(extra_deny)?;
    #[cfg_attr(not(target_arch = "x86_64"), allow(unused_mut))]
    let mut progs = vec![build_main(&denied)?, build_clone3()?];
    #[cfg(target_arch = "x86_64")]
    progs.push(build_x32_guard());
    Ok(progs)
}

/// Install the stack on the calling thread (sets `no_new_privs` first).
/// Call from the sandbox init *after* all setup syscalls (DESIGN §3 step 12).
pub fn install(progs: &[BpfProgram]) -> Result<(), SeccompError> {
    for p in progs {
        seccompiler::apply_filter(p).map_err(|e| SeccompError::Install(e.to_string()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use seccompiler::sock_filter;

    const AUDIT_ARCH: u32 = {
        #[cfg(target_arch = "x86_64")]
        {
            62 | 0x8000_0000 | 0x4000_0000
        }
        #[cfg(target_arch = "aarch64")]
        {
            183 | 0x8000_0000 | 0x4000_0000
        }
    };
    const ALLOW: u32 = libc::SECCOMP_RET_ALLOW;

    fn errno(e: i32) -> u32 {
        libc::SECCOMP_RET_ERRNO | e as u32
    }

    /// Minimal classic-BPF interpreter for the instruction subset that
    /// `seccompiler` emits (LD abs, ALU and, JEQ/JGT/JGE/JA, RET).
    fn run(prog: &[sock_filter], arch: u32, nr: u32, args: [u64; 6]) -> u32 {
        let load = |off: u32| -> u32 {
            match off {
                0 => nr,
                4 => arch,
                16..=63 => {
                    let i = ((off - 16) / 8) as usize;
                    if (off - 16).is_multiple_of(8) {
                        args[i] as u32
                    } else {
                        (args[i] >> 32) as u32
                    }
                }
                _ => panic!("unexpected load offset {off}"),
            }
        };
        let (mut a, mut pc) = (0u32, 0usize);
        loop {
            let i = &prog[pc];
            pc += 1;
            match i.code {
                0x20 => a = load(i.k),                                     // LD W ABS
                0x54 => a &= i.k,                                          // ALU AND K
                0x15 => pc += if a == i.k { i.jt } else { i.jf } as usize, // JEQ
                0x25 => pc += if a > i.k { i.jt } else { i.jf } as usize,  // JGT
                0x35 => pc += if a >= i.k { i.jt } else { i.jf } as usize, // JGE
                0x05 => pc += i.k as usize,                                // JA
                0x06 => return i.k,                                        // RET K
                c => panic!("unexpected bpf opcode {c:#x}"),
            }
        }
    }

    /// Most restrictive result across a filter stack (kernel semantics).
    fn eval(progs: &[BpfProgram], nr: i64, args: [u64; 6]) -> u32 {
        progs
            .iter()
            .map(|p| run(p, AUDIT_ARCH, nr as u32, args))
            .min_by_key(|r| (r & 0xffff_0000) as i32)
            .unwrap()
    }

    fn stack() -> Vec<BpfProgram> {
        build(&[]).unwrap()
    }

    #[test]
    fn invariant_2_list_is_fully_denied_with_eperm() {
        let s = stack();
        // Exactly the names listed in invariant 2 of the brief (families expanded).
        for name in [
            "mount",
            "umount2",
            "pivot_root",
            "unshare",
            "setns",
            "open_tree",
            "move_mount",
            "fsopen",
            "fsmount",
            "ptrace",
            "bpf",
            "keyctl",
            "io_uring_setup",
            "io_uring_enter",
            "io_uring_register",
            "perf_event_open",
            "kexec_load",
            "kexec_file_load",
            "reboot",
            "swapon",
            "init_module",
            "finit_module",
            "delete_module",
        ] {
            assert_eq!(eval(&s, nr_of(name), [0; 6]), errno(libc::EPERM), "{name}");
        }
        // Siblings added by DESIGN
        for name in [
            "fsconfig",
            "fspick",
            "mount_setattr",
            "chroot",
            "swapoff",
            "add_key",
            "request_key",
        ] {
            assert_eq!(eval(&s, nr_of(name), [0; 6]), errno(libc::EPERM), "{name}");
        }
    }

    #[test]
    fn design_d9_additions_are_denied() {
        let s = stack();
        for name in [
            "process_vm_readv",
            "process_vm_writev",
            "pidfd_getfd",
            "kcmp",
            "open_by_handle_at",
            "name_to_handle_at",
            "userfaultfd",
            "quotactl",
            "acct",
            "lookup_dcookie",
            "syslog",
            "settimeofday",
            "clock_settime",
            "clock_adjtime",
            "adjtimex",
            "personality",
        ] {
            assert_eq!(eval(&s, nr_of(name), [0; 6]), errno(libc::EPERM), "{name}");
        }
    }

    #[test]
    fn ordinary_syscalls_stay_allowed() {
        let s = stack();
        for name in [
            "getpid",
            "socket",
            "connect",
            "memfd_create",
            "unlinkat",
            "symlinkat",
            "mknodat",
            "sethostname",
            "pidfd_open",
        ] {
            assert_eq!(eval(&s, nr_of(name), [0; 6]), ALLOW, "{name}");
        }
        // plain clone (fork/thread style flags) and a harmless ioctl
        assert_eq!(
            eval(&s, nr_of("clone"), [0x0000_0100 | 17, 0, 0, 0, 0, 0]),
            ALLOW
        );
        assert_eq!(
            eval(&s, nr_of("ioctl"), [0, 0x5401 /* TCGETS */, 0, 0, 0, 0]),
            ALLOW
        );
    }

    #[test]
    fn clone_with_any_new_namespace_bit_is_denied() {
        let s = stack();
        let n = nr_of("clone");
        for bit in CLONE_NEW_BITS {
            for base in [0u64, 0x0000_0100 | 17, 0x003d_0f00] {
                assert_eq!(
                    eval(&s, n, [base | bit, 0, 0, 0, 0, 0]),
                    errno(libc::EPERM),
                    "bit {bit:#x} base {base:#x}"
                );
            }
        }
        // upper 32 bits of the flags word are not ignored
        assert_eq!(
            eval(&s, n, [0x1_0000_0000 | CLONE_NEW_BITS[4], 0, 0, 0, 0, 0]),
            errno(libc::EPERM)
        );
    }

    #[test]
    fn clone3_is_enosys() {
        assert_eq!(eval(&stack(), nr_of("clone3"), [0; 6]), errno(libc::ENOSYS));
    }

    #[test]
    fn ioctl_tty_injection_is_denied_only_for_those_commands() {
        let s = stack();
        let n = nr_of("ioctl");
        for cmd in [TIOCSTI, TIOCLINUX, TIOCSETD] {
            assert_eq!(
                eval(&s, n, [0, cmd, 0, 0, 0, 0]),
                errno(libc::EPERM),
                "{cmd:#x}"
            );
            // high bits of the (32-bit) cmd are ignored by the kernel, so the
            // filter compares only the low dword
            assert_eq!(
                eval(&s, n, [0, 0xdead_0000_0000 | cmd, 0, 0, 0, 0]),
                errno(libc::EPERM)
            );
        }
        assert_eq!(eval(&s, n, [0, 0x5413 /* TIOCGWINSZ */, 0, 0, 0, 0]), ALLOW);
    }

    #[test]
    fn foreign_architecture_is_killed() {
        let s = stack();
        let foreign = if AUDIT_ARCH == 62 | 0xC000_0000 {
            183 | 0xC000_0000
        } else {
            62 | 0xC000_0000
        };
        let r = run(&s[0], foreign, nr_of("getpid") as u32, [0; 6]);
        assert_eq!(r, libc::SECCOMP_RET_KILL_PROCESS);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn x32_syscall_numbers_are_killed() {
        let s = stack();
        let r = eval(&s, 0x4000_0000 + 39, [0; 6]); // x32 getpid
        assert_eq!(r, libc::SECCOMP_RET_KILL_PROCESS);
        assert_eq!(eval(&s, 39, [0; 6]), ALLOW);
        assert_eq!(s.len(), 3);
    }

    #[test]
    fn extra_deny_adds_and_unknown_names_fail() {
        let s = build(&["socket".to_owned(), "memfd_create".to_owned()]).unwrap();
        assert_eq!(eval(&s, nr_of("socket"), [0; 6]), errno(libc::EPERM));
        assert_eq!(eval(&s, nr_of("memfd_create"), [0; 6]), errno(libc::EPERM));
        assert_eq!(eval(&s, nr_of("getpid"), [0; 6]), ALLOW);
        assert!(matches!(
            build(&["no_such_call".to_owned()]),
            Err(SeccompError::UnknownSyscall(_))
        ));
        // extra_deny cannot weaken: duplicates of base names are fine
        assert!(build(&["mount".to_owned()]).is_ok());
    }

    #[test]
    fn filters_fit_the_bpf_limit() {
        for p in stack() {
            assert!(p.len() < 4096);
        }
    }

    #[test]
    fn every_base_name_is_in_the_table() {
        for n in BASE_DENY.iter().chain(ARCH_DENY) {
            assert!(lookup(n).is_some(), "{n}");
        }
    }

    /// Real kernel check: install the stack in a forked child and observe
    /// EPERM from ptrace(TRACEME) (allowed without the filter). Needs only
    /// seccomp, not user namespaces, so it runs in restricted containers too.
    #[test]
    fn kernel_enforces_installed_filter() {
        // SAFETY: fork in a test process; the child only makes raw syscalls
        // and `_exit`s, never returning into the test harness.
        unsafe {
            let pid = libc::fork();
            assert!(pid >= 0);
            if pid == 0 {
                let progs = build(&[]).expect("build");
                if install(&progs).is_err() {
                    libc::_exit(10);
                }
                let r = libc::syscall(libc::SYS_ptrace, libc::PTRACE_TRACEME, 0, 0, 0);
                let e = *libc::__errno_location();
                let pid_ok = libc::syscall(libc::SYS_getpid) > 0;
                libc::_exit(if r == -1 && e == libc::EPERM && pid_ok {
                    0
                } else {
                    11
                });
            }
            let mut status = 0;
            libc::waitpid(pid, &mut status, 0);
            assert!(
                libc::WIFEXITED(status),
                "child did not exit normally: {status:#x}"
            );
            assert_eq!(
                libc::WEXITSTATUS(status),
                0,
                "child exit code (10=install failed, 11=filter ineffective)"
            );
        }
    }
}

//! Persistent Guest Executor.
//!
//! Security model for this stage:
//!
//! trusted isolated-service parent
//!     -> pre-created AF_UNIX SOCK_SEQPACKET socketpair
//!     -> fork()
//!     -> child normalizes the only retained capability to fd 3
//!     -> closes inherited descriptors
//!     -> blocks catchable inherited signals
//!     -> PR_SET_NO_NEW_PRIVS
//!     -> strict default-deny seccomp
//!     -> fixed-size IPC loop
//!
//! IMPORTANT:
//! The post-fork child deliberately avoids JNI, Rust allocation, logging,
//! filesystem access, mutexes, and high-level runtime code.

use std::sync::Mutex;

const CONTROL_FD: i32 = 3;

const MAGIC_0: u8 = b'S';
const MAGIC_1: u8 = b'G';
const PROTOCOL_VERSION: u8 = 1;
const PACKET_LEN: usize = 8;

const OP_PING: u8 = 0x01;
const OP_STATUS: u8 = 0x02;
const OP_SHUTDOWN: u8 = 0x03;

const RESP_READY: u8 = 0x80;
const RESP_PONG: u8 = 0x81;
const RESP_LOCKED: u8 = 0x82;
const RESP_BYE: u8 = 0x83;
const RESP_ERROR: u8 = 0xff;

const AF_UNIX: i32 = 1;
const SOCK_SEQPACKET: i32 = 5;
const SOCK_CLOEXEC: i32 = 0x0008_0000;

const MSG_TRUNC: i32 = 0x20;
const MSG_NOSIGNAL: i32 = 0x4000;

const POLLIN: i16 = 0x0001;

const SIGKILL: i32 = 9;
const SIG_SETMASK: i64 = 2;

const RLIMIT_NOFILE: i32 = 7;
const MAX_FALLBACK_CLOSE_FDS: u32 = 1_048_576;

const PR_SET_PDEATHSIG: i64 = 1;
const PR_SET_SECCOMP: i64 = 22;
const PR_SET_NO_NEW_PRIVS: i64 = 38;
const PR_GET_NO_NEW_PRIVS: i64 = 39;

const SECCOMP_MODE_FILTER: i64 = 2;

const BPF_LD_W_ABS: u16 = 0x20;
const BPF_JMP_JEQ_K: u16 = 0x15;
const BPF_RET_K: u16 = 0x06;

const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;

const EPERM: i32 = 1;
const ENOENT: i32 = 2;
const EIO: i32 = 5;
const EBUSY: i32 = 16;
const EINVAL: i32 = 22;
const EPROTO: i32 = 71;
const ETIMEDOUT: i32 = 110;

const STARTUP_TIMEOUT_MS: i32 = 2_000;

#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH_NATIVE: u32 = 0xC000_00B7;
#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH_NATIVE: u32 = 0xC000_003E;

#[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
const AUDIT_ARCH_NATIVE: u32 = 0;

/*
 * AArch64 Linux syscall numbers used after fork.
 *
 * Only the AArch64 child executes the locked-down runtime. Keeping this list
 * explicit makes the kernel surface auditable.
 */
#[cfg(target_arch = "aarch64")]
mod nr {
    pub const DUP3: i64 = 24;
    pub const CLOSE: i64 = 57;
    pub const EXIT: i64 = 93;
    pub const EXIT_GROUP: i64 = 94;
    pub const KILL: i64 = 129;
    pub const RT_SIGPROCMASK: i64 = 135;
    pub const PRCTL: i64 = 167;
    pub const GETPID: i64 = 172;
    pub const GETPPID: i64 = 173;
    pub const GETUID: i64 = 174;
    pub const SENDTO: i64 = 206;
    pub const RECVFROM: i64 = 207;
    pub const CLOSE_RANGE: i64 = 436;
}

#[repr(C)]
struct PollFd {
    fd: i32,
    events: i16,
    revents: i16,
}

#[repr(C)]
struct RLimit {
    rlim_cur: u64,
    rlim_max: u64,
}

#[repr(C)]
struct SockFilter {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

#[repr(C)]
struct SockFprog {
    len: u16,
    filter: *const SockFilter,
}

/*
 * Parent-side C ABI only.
 *
 * These calls happen in the trusted isolated service process. The locked-down
 * child does not call these wrappers after fork.
 */
unsafe extern "C" {
    fn socketpair(domain: i32, socket_type: i32, protocol: i32, sv: *mut i32) -> i32;
    fn fork() -> i32;
    fn close(fd: i32) -> i32;
    fn kill(pid: i32, signal: i32) -> i32;
    fn waitpid(pid: i32, status: *mut i32, options: i32) -> i32;
    fn send(fd: i32, buffer: *const u8, length: usize, flags: i32) -> isize;
    fn recv(fd: i32, buffer: *mut u8, length: usize, flags: i32) -> isize;
    fn poll(fds: *mut PollFd, nfds: usize, timeout: i32) -> i32;
    fn getrlimit(resource: i32, limit: *mut RLimit) -> i32;
    fn _exit(status: i32) -> !;
}

#[derive(Clone, Copy)]
struct ExecutorState {
    pid: i32,
    control_fd: i32,
}

impl ExecutorState {
    const fn stopped() -> Self {
        Self {
            pid: 0,
            control_fd: -1,
        }
    }

    fn running(&self) -> bool {
        self.pid > 0 && self.control_fd >= 0
    }
}

static STATE: Mutex<ExecutorState> =
    Mutex::new(ExecutorState::stopped());

fn last_errno() -> i32 {
    std::io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(EIO)
}

const fn packet(opcode: u8) -> [u8; PACKET_LEN] {
    [
        MAGIC_0,
        MAGIC_1,
        PROTOCOL_VERSION,
        opcode,
        0,
        0,
        0,
        0,
    ]
}

fn packet_opcode(bytes: &[u8; PACKET_LEN]) -> Option<u8> {
    if bytes[0] != MAGIC_0
        || bytes[1] != MAGIC_1
        || bytes[2] != PROTOCOL_VERSION
        || bytes[4] != 0
        || bytes[5] != 0
        || bytes[6] != 0
        || bytes[7] != 0
    {
        return None;
    }

    Some(bytes[3])
}

fn parent_send(fd: i32, opcode: u8) -> Result<(), i32> {
    let bytes = packet(opcode);

    let written = unsafe {
        send(
            fd,
            bytes.as_ptr(),
            bytes.len(),
            MSG_NOSIGNAL,
        )
    };

    if written == bytes.len() as isize {
        Ok(())
    } else if written < 0 {
        Err(last_errno())
    } else {
        Err(EPROTO)
    }
}

fn parent_recv(
    fd: i32,
    expected_opcode: u8,
    timeout_ms: i32,
) -> Result<(), i32> {
    let mut poll_fd = PollFd {
        fd,
        events: POLLIN,
        revents: 0,
    };

    let poll_result = unsafe {
        poll(
            &mut poll_fd,
            1,
            timeout_ms,
        )
    };

    if poll_result == 0 {
        return Err(ETIMEDOUT);
    }

    if poll_result < 0 {
        return Err(last_errno());
    }

    if poll_fd.revents & POLLIN == 0 {
        return Err(EIO);
    }

    let mut bytes = [0_u8; PACKET_LEN];

    /*
     * MSG_TRUNC is intentional. For SOCK_SEQPACKET it lets us detect packets
     * larger than our buffer instead of silently accepting a valid prefix.
     */
    let received = unsafe {
        recv(
            fd,
            bytes.as_mut_ptr(),
            bytes.len(),
            MSG_TRUNC,
        )
    };

    if received < 0 {
        return Err(last_errno());
    }

    if received as usize != PACKET_LEN {
        return Err(EPROTO);
    }

    match packet_opcode(&bytes) {
        Some(opcode) if opcode == expected_opcode => Ok(()),
        _ => Err(EPROTO),
    }
}

fn parent_force_terminate(state: &mut ExecutorState) {
    let pid = state.pid;
    let fd = state.control_fd;

    state.pid = 0;
    state.control_fd = -1;

    if fd >= 0 {
        unsafe {
            let _ = close(fd);
        }
    }

    if pid > 0 {
        unsafe {
            let _ = kill(pid, SIGKILL);
            let _ = waitpid(
                pid,
                std::ptr::null_mut(),
                0,
            );
        }
    }
}

fn capture_fd_limit() -> Result<u32, i32> {
    let mut limit = RLimit {
        rlim_cur: 0,
        rlim_max: 0,
    };

    if unsafe {
        getrlimit(
            RLIMIT_NOFILE,
            &mut limit,
        )
    } != 0
    {
        return Err(last_errno());
    }

    if limit.rlim_cur > u32::MAX as u64 {
        Ok(u32::MAX)
    } else {
        Ok(limit.rlim_cur as u32)
    }
}

/// Starts one persistent Guest Executor.
///
/// The caller MUST be the Android isolated service process, never the normal
/// application process.
pub fn start() -> Result<i32, i32> {
    let mut state =
        STATE.lock().map_err(|_| EIO)?;

    if state.running() {
        return Err(EBUSY);
    }

    let max_fd = capture_fd_limit()?;

    let mut pair = [-1_i32; 2];

    if unsafe {
        socketpair(
            AF_UNIX,
            SOCK_SEQPACKET | SOCK_CLOEXEC,
            0,
            pair.as_mut_ptr(),
        )
    } != 0
    {
        return Err(last_errno());
    }

    let parent_fd = pair[0];
    let child_fd = pair[1];

    let child_pid = unsafe { fork() };

    if child_pid < 0 {
        let errno = last_errno();

        unsafe {
            let _ = close(parent_fd);
            let _ = close(child_fd);
        }

        return Err(errno);
    }

    if child_pid == 0 {
        /*
         * No Rust heap allocation, logging, JNI, filesystem, or mutex access
         * after this branch.
         */
        #[cfg(target_arch = "aarch64")]
        unsafe {
            child_main(
                parent_fd,
                child_fd,
                max_fd,
            );
        }

        #[cfg(not(target_arch = "aarch64"))]
        unsafe {
            _exit(119);
        }
    }

    unsafe {
        let _ = close(child_fd);
    }

    state.pid = child_pid;
    state.control_fd = parent_fd;

    if let Err(errno) =
        parent_recv(
            parent_fd,
            RESP_READY,
            STARTUP_TIMEOUT_MS,
        )
    {
        parent_force_terminate(&mut state);
        return Err(errno);
    }

    Ok(child_pid)
}

/// Sends PING to the already-running child.
pub fn ping() -> Result<i32, i32> {
    request_response(
        OP_PING,
        RESP_PONG,
    )
}

/// Confirms that the child is alive behind its locked-down boundary.
pub fn status() -> Result<i32, i32> {
    request_response(
        OP_STATUS,
        RESP_LOCKED,
    )
}

fn request_response(
    request_opcode: u8,
    response_opcode: u8,
) -> Result<i32, i32> {
    let mut state =
        STATE.lock().map_err(|_| EIO)?;

    if !state.running() {
        return Err(ENOENT);
    }

    let pid = state.pid;
    let fd = state.control_fd;

    if let Err(errno) =
        parent_send(
            fd,
            request_opcode,
        )
    {
        parent_force_terminate(&mut state);
        return Err(errno);
    }

    if let Err(errno) =
        parent_recv(
            fd,
            response_opcode,
            STARTUP_TIMEOUT_MS,
        )
    {
        parent_force_terminate(&mut state);
        return Err(errno);
    }

    Ok(pid)
}

/// Requests a clean shutdown and reaps the child.
pub fn shutdown() -> Result<(), i32> {
    let mut state =
        STATE.lock().map_err(|_| EIO)?;

    if !state.running() {
        return Err(ENOENT);
    }

    let pid = state.pid;
    let fd = state.control_fd;

    if let Err(errno) =
        parent_send(
            fd,
            OP_SHUTDOWN,
        )
    {
        parent_force_terminate(&mut state);
        return Err(errno);
    }

    if let Err(errno) =
        parent_recv(
            fd,
            RESP_BYE,
            STARTUP_TIMEOUT_MS,
        )
    {
        parent_force_terminate(&mut state);
        return Err(errno);
    }

    state.pid = 0;
    state.control_fd = -1;

    unsafe {
        let _ = close(fd);
    }

    let mut wait_status = 0_i32;

    let waited = unsafe {
        waitpid(
            pid,
            &mut wait_status,
            0,
        )
    };

    if waited < 0 {
        return Err(last_errno());
    }

    if wait_if_exited(wait_status)
        && wait_exit_status(wait_status) == 0
    {
        Ok(())
    } else {
        Err(EIO)
    }
}

fn wait_if_exited(status: i32) -> bool {
    (status & 0x7f) == 0
}

fn wait_exit_status(status: i32) -> i32 {
    (status >> 8) & 0xff
}

#[cfg(target_arch = "aarch64")]
#[inline(always)]
unsafe fn svc0(number: i64) -> i64 {
    let result: i64;

    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") number,
            lateout("x0") result,
            options(nostack),
        );
    }

    result
}

#[cfg(target_arch = "aarch64")]
#[inline(always)]
unsafe fn svc1(
    number: i64,
    arg0: i64,
) -> i64 {
    let result: i64;

    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") number,
            inlateout("x0") arg0 => result,
            options(nostack),
        );
    }

    result
}

#[cfg(target_arch = "aarch64")]
#[inline(always)]
unsafe fn svc3(
    number: i64,
    arg0: i64,
    arg1: i64,
    arg2: i64,
) -> i64 {
    let result: i64;

    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") number,
            inlateout("x0") arg0 => result,
            in("x1") arg1,
            in("x2") arg2,
            options(nostack),
        );
    }

    result
}

#[cfg(target_arch = "aarch64")]
#[inline(always)]
unsafe fn svc4(
    number: i64,
    arg0: i64,
    arg1: i64,
    arg2: i64,
    arg3: i64,
) -> i64 {
    let result: i64;

    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") number,
            inlateout("x0") arg0 => result,
            in("x1") arg1,
            in("x2") arg2,
            in("x3") arg3,
            options(nostack),
        );
    }

    result
}

#[cfg(target_arch = "aarch64")]
#[inline(always)]
unsafe fn svc5(
    number: i64,
    arg0: i64,
    arg1: i64,
    arg2: i64,
    arg3: i64,
    arg4: i64,
) -> i64 {
    let result: i64;

    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") number,
            inlateout("x0") arg0 => result,
            in("x1") arg1,
            in("x2") arg2,
            in("x3") arg3,
            in("x4") arg4,
            options(nostack),
        );
    }

    result
}

#[cfg(target_arch = "aarch64")]
#[inline(always)]
unsafe fn svc6(
    number: i64,
    arg0: i64,
    arg1: i64,
    arg2: i64,
    arg3: i64,
    arg4: i64,
    arg5: i64,
) -> i64 {
    let result: i64;

    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") number,
            inlateout("x0") arg0 => result,
            in("x1") arg1,
            in("x2") arg2,
            in("x3") arg3,
            in("x4") arg4,
            in("x5") arg5,
            options(nostack),
        );
    }

    result
}

#[cfg(target_arch = "aarch64")]
unsafe fn child_close(fd: i32) {
    unsafe {
        let _ = svc1(
            nr::CLOSE,
            fd as i64,
        );
    }
}

#[cfg(target_arch = "aarch64")]
unsafe fn child_exit_now(code: i32) -> ! {
    unsafe {
        let _ = svc1(
            nr::EXIT_GROUP,
            code.clamp(0, 255) as i64,
        );

        let _ = svc1(
            nr::EXIT,
            code.clamp(0, 255) as i64,
        );
    }

    loop {
        core::hint::spin_loop();
    }
}

#[cfg(target_arch = "aarch64")]
unsafe fn child_normalize_control_fd(
    parent_fd: i32,
    child_fd: i32,
) -> bool {
    unsafe {
        child_close(parent_fd);

        if child_fd != CONTROL_FD {
            let duplicated = svc3(
                nr::DUP3,
                child_fd as i64,
                CONTROL_FD as i64,
                0,
            );

            if duplicated != CONTROL_FD as i64 {
                return false;
            }

            child_close(child_fd);
        }

        child_close(0);
        child_close(1);
        child_close(2);
    }

    true
}

#[cfg(target_arch = "aarch64")]
unsafe fn child_scrub_fds(
    max_fd: u32,
) -> bool {
    /*
     * Prefer close_range(4, UINT_MAX, 0). If Android's inherited policy or an
     * older kernel rejects it, fail over to explicit close().
     */
    let close_range_result = unsafe {
        svc3(
            nr::CLOSE_RANGE,
            4,
            u32::MAX as i64,
            0,
        )
    };

    if close_range_result == 0 {
        return true;
    }

    if max_fd > MAX_FALLBACK_CLOSE_FDS {
        /*
         * Fail closed rather than silently retaining high-numbered FDs.
         */
        return false;
    }

    let mut fd = 4_u32;

    while fd < max_fd {
        unsafe {
            child_close(fd as i32);
        }

        fd += 1;
    }

    true
}

#[cfg(target_arch = "aarch64")]
unsafe fn child_block_catchable_signals() -> bool {
    /*
     * Linux kernel sigset for AArch64 is 64 bits.
     * SIGKILL/SIGSTOP cannot be blocked and are ignored by the kernel mask.
     */
    let all_signals = u64::MAX;

    let result = unsafe {
        svc4(
            nr::RT_SIGPROCMASK,
            SIG_SETMASK,
            (&all_signals as *const u64) as i64,
            0,
            core::mem::size_of::<u64>() as i64,
        )
    };

    result == 0
}

#[cfg(target_arch = "aarch64")]
unsafe fn child_set_pdeathsig() -> bool {
    let result = unsafe {
        svc5(
            nr::PRCTL,
            PR_SET_PDEATHSIG,
            SIGKILL as i64,
            0,
            0,
            0,
        )
    };

    if result != 0 {
        return false;
    }

    /*
     * Race check if getppid is available. The inherited old PoC filter may
     * return -EPERM for getppid; that is acceptable for this temporary stage.
     */
    let ppid = unsafe {
        svc0(nr::GETPPID)
    };

    ppid != 1
}

#[cfg(target_arch = "aarch64")]
unsafe fn child_enable_nnp() -> bool {
    let set_result = unsafe {
        svc5(
            nr::PRCTL,
            PR_SET_NO_NEW_PRIVS,
            1,
            0,
            0,
            0,
        )
    };

    if set_result != 0 {
        return false;
    }

    let get_result = unsafe {
        svc5(
            nr::PRCTL,
            PR_GET_NO_NEW_PRIVS,
            0,
            0,
            0,
            0,
        )
    };

    get_result == 1
}

#[cfg(target_arch = "aarch64")]
unsafe fn child_install_strict_seccomp() -> bool {
    if AUDIT_ARCH_NATIVE == 0 {
        return false;
    }

    /*
     * seccomp_data:
     *   nr   @ offset 0
     *   arch @ offset 4
     *
     * Allowed kernel surface after lockdown:
     *   recvfrom
     *   sendto
     *   close
     *   getpid        (temporary positive-control syscall)
     *   exit
     *   exit_group
     *
     * Everything else -> EPERM.
     */
    let filters = [
        SockFilter {
            code: BPF_LD_W_ABS,
            jt: 0,
            jf: 0,
            k: 4,
        },
        SockFilter {
            code: BPF_JMP_JEQ_K,
            jt: 1,
            jf: 0,
            k: AUDIT_ARCH_NATIVE,
        },
        SockFilter {
            code: BPF_RET_K,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_KILL_PROCESS,
        },
        SockFilter {
            code: BPF_LD_W_ABS,
            jt: 0,
            jf: 0,
            k: 0,
        },
        SockFilter {
            code: BPF_JMP_JEQ_K,
            jt: 0,
            jf: 1,
            k: nr::RECVFROM as u32,
        },
        SockFilter {
            code: BPF_RET_K,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_ALLOW,
        },
        SockFilter {
            code: BPF_JMP_JEQ_K,
            jt: 0,
            jf: 1,
            k: nr::SENDTO as u32,
        },
        SockFilter {
            code: BPF_RET_K,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_ALLOW,
        },
        SockFilter {
            code: BPF_JMP_JEQ_K,
            jt: 0,
            jf: 1,
            k: nr::CLOSE as u32,
        },
        SockFilter {
            code: BPF_RET_K,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_ALLOW,
        },
        SockFilter {
            code: BPF_JMP_JEQ_K,
            jt: 0,
            jf: 1,
            k: nr::GETPID as u32,
        },
        SockFilter {
            code: BPF_RET_K,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_ALLOW,
        },
        SockFilter {
            code: BPF_JMP_JEQ_K,
            jt: 0,
            jf: 1,
            k: nr::EXIT as u32,
        },
        SockFilter {
            code: BPF_RET_K,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_ALLOW,
        },
        SockFilter {
            code: BPF_JMP_JEQ_K,
            jt: 0,
            jf: 1,
            k: nr::EXIT_GROUP as u32,
        },
        SockFilter {
            code: BPF_RET_K,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_ALLOW,
        },
        SockFilter {
            code: BPF_RET_K,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_ERRNO | EPERM as u32,
        },
    ];

    let program = SockFprog {
        len: filters.len() as u16,
        filter: filters.as_ptr(),
    };

    let result = unsafe {
        svc5(
            nr::PRCTL,
            PR_SET_SECCOMP,
            SECCOMP_MODE_FILTER,
            (&program as *const SockFprog) as i64,
            0,
            0,
        )
    };

    result == 0
}

#[cfg(target_arch = "aarch64")]
unsafe fn child_verify_boundary() -> bool {
    let allowed_getpid =
        unsafe { svc0(nr::GETPID) };

    let blocked_getuid =
        unsafe { svc0(nr::GETUID) };

    allowed_getpid > 0
        && blocked_getuid == -(EPERM as i64)
}

#[cfg(target_arch = "aarch64")]
unsafe fn child_send(opcode: u8) -> bool {
    let bytes = packet(opcode);

    let result = unsafe {
        svc6(
            nr::SENDTO,
            CONTROL_FD as i64,
            bytes.as_ptr() as i64,
            PACKET_LEN as i64,
            MSG_NOSIGNAL as i64,
            0,
            0,
        )
    };

    result == PACKET_LEN as i64
}

#[cfg(target_arch = "aarch64")]
unsafe fn child_recv(
    bytes: &mut [u8; PACKET_LEN],
) -> i64 {
    unsafe {
        svc6(
            nr::RECVFROM,
            CONTROL_FD as i64,
            bytes.as_mut_ptr() as i64,
            PACKET_LEN as i64,
            MSG_TRUNC as i64,
            0,
            0,
        )
    }
}

#[cfg(target_arch = "aarch64")]
unsafe fn child_main(
    parent_fd: i32,
    child_fd: i32,
    max_fd: u32,
) -> ! {
    if !unsafe {
        child_normalize_control_fd(
            parent_fd,
            child_fd,
        )
    } {
        unsafe { child_exit_now(101) };
    }

    if !unsafe {
        child_scrub_fds(max_fd)
    } {
        unsafe { child_exit_now(102) };
    }

    if !unsafe {
        child_block_catchable_signals()
    } {
        unsafe { child_exit_now(103) };
    }

    if !unsafe {
        child_set_pdeathsig()
    } {
        unsafe { child_exit_now(104) };
    }

    if !unsafe {
        child_enable_nnp()
    } {
        unsafe { child_exit_now(105) };
    }

    if !unsafe {
        child_install_strict_seccomp()
    } {
        unsafe { child_exit_now(106) };
    }

    if !unsafe {
        child_verify_boundary()
    } {
        unsafe { child_exit_now(107) };
    }

    if !unsafe {
        child_send(RESP_READY)
    } {
        unsafe { child_exit_now(108) };
    }

    loop {
        let mut bytes =
            [0_u8; PACKET_LEN];

        let received =
            unsafe {
                child_recv(&mut bytes)
            };

        if received <= 0 {
            unsafe {
                child_exit_now(109);
            }
        }

        if received as usize != PACKET_LEN {
            if !unsafe {
                child_send(RESP_ERROR)
            } {
                unsafe {
                    child_exit_now(110);
                }
            }

            continue;
        }

        let opcode =
            packet_opcode(&bytes);

        match opcode {
            Some(OP_PING) => {
                if !unsafe {
                    child_send(RESP_PONG)
                } {
                    unsafe {
                        child_exit_now(111);
                    }
                }
            }

            Some(OP_STATUS) => {
                if !unsafe {
                    child_send(RESP_LOCKED)
                } {
                    unsafe {
                        child_exit_now(112);
                    }
                }
            }

            Some(OP_SHUTDOWN) => {
                let _ =
                    unsafe {
                        child_send(RESP_BYE)
                    };

                unsafe {
                    child_close(CONTROL_FD);
                    child_exit_now(0);
                }
            }

            _ => {
                if !unsafe {
                    child_send(RESP_ERROR)
                } {
                    unsafe {
                        child_exit_now(113);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_shape_is_stable() {
        assert_eq!(
            packet(OP_PING),
            [
                b'S',
                b'G',
                1,
                OP_PING,
                0,
                0,
                0,
                0,
            ],
        );
    }

    #[test]
    fn malformed_packet_is_rejected() {
        let mut malformed =
            packet(OP_STATUS);

        malformed[7] = 1;

        assert_eq!(
            packet_opcode(&malformed),
            None,
        );
    }

    #[test]
    fn valid_packet_returns_opcode() {
        let bytes =
            packet(OP_SHUTDOWN);

        assert_eq!(
            packet_opcode(&bytes),
            Some(OP_SHUTDOWN),
        );
    }
}

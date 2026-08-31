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

use crate::ipc_protocol;
#[cfg(any(target_arch = "aarch64", test))]
use crate::ipc_protocol::MessageKind;
use std::sync::Mutex;

#[cfg_attr(
    not(target_arch = "aarch64"),
    expect(dead_code, reason = "used only by the AArch64 locked child")
)]
const CONTROL_FD: i32 = 3;

#[cfg_attr(
    not(test),
    expect(dead_code, reason = "retained for protocol audit visibility")
)]
const MAGIC_0: u8 = ipc_protocol::MAGIC_0;
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "retained for protocol audit visibility")
)]
const MAGIC_1: u8 = ipc_protocol::MAGIC_1;
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "retained for protocol audit visibility")
)]
const PROTOCOL_VERSION: u8 = ipc_protocol::PROTOCOL_VERSION;
const PACKET_LEN: usize = ipc_protocol::PACKET_LEN;

const OP_PING: u8 = ipc_protocol::OP_PING;
const OP_STATUS: u8 = ipc_protocol::OP_STATUS;
const OP_SHUTDOWN: u8 = ipc_protocol::OP_SHUTDOWN;

const RESP_READY: u8 = ipc_protocol::RESP_READY;
const RESP_PONG: u8 = ipc_protocol::RESP_PONG;
const RESP_LOCKED: u8 = ipc_protocol::RESP_LOCKED;
const RESP_BYE: u8 = ipc_protocol::RESP_BYE;
#[cfg_attr(
    not(target_arch = "aarch64"),
    expect(dead_code, reason = "used only by the AArch64 locked child")
)]
const RESP_ERROR: u8 = ipc_protocol::RESP_ERROR;

const AF_UNIX: i32 = 1;
const SOCK_SEQPACKET: i32 = 5;
const SOCK_CLOEXEC: i32 = 0x0008_0000;

const MSG_TRUNC: i32 = 0x20;
const MSG_NOSIGNAL: i32 = 0x4000;

const POLLIN: i16 = 0x0001;

const SIGKILL: i32 = 9;
#[cfg_attr(
    not(target_arch = "aarch64"),
    expect(dead_code, reason = "used only by the AArch64 locked child")
)]
const SIG_SETMASK: i64 = 2;

const RLIMIT_NOFILE: i32 = 7;
#[cfg_attr(
    not(target_arch = "aarch64"),
    expect(dead_code, reason = "used only by the AArch64 locked child")
)]
const MAX_FALLBACK_CLOSE_FDS: u32 = 1_048_576;

#[cfg_attr(
    not(target_arch = "aarch64"),
    expect(dead_code, reason = "used only by the AArch64 locked child")
)]
const PR_SET_PDEATHSIG: i64 = 1;
#[cfg_attr(
    not(target_arch = "aarch64"),
    expect(dead_code, reason = "used only by the AArch64 locked child")
)]
const PR_SET_SECCOMP: i64 = 22;
#[cfg_attr(
    not(target_arch = "aarch64"),
    expect(dead_code, reason = "used only by the AArch64 locked child")
)]
const PR_SET_NO_NEW_PRIVS: i64 = 38;
#[cfg_attr(
    not(target_arch = "aarch64"),
    expect(dead_code, reason = "used only by the AArch64 locked child")
)]
const PR_GET_NO_NEW_PRIVS: i64 = 39;

#[cfg_attr(
    not(target_arch = "aarch64"),
    expect(dead_code, reason = "used only by the AArch64 locked child")
)]
const SECCOMP_MODE_FILTER: i64 = 2;

#[cfg_attr(
    not(target_arch = "aarch64"),
    expect(dead_code, reason = "used only by the AArch64 locked child")
)]
const BPF_LD_W_ABS: u16 = 0x20;
#[cfg_attr(
    not(target_arch = "aarch64"),
    expect(dead_code, reason = "used only by the AArch64 locked child")
)]
const BPF_JMP_JEQ_K: u16 = 0x15;
#[cfg_attr(
    not(target_arch = "aarch64"),
    expect(dead_code, reason = "used only by the AArch64 locked child")
)]
const BPF_RET_K: u16 = 0x06;

#[cfg_attr(
    not(target_arch = "aarch64"),
    expect(dead_code, reason = "used only by the AArch64 locked child")
)]
const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
#[cfg_attr(
    not(target_arch = "aarch64"),
    expect(dead_code, reason = "used only by the AArch64 locked child")
)]
const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
#[cfg_attr(
    not(target_arch = "aarch64"),
    expect(dead_code, reason = "used only by the AArch64 locked child")
)]
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;

#[cfg_attr(
    not(target_arch = "aarch64"),
    expect(dead_code, reason = "used only by the AArch64 locked child")
)]
const EPERM: i32 = 1;
const ENOENT: i32 = 2;
const EIO: i32 = 5;
const EBUSY: i32 = 16;
#[expect(
    dead_code,
    reason = "retained in the explicit Linux errno table for this low-level TCB"
)]
const EINVAL: i32 = 22;
const EPROTO: i32 = 71;
const ETIMEDOUT: i32 = 110;

const STARTUP_TIMEOUT_MS: i32 = 2_000;

#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH_NATIVE: u32 = 0xC000_00B7;
#[cfg(target_arch = "x86_64")]
#[expect(
    dead_code,
    reason = "retained for architecture audit documentation; locked child currently runs only on AArch64"
)]
const AUDIT_ARCH_NATIVE: u32 = 0xC000_003E;

#[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
#[expect(
    dead_code,
    reason = "retained as the fail-closed architecture sentinel"
)]
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
    #[expect(
        dead_code,
        reason = "retained in the explicit AArch64 syscall table for audit completeness"
    )]
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

#[cfg_attr(
    not(target_arch = "aarch64"),
    expect(dead_code, reason = "used only by the AArch64 seccomp program")
)]
#[repr(C)]
struct SockFilter {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

#[cfg_attr(
    not(target_arch = "aarch64"),
    expect(dead_code, reason = "used only by the AArch64 seccomp program")
)]
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
    next_request_id: u32,
}

impl ExecutorState {
    const fn stopped() -> Self {
        Self {
            pid: 0,
            control_fd: -1,
            next_request_id: 1,
        }
    }

    fn running(&self) -> bool {
        self.pid > 0 && self.control_fd >= 0
    }
}

static STATE: Mutex<ExecutorState> = Mutex::new(ExecutorState::stopped());

fn last_errno() -> i32 {
    std::io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(EIO)
}

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "retained as the original packet helper while IPC v1 uses explicit request IDs"
    )
)]
fn packet(opcode: u8) -> [u8; PACKET_LEN] {
    let request_id = if opcode == RESP_READY { 0 } else { 1 };

    let encoded = if ipc_protocol::is_request_opcode(opcode) {
        ipc_protocol::encode_request(opcode, request_id)
    } else {
        ipc_protocol::encode_response(opcode, request_id)
    };

    encoded.unwrap_or([0_u8; PACKET_LEN])
}

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "retained as the original parser helper; production IPC v1 consumes the full parsed message"
    )
)]
fn packet_opcode(bytes: &[u8; PACKET_LEN]) -> Option<u8> {
    ipc_protocol::parse(bytes)
        .ok()
        .map(|message| message.opcode)
}

fn take_request_id(state: &mut ExecutorState) -> u32 {
    let request_id = state.next_request_id;

    state.next_request_id = state.next_request_id.wrapping_add(1);
    if state.next_request_id == 0 {
        state.next_request_id = 1;
    }

    request_id
}

fn parent_send(fd: i32, opcode: u8, request_id: u32) -> Result<(), i32> {
    let bytes = ipc_protocol::encode_request(opcode, request_id).ok_or(EPROTO)?;

    // SAFETY: `bytes` is alive for the duration of the call and exposes a
    // valid pointer/length pair. `fd` is an internal control-socket descriptor;
    // an invalid/closed descriptor is reported by the kernel as an error.
    let written = unsafe { send(fd, bytes.as_ptr(), bytes.len(), MSG_NOSIGNAL) };

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
    expected_request_id: u32,
    timeout_ms: i32,
) -> Result<(), i32> {
    let mut poll_fd = PollFd {
        fd,
        events: POLLIN,
        revents: 0,
    };

    // SAFETY: `poll_fd` is initialized and remains exclusively borrowed for
    // this call; `nfds` is exactly one, matching the single `PollFd` object.
    let poll_result = unsafe { poll(&mut poll_fd, 1, timeout_ms) };

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
    // SAFETY: `bytes` is a live writable buffer of exactly `bytes.len()`
    // bytes for the duration of `recv`; kernel errors are handled below.
    let received = unsafe { recv(fd, bytes.as_mut_ptr(), bytes.len(), MSG_TRUNC) };

    if received < 0 {
        return Err(last_errno());
    }

    if received as usize != PACKET_LEN {
        return Err(EPROTO);
    }

    let message = ipc_protocol::parse(&bytes).map_err(|_| EPROTO)?;

    if !ipc_protocol::matches_response(message, expected_opcode, expected_request_id) {
        return Err(EPROTO);
    }

    Ok(())
}

fn parent_force_terminate(state: &mut ExecutorState) {
    let pid = state.pid;
    let fd = state.control_fd;

    state.pid = 0;
    state.control_fd = -1;
    state.next_request_id = 1;

    if fd >= 0 {
        // SAFETY: `fd >= 0` is a descriptor value owned by this executor state.
        // `close` does not dereference userspace pointers; failures are ignored
        // here because this path is already force-cleanup.
        unsafe {
            let _ = close(fd);
        }
    }

    if pid > 0 {
        // SAFETY: `pid > 0` identifies the child process recorded in executor
        // state. Linux permits a null status pointer to `waitpid` when the exit
        // status is intentionally discarded.
        unsafe {
            let _ = kill(pid, SIGKILL);
            let _ = waitpid(pid, std::ptr::null_mut(), 0);
        }
    }
}

fn capture_fd_limit() -> Result<u32, i32> {
    let mut limit = RLimit {
        rlim_cur: 0,
        rlim_max: 0,
    };

    // SAFETY: `limit` is a valid, writable `#[repr(C)]` buffer matching the
    // 64-bit Linux/Android `struct rlimit` ABI used by supported targets.
    if unsafe { getrlimit(RLIMIT_NOFILE, &mut limit) } != 0 {
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
    let mut state = STATE.lock().map_err(|_| EIO)?;

    if state.running() {
        return Err(EBUSY);
    }

    let max_fd = capture_fd_limit()?;

    #[cfg(not(target_arch = "aarch64"))]
    let _ = max_fd;

    let mut pair = [-1_i32; 2];

    // SAFETY: `pair` points to storage for exactly two `i32` descriptors as
    // required by `socketpair`. Constants select an AF_UNIX SOCK_SEQPACKET pair.
    if unsafe { socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, pair.as_mut_ptr()) } != 0 {
        return Err(last_errno());
    }

    let parent_fd = pair[0];
    let child_fd = pair[1];

    // SAFETY: `fork` has no pointer arguments. The child branch below follows
    // the module's post-fork discipline and does not return to high-level code.
    let child_pid = unsafe { fork() };

    if child_pid < 0 {
        let errno = last_errno();

        // SAFETY: both descriptors were returned by the successful
        // `socketpair` call above and are still owned by this process.
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
        // SAFETY: this is the freshly forked child. `child_main` receives the
        // two socketpair descriptors and the pre-fork FD ceiling, then never
        // returns to the Rust/ART parent runtime.
        unsafe {
            child_main(parent_fd, child_fd, max_fd);
        }

        #[cfg(not(target_arch = "aarch64"))]
        // SAFETY: the non-AArch64 child is unsupported and must terminate
        // immediately without running destructors or high-level runtime code.
        unsafe {
            _exit(119);
        }
    }

    // SAFETY: only the parent reaches this point; its copy of `child_fd` came
    // from `socketpair` and is intentionally closed so only `parent_fd` remains.
    unsafe {
        let _ = close(child_fd);
    }

    state.pid = child_pid;
    state.control_fd = parent_fd;
    state.next_request_id = 1;

    if let Err(errno) = parent_recv(parent_fd, RESP_READY, 0, STARTUP_TIMEOUT_MS) {
        parent_force_terminate(&mut state);
        return Err(errno);
    }

    Ok(child_pid)
}

/// Sends PING to the already-running child.
pub fn ping() -> Result<i32, i32> {
    request_response(OP_PING, RESP_PONG)
}

/// Confirms that the child is alive behind its locked-down boundary.
pub fn status() -> Result<i32, i32> {
    request_response(OP_STATUS, RESP_LOCKED)
}

fn request_response(request_opcode: u8, response_opcode: u8) -> Result<i32, i32> {
    let mut state = STATE.lock().map_err(|_| EIO)?;

    if !state.running() {
        return Err(ENOENT);
    }

    let pid = state.pid;
    let fd = state.control_fd;
    let request_id = take_request_id(&mut state);

    if let Err(errno) = parent_send(fd, request_opcode, request_id) {
        parent_force_terminate(&mut state);
        return Err(errno);
    }

    if let Err(errno) = parent_recv(fd, response_opcode, request_id, STARTUP_TIMEOUT_MS) {
        parent_force_terminate(&mut state);
        return Err(errno);
    }

    Ok(pid)
}

/// Requests a clean shutdown and reaps the child.
pub fn shutdown() -> Result<(), i32> {
    let mut state = STATE.lock().map_err(|_| EIO)?;

    if !state.running() {
        return Err(ENOENT);
    }

    let pid = state.pid;
    let fd = state.control_fd;
    let request_id = take_request_id(&mut state);

    if let Err(errno) = parent_send(fd, OP_SHUTDOWN, request_id) {
        parent_force_terminate(&mut state);
        return Err(errno);
    }

    if let Err(errno) = parent_recv(fd, RESP_BYE, request_id, STARTUP_TIMEOUT_MS) {
        parent_force_terminate(&mut state);
        return Err(errno);
    }

    state.pid = 0;
    state.control_fd = -1;
    state.next_request_id = 1;

    // SAFETY: `fd` is the live control descriptor taken from executor state
    // and state ownership is cleared immediately before this close.
    unsafe {
        let _ = close(fd);
    }

    let mut wait_status = 0_i32;

    // SAFETY: `pid` is the recorded child PID and `wait_status` is a valid
    // writable `i32` for the Linux wait status returned by `waitpid`.
    let waited = unsafe { waitpid(pid, &mut wait_status, 0) };

    if waited < 0 {
        return Err(last_errno());
    }

    if wait_if_exited(wait_status) && wait_exit_status(wait_status) == 0 {
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

    // SAFETY: The caller of this unsafe syscall wrapper is responsible for
    // supplying a valid AArch64 Linux syscall number. The assembly only loads
    // x8, executes `svc #0`, and captures x0; it does not touch Rust memory.
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
unsafe fn svc1(number: i64, arg0: i64) -> i64 {
    let result: i64;

    // SAFETY: The caller is responsible for the syscall-specific validity of
    // every supplied argument. This wrapper only places the values in the
    // documented AArch64 syscall registers and captures the raw result.
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
unsafe fn svc3(number: i64, arg0: i64, arg1: i64, arg2: i64) -> i64 {
    let result: i64;

    // SAFETY: The caller is responsible for the syscall-specific validity of
    // every supplied argument. This wrapper only places the values in the
    // documented AArch64 syscall registers and captures the raw result.
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
unsafe fn svc4(number: i64, arg0: i64, arg1: i64, arg2: i64, arg3: i64) -> i64 {
    let result: i64;

    // SAFETY: The caller is responsible for the syscall-specific validity of
    // every supplied argument. This wrapper only places the values in the
    // documented AArch64 syscall registers and captures the raw result.
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
unsafe fn svc5(number: i64, arg0: i64, arg1: i64, arg2: i64, arg3: i64, arg4: i64) -> i64 {
    let result: i64;

    // SAFETY: The caller is responsible for the syscall-specific validity of
    // every supplied argument. This wrapper only places the values in the
    // documented AArch64 syscall registers and captures the raw result.
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

    // SAFETY: The caller is responsible for the syscall-specific validity of
    // every supplied argument. This wrapper only places the values in the
    // documented AArch64 syscall registers and captures the raw result.
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
    // SAFETY: `close(2)` consumes only the integer descriptor value and does
    // not dereference userspace memory. The caller controls descriptor ownership.
    unsafe {
        let _ = svc1(nr::CLOSE, fd as i64);
    }
}

#[cfg(target_arch = "aarch64")]
unsafe fn child_exit_now(code: i32) -> ! {
    // SAFETY: exit/exit_group take only an integer status. This post-fork child
    // intentionally terminates without unwinding or running Rust destructors.
    unsafe {
        let _ = svc1(nr::EXIT_GROUP, code.clamp(0, 255) as i64);

        let _ = svc1(nr::EXIT, code.clamp(0, 255) as i64);
    }

    loop {
        core::hint::spin_loop();
    }
}

#[cfg(target_arch = "aarch64")]
unsafe fn child_normalize_control_fd(parent_fd: i32, child_fd: i32) -> bool {
    // SAFETY: both descriptors originate from the pre-fork socketpair. The
    // child owns its descriptor table here and normalizes the sole retained
    // control capability to CONTROL_FD before any untrusted work begins.
    unsafe {
        child_close(parent_fd);

        if child_fd != CONTROL_FD {
            let duplicated = svc3(nr::DUP3, child_fd as i64, CONTROL_FD as i64, 0);

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
unsafe fn child_scrub_fds(max_fd: u32) -> bool {
    /*
     * Prefer close_range(4, UINT_MAX, 0). If Android's inherited policy or an
     * older kernel rejects it, fail over to explicit close().
     */
    // SAFETY: close_range receives only integer bounds/flags. Starting at fd 4
    // preserves the normalized control capability at fd 3 and removes all
    // higher inherited descriptors when the kernel supports close_range.
    let close_range_result = unsafe { svc3(nr::CLOSE_RANGE, 4, u32::MAX as i64, 0) };

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
        // SAFETY: fallback iteration covers only integer descriptor values in
        // the captured pre-fork range; closing an absent descriptor is harmless.
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

    // SAFETY: `all_signals` is a live 64-bit kernel sigset for the entire syscall;
    // the pointer and size passed to rt_sigprocmask match the AArch64 Linux ABI.
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
    // SAFETY: PR_SET_PDEATHSIG uses integer-only arguments and SIGKILL is a
    // valid Linux signal number. No userspace pointer is passed to the kernel.
    let result = unsafe { svc5(nr::PRCTL, PR_SET_PDEATHSIG, SIGKILL as i64, 0, 0, 0) };

    if result != 0 {
        return false;
    }

    /*
     * Race check if getppid is available. The inherited old PoC filter may
     * return -EPERM for getppid; that is acceptable for this temporary stage.
     */
    // SAFETY: getppid is a zero-argument syscall; this is only a post-prctl race check.
    let ppid = unsafe { svc0(nr::GETPPID) };

    ppid != 1
}

#[cfg(target_arch = "aarch64")]
unsafe fn child_enable_nnp() -> bool {
    // SAFETY: PR_SET_NO_NEW_PRIVS uses integer-only arguments; value 1 is the
    // documented operation and no userspace pointers are involved.
    let set_result = unsafe { svc5(nr::PRCTL, PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };

    if set_result != 0 {
        return false;
    }

    // SAFETY: PR_GET_NO_NEW_PRIVS is an integer-only query with zeroed unused arguments.
    let get_result = unsafe { svc5(nr::PRCTL, PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) };

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

    // SAFETY: `program` and the backing `filters` array remain alive for the
    // entire prctl call; SockFprog/SockFilter are C-layout and the filter length
    // exactly matches the initialized array. The policy itself is fixed above.
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
    // SAFETY: getpid is a zero-argument positive-control syscall intentionally
    // allowed by the just-installed seccomp filter.
    let allowed_getpid = unsafe { svc0(nr::GETPID) };

    // SAFETY: getuid is a zero-argument negative-control syscall intentionally
    // omitted from the allowlist; the raw -EPERM result verifies confinement.
    let blocked_getuid = unsafe { svc0(nr::GETUID) };

    allowed_getpid > 0 && blocked_getuid == -(EPERM as i64)
}

#[cfg(target_arch = "aarch64")]
unsafe fn child_send(opcode: u8, request_id: u32) -> bool {
    let bytes = match ipc_protocol::encode_response(opcode, request_id) {
        Some(bytes) => bytes,
        None => return false,
    };

    // SAFETY: `bytes` is a live PACKET_LEN-byte array for the full syscall and
    // CONTROL_FD is the normalized connected SOCK_SEQPACKET capability. sendto
    // receives no destination pointer because the socketpair is already connected.
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
unsafe fn child_recv(bytes: &mut [u8; PACKET_LEN]) -> i64 {
    // SAFETY: `bytes` is an exclusive writable PACKET_LEN-byte buffer for the
    // duration of recvfrom and CONTROL_FD is the normalized connected socket.
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
unsafe fn child_main(parent_fd: i32, child_fd: i32, max_fd: u32) -> ! {
    // SAFETY: descriptors are the two pre-fork socketpair ends and this is the
    // freshly forked child before any other descriptor mutation.
    if !unsafe { child_normalize_control_fd(parent_fd, child_fd) } {
        // SAFETY: fail-closed termination uses an integer exit status only.
        unsafe { child_exit_now(101) };
    }

    // SAFETY: max_fd was captured before fork and bounds the fallback scrub;
    // CONTROL_FD has already been normalized to fd 3.
    if !unsafe { child_scrub_fds(max_fd) } {
        // SAFETY: fail-closed termination uses an integer exit status only.
        unsafe { child_exit_now(102) };
    }

    // SAFETY: the helper constructs and passes its own valid kernel sigset.
    if !unsafe { child_block_catchable_signals() } {
        // SAFETY: fail-closed termination uses an integer exit status only.
        unsafe { child_exit_now(103) };
    }

    // SAFETY: the helper uses only integer prctl/getppid arguments in this child.
    if !unsafe { child_set_pdeathsig() } {
        // SAFETY: fail-closed termination uses an integer exit status only.
        unsafe { child_exit_now(104) };
    }

    // SAFETY: the helper performs the documented integer-only NNP prctl operations.
    if !unsafe { child_enable_nnp() } {
        // SAFETY: fail-closed termination uses an integer exit status only.
        unsafe { child_exit_now(105) };
    }

    // SAFETY: the helper owns a fully initialized fixed BPF program for the
    // duration of PR_SET_SECCOMP and is called only after NNP is verified.
    if !unsafe { child_install_strict_seccomp() } {
        // SAFETY: fail-closed termination uses an integer exit status only.
        unsafe { child_exit_now(106) };
    }

    // SAFETY: verification invokes only the zero-argument control syscalls
    // documented by the strict seccomp policy.
    if !unsafe { child_verify_boundary() } {
        // SAFETY: fail-closed termination uses an integer exit status only.
        unsafe { child_exit_now(107) };
    }

    // SAFETY: child_send owns its fixed response buffer and writes only to the
    // normalized connected CONTROL_FD. READY intentionally uses request_id 0.
    if !unsafe { child_send(RESP_READY, 0) } {
        // SAFETY: fail-closed termination uses an integer exit status only.
        unsafe { child_exit_now(108) };
    }

    loop {
        let mut bytes = [0_u8; PACKET_LEN];

        // SAFETY: `bytes` is an exclusive fixed-size stack buffer and child_recv
        // reads only from the normalized connected CONTROL_FD.
        let received = unsafe { child_recv(&mut bytes) };

        if received <= 0 {
            // SAFETY: the IPC channel is unusable, so the child terminates
            // immediately with an integer status and does not unwind.
            unsafe {
                child_exit_now(109);
            }
        }

        if received as usize != PACKET_LEN {
            // SAFETY: child_send owns its fixed encoded response and uses only CONTROL_FD.
            if !unsafe { child_send(RESP_ERROR, 0) } {
                // SAFETY: failure to report a malformed packet is fail-closed.
                unsafe {
                    child_exit_now(110);
                }
            }

            continue;
        }

        let request = match ipc_protocol::parse(&bytes) {
            Ok(message) if message.kind == MessageKind::Request => message,
            _ => {
                // SAFETY: child_send owns its fixed encoded response and uses only CONTROL_FD.
                if !unsafe { child_send(RESP_ERROR, 0) } {
                    // SAFETY: failure to report a rejected request is fail-closed.
                    unsafe {
                        child_exit_now(110);
                    }
                }

                continue;
            }
        };

        match request.opcode {
            OP_PING => {
                // SAFETY: request_id came from a successfully parsed v1 request and
                // child_send writes a fixed response only to CONTROL_FD.
                if !unsafe { child_send(RESP_PONG, request.request_id) } {
                    // SAFETY: IPC response failure terminates without unwinding.
                    unsafe {
                        child_exit_now(111);
                    }
                }
            }

            OP_STATUS => {
                // SAFETY: request_id came from a successfully parsed v1 request and
                // child_send writes a fixed response only to CONTROL_FD.
                if !unsafe { child_send(RESP_LOCKED, request.request_id) } {
                    // SAFETY: IPC response failure terminates without unwinding.
                    unsafe {
                        child_exit_now(112);
                    }
                }
            }

            OP_SHUTDOWN => {
                // SAFETY: request_id came from a valid shutdown request; the fixed BYE
                // response is best-effort on the normalized control socket.
                let _ = unsafe { child_send(RESP_BYE, request.request_id) };

                // SAFETY: CONTROL_FD is the sole retained capability in the locked child;
                // close followed by raw exit intentionally avoids destructors/unwinding.
                unsafe {
                    child_close(CONTROL_FD);
                    child_exit_now(0);
                }
            }

            _ => {
                // SAFETY: request_id came from a parsed request and child_send writes a
                // fixed response only to the normalized CONTROL_FD.
                if !unsafe { child_send(RESP_ERROR, request.request_id) } {
                    // SAFETY: failure to report an unsupported opcode is fail-closed.
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
                MAGIC_0,
                MAGIC_1,
                PROTOCOL_VERSION,
                ipc_protocol::KIND_REQUEST,
                OP_PING,
                0,
                0,
                0,
                1,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
            ],
        );
    }

    #[test]
    fn malformed_packet_is_rejected() {
        let mut malformed = packet(OP_STATUS);

        malformed[15] = 1;

        assert_eq!(packet_opcode(&malformed), None);
    }

    #[test]
    fn valid_packet_returns_opcode() {
        let bytes = packet(OP_SHUTDOWN);

        assert_eq!(packet_opcode(&bytes), Some(OP_SHUTDOWN));
    }

    #[test]
    fn request_id_wrap_skips_zero() {
        let mut state = ExecutorState {
            pid: 1,
            control_fd: 3,
            next_request_id: u32::MAX,
        };

        assert_eq!(take_request_id(&mut state), u32::MAX);
        assert_eq!(state.next_request_id, 1);
        assert_eq!(take_request_id(&mut state), 1);
        assert_eq!(state.next_request_id, 2);
    }

    #[test]
    fn mismatched_response_request_id_is_rejected_by_protocol_state() {
        let bytes = ipc_protocol::encode_response(RESP_PONG, 9).expect("valid response");
        let message = ipc_protocol::parse(&bytes).expect("parse response");

        assert_eq!(message.kind, MessageKind::Response);
        assert_eq!(message.opcode, RESP_PONG);
        assert!(!ipc_protocol::matches_response(message, RESP_PONG, 8));
        assert!(ipc_protocol::matches_response(message, RESP_PONG, 9));
    }
}

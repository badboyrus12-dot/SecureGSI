mod duress;
mod guest;
mod image;
mod persistent_executor;

use jni::JNIEnv;
use jni::objects::{JClass, JString};
use jni::sys::jstring;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/*
 * Minimal Linux/Android ABI shim.
 *
 * We intentionally do not reference Linux-only APIs through the Rust `libc`
 * crate here. Android Studio/rust-analyzer may analyze the crate with a
 * Windows host target and then incorrectly report Linux-only libc symbols as
 * missing.
 *
 * The real Android build still links these standard bionic C ABI symbols.
 */
mod os {
    use core::ffi::{c_int, c_long};

    pub type Pid = i32;

    pub const EPERM: i32 = 1;
    pub const EIO: i32 = 5;

    unsafe extern "C" {
        fn dup(oldfd: c_int) -> c_int;
        fn prctl(option: c_int, ...) -> c_int;
        fn fork() -> Pid;
        fn waitpid(pid: Pid, status: *mut c_int, options: c_int) -> Pid;
        fn syscall(number: c_long, ...) -> c_long;
        fn _exit(status: c_int) -> !;
    }

    pub unsafe fn dup_fd(fd: i32) -> i32 {
        // SAFETY: The caller is responsible for supplying a valid descriptor.
        // dup does not dereference Rust memory and returns a new descriptor or -1.
        unsafe { dup(fd) }
    }

    pub unsafe fn prctl5(option: i32, arg2: usize, arg3: usize, arg4: usize, arg5: usize) -> i32 {
        // SAFETY: This wrapper preserves the raw prctl ABI. Callers must ensure
        // that option-specific integer or pointer arguments are valid.
        unsafe { prctl(option, arg2, arg3, arg4, arg5) }
    }

    pub unsafe fn fork_process() -> Pid {
        // SAFETY: fork has no pointer arguments. The caller must obey the
        // post-fork restrictions required by the surrounding runtime.
        unsafe { fork() }
    }

    pub unsafe fn wait_process(pid: Pid, status: *mut i32) -> Pid {
        // SAFETY: The caller must provide either a valid writable status pointer
        // or a null pointer and a PID that may legally be waited for.
        unsafe { waitpid(pid, status, 0) }
    }

    pub unsafe fn syscall0(number: i64) -> i64 {
        // SAFETY: This wrapper is used only for zero-argument syscall numbers;
        // no Rust pointers are passed through the variadic syscall ABI.
        unsafe { syscall(number as c_long) as i64 }
    }

    pub unsafe fn exit_now(code: i32) -> ! {
        // SAFETY: _exit terminates the current process immediately and does not
        // return into Rust; the integer exit status requires no pointer validity.
        unsafe { _exit(code) }
    }

    pub fn wait_if_exited(status: i32) -> bool {
        (status & 0x7f) == 0
    }

    pub fn wait_exit_status(status: i32) -> i32 {
        (status >> 8) & 0xff
    }

    pub fn wait_if_signaled(status: i32) -> bool {
        let signal = status & 0x7f;
        signal != 0 && signal != 0x7f
    }

    pub fn wait_term_signal(status: i32) -> i32 {
        status & 0x7f
    }
}

#[cfg(target_arch = "aarch64")]
const SYS_GETPID: i64 = 172;
#[cfg(target_arch = "aarch64")]
const SYS_GETPPID: i64 = 173;

#[cfg(target_arch = "x86_64")]
const SYS_GETPID: i64 = 39;
#[cfg(target_arch = "x86_64")]
const SYS_GETPPID: i64 = 110;

#[cfg(target_arch = "arm")]
const SYS_GETPID: i64 = 20;
#[cfg(target_arch = "arm")]
const SYS_GETPPID: i64 = 64;

#[cfg(target_arch = "x86")]
const SYS_GETPID: i64 = 20;
#[cfg(target_arch = "x86")]
const SYS_GETPPID: i64 = 64;

#[cfg(not(any(
    target_arch = "aarch64",
    target_arch = "x86_64",
    target_arch = "arm",
    target_arch = "x86"
)))]
const SYS_GETPID: i64 = -1;

#[cfg(not(any(
    target_arch = "aarch64",
    target_arch = "x86_64",
    target_arch = "arm",
    target_arch = "x86"
)))]
const SYS_GETPPID: i64 = -1;

const PR_SET_NO_NEW_PRIVS: i32 = 38;
const PR_GET_NO_NEW_PRIVS: i32 = 39;
const PR_SET_SECCOMP: i32 = 22;
const SECCOMP_MODE_FILTER: usize = 2;

const BPF_LD_W_ABS: u16 = 0x20;
const BPF_JMP_JEQ_K: u16 = 0x15;
const BPF_RET_K: u16 = 0x06;

const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;

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

pub fn sha256(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);

    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn last_errno() -> i32 {
    std::io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(os::EIO)
}

fn errno_text(errno: i32) -> String {
    std::io::Error::from_raw_os_error(errno).to_string()
}

fn to_jstring(env: &JNIEnv, value: &str) -> jstring {
    match env.new_string(value) {
        Ok(string) => string.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

fn child_exit(code: i32) -> ! {
    // SAFETY: exit_now is called with a clamped process exit code and never
    // returns, which is exactly the required behavior in the forked child.
    unsafe {
        os::exit_now(code.clamp(0, 255));
    }
}

fn install_getppid_probe_seccomp() -> Result<(), i32> {
    if SYS_GETPPID < 0 {
        return Err(os::EIO);
    }

    let filters = [
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
            k: SYS_GETPPID as u32,
        },
        SockFilter {
            code: BPF_RET_K,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_ERRNO | os::EPERM as u32,
        },
        SockFilter {
            code: BPF_RET_K,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_ALLOW,
        },
    ];

    let program = SockFprog {
        len: filters.len() as u16,
        filter: filters.as_ptr(),
    };

    // SAFETY: program points to a live SockFprog whose filter slice remains
    // allocated for the entire prctl call; the kernel only reads it synchronously.
    let result = unsafe {
        os::prctl5(
            PR_SET_SECCOMP,
            SECCOMP_MODE_FILTER,
            (&program as *const SockFprog) as usize,
            0,
            0,
        )
    };

    if result != 0 {
        return Err(last_errno());
    }

    Ok(())
}

fn no_new_privs_report() -> String {
    // SAFETY: PR_SET_NO_NEW_PRIVS uses integer arguments only; no pointers are
    // passed and the result is checked immediately.
    let set_result = unsafe { os::prctl5(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };

    if set_result != 0 {
        let errno = last_errno();

        return format!(
            "PR_SET_NO_NEW_PRIVS: FAILED\nerrno {errno}: {}",
            errno_text(errno)
        );
    }

    // SAFETY: PR_GET_NO_NEW_PRIVS uses integer arguments only; no pointers are
    // passed and the return value is validated below.
    let get_result = unsafe { os::prctl5(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) };

    if get_result == 1 {
        return String::from("PR_SET_NO_NEW_PRIVS: OK\nPR_GET_NO_NEW_PRIVS: 1");
    }

    if get_result < 0 {
        let errno = last_errno();

        return format!(
            "PR_SET_NO_NEW_PRIVS: OK\n\
             PR_GET_NO_NEW_PRIVS: FAILED\n\
             errno {errno}: {}",
            errno_text(errno)
        );
    }

    format!(
        "PR_SET_NO_NEW_PRIVS: OK\n\
         PR_GET_NO_NEW_PRIVS: UNEXPECTED ({get_result})"
    )
}

fn start_guest_report() -> String {
    match guest::start_guest() {
        Ok(pid) => format!("SecureGSI Guest Runtime\nPID: {pid}\nStatus: RUNNING"),
        Err(errno) => format!("Guest process failed\nerrno {errno}: {}", errno_text(errno)),
    }
}

fn stop_guest_report() -> String {
    match guest::stop_guest() {
        Ok(()) => String::from("SecureGSI Guest Runtime\nStatus: STOPPED"),
        Err(errno) => format!("Failed to stop guest\nerrno {errno}: {}", errno_text(errno)),
    }
}

fn guest_status_report() -> String {
    match guest::guest_pid() {
        Some(pid) => format!("SecureGSI Guest Runtime\nPID: {pid}\nStatus: RUNNING"),
        None => String::from("SecureGSI Guest Runtime\nStatus: STOPPED"),
    }
}

fn seccomp_install_report() -> String {
    match install_getppid_probe_seccomp() {
        Ok(()) => String::from(
            "STACKED_SECCOMP: INSTALLED\n\
             blocked syscall: getppid -> EPERM",
        ),
        Err(errno) => format!(
            "STACKED_SECCOMP: FAILED\nerrno {errno}: {}",
            errno_text(errno)
        ),
    }
}

fn seccomp_runtime_report() -> String {
    // SAFETY: SYS_GETPID is a zero-argument syscall on the supported targets.
    let getpid_result = unsafe { os::syscall0(SYS_GETPID) };

    // SAFETY: SYS_GETPPID is a zero-argument syscall on the supported targets.
    let getppid_result = unsafe { os::syscall0(SYS_GETPPID) };

    if getppid_result != -1 {
        return format!(
            "SECCOMP_TEST: FAILED\n\
             getpid result: {getpid_result}\n\
             getppid unexpectedly succeeded: {getppid_result}"
        );
    }

    let errno = last_errno();

    if getpid_result > 0 && errno == os::EPERM {
        return format!(
            "SECCOMP_TEST: PASSED\n\
             getpid: ALLOWED ({getpid_result})\n\
             getppid: BLOCKED\n\
             result: {getppid_result}\n\
             errno: {errno} ({})",
            errno_text(errno)
        );
    }

    format!(
        "SECCOMP_TEST: FAILED\n\
         getpid result: {getpid_result}\n\
         getppid result: {getppid_result}\n\
         errno: {errno} ({})",
        errno_text(errno)
    )
}

#[cfg(target_arch = "aarch64")]
fn direct_svc_syscall0(syscall_number: i64) -> i64 {
    let result: i64;

    // SAFETY: The inline assembly performs a zero-argument Linux syscall using
    // the documented AArch64 syscall ABI. It does not access Rust memory or stack.
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") syscall_number,
            lateout("x0") result,
            options(nostack),
        );
    }

    result
}

#[cfg(target_arch = "aarch64")]
fn direct_svc_report() -> String {
    let direct_getpid = direct_svc_syscall0(SYS_GETPID);

    let direct_getppid = direct_svc_syscall0(SYS_GETPPID);

    let expected_block = -(os::EPERM as i64);

    if direct_getpid > 0 && direct_getppid == expected_block {
        return format!(
            "DIRECT_SVC_TEST: PASSED\n\
             getpid via svc #0: ALLOWED ({direct_getpid})\n\
             getppid via svc #0: BLOCKED\n\
             raw result: {direct_getppid}\n\
             expected: {expected_block} (-EPERM)"
        );
    }

    return format!(
        "DIRECT_SVC_TEST: FAILED\n\
         getpid via svc #0: {direct_getpid}\n\
         getppid via svc #0: {direct_getppid}\n\
         expected getppid: {expected_block} (-EPERM)"
    );
}

#[cfg(not(target_arch = "aarch64"))]
fn direct_svc_report() -> String {
    String::from("DIRECT_SVC_TEST: UNSUPPORTED\nrequires ARM64/aarch64 target")
}

fn isolated_executor_proof_child() -> ! {
    // SAFETY: PR_SET_NO_NEW_PRIVS has integer-only arguments and is executed in
    // the dedicated proof child before hostile code.
    let set_nnp = unsafe { os::prctl5(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };

    if set_nnp != 0 {
        child_exit(101);
    }

    // SAFETY: PR_GET_NO_NEW_PRIVS has integer-only arguments; the result must be
    // exactly 1 or the proof child exits.
    let get_nnp = unsafe { os::prctl5(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) };

    if get_nnp != 1 {
        child_exit(102);
    }

    if install_getppid_probe_seccomp().is_err() {
        child_exit(103);
    }

    #[cfg(target_arch = "aarch64")]
    {
        let direct_getpid = direct_svc_syscall0(SYS_GETPID);

        let direct_getppid = direct_svc_syscall0(SYS_GETPPID);

        if direct_getpid <= 0 {
            child_exit(104);
        }

        if direct_getppid != -(os::EPERM as i64) {
            child_exit(105);
        }

        child_exit(0);
    }

    #[cfg(not(target_arch = "aarch64"))]
    {
        child_exit(106);
    }
}

fn isolated_executor_parent_report(child_pid: os::Pid) -> String {
    let mut status = 0_i32;

    // SAFETY: status is a valid writable i32 for the duration of waitpid and
    // child_pid is the PID returned by our successful fork.
    let wait_result = unsafe { os::wait_process(child_pid, &mut status) };

    if wait_result < 0 {
        let errno = last_errno();

        return format!(
            "ISOLATED_EXECUTOR_PROOF: WAIT_FAILED\n\
             child_pid: {child_pid}\n\
             errno: {errno} ({})",
            errno_text(errno)
        );
    }

    if os::wait_if_signaled(status) {
        let signal = os::wait_term_signal(status);

        return format!(
            "ISOLATED_EXECUTOR_PROOF: FAILED\n\
             child terminated by signal: {signal}"
        );
    }

    if !os::wait_if_exited(status) {
        return String::from("ISOLATED_EXECUTOR_PROOF: FAILED\nunknown child state");
    }

    let code = os::wait_exit_status(status);

    match code {
        0 => format!(
            "ISOLATED_EXECUTOR_PROOF: PASSED\n\
             child_pid: {child_pid}\n\
             NoNewPrivs: VERIFIED\n\
             seccomp: INSTALLED\n\
             direct ARM64 svc #0: BLOCKED AS EXPECTED"
        ),
        101 => String::from(
            "ISOLATED_EXECUTOR_PROOF: FAILED\n\
             PR_SET_NO_NEW_PRIVS failed",
        ),
        102 => String::from(
            "ISOLATED_EXECUTOR_PROOF: FAILED\n\
             PR_GET_NO_NEW_PRIVS verification failed",
        ),
        103 => String::from(
            "ISOLATED_EXECUTOR_PROOF: FAILED\n\
             seccomp installation failed",
        ),
        104 => String::from(
            "ISOLATED_EXECUTOR_PROOF: FAILED\n\
             direct getpid syscall failed",
        ),
        105 => String::from(
            "ISOLATED_EXECUTOR_PROOF: FAILED\n\
             direct getppid bypassed seccomp",
        ),
        106 => String::from(
            "ISOLATED_EXECUTOR_PROOF: FAILED\n\
             not running on ARM64",
        ),
        other => format!(
            "ISOLATED_EXECUTOR_PROOF: FAILED\n\
             unexpected child exit code: {other}"
        ),
    }
}

fn isolated_executor_proof_report() -> String {
    // SAFETY: fork has no pointer arguments. The child immediately enters the
    // restricted proof path and does not return to the JNI caller.
    let child_pid = unsafe { os::fork_process() };

    if child_pid < 0 {
        let errno = last_errno();

        return format!(
            "ISOLATED_EXECUTOR_PROOF: FORK_FAILED\n\
             errno: {errno} ({})",
            errno_text(errno)
        );
    }

    if child_pid == 0 {
        /*
         * This never returns.
         * No JNI / String construction occurs after entering the child proof.
         */
        isolated_executor_proof_child();
    }

    isolated_executor_parent_report(child_pid)
}

fn start_persistent_executor_report() -> String {
    match persistent_executor::start() {
        Ok(pid) => format!(
            "PERSISTENT_EXECUTOR_START: OK\n\
             PID: {pid}\n\
             State: LOCKED"
        ),
        Err(errno) => format!(
            "PERSISTENT_EXECUTOR_START: FAILED\n\
             errno {errno}: {}",
            errno_text(errno)
        ),
    }
}

fn ping_persistent_executor_report() -> String {
    match persistent_executor::ping() {
        Ok(pid) => format!(
            "PERSISTENT_EXECUTOR_PING: PONG\n\
             PID: {pid}"
        ),
        Err(errno) => format!(
            "PERSISTENT_EXECUTOR_PING: FAILED\n\
             errno {errno}: {}",
            errno_text(errno)
        ),
    }
}

fn persistent_executor_status_report() -> String {
    match persistent_executor::status() {
        Ok(pid) => format!(
            "PERSISTENT_EXECUTOR_STATUS: LOCKED\n\
             PID: {pid}"
        ),
        Err(errno) => format!(
            "PERSISTENT_EXECUTOR_STATUS: NOT_RUNNING_OR_FAILED\n\
             errno {errno}: {}",
            errno_text(errno)
        ),
    }
}

fn shutdown_persistent_executor_report() -> String {
    match persistent_executor::shutdown() {
        Ok(()) => String::from("PERSISTENT_EXECUTOR_SHUTDOWN: OK\nState: STOPPED"),
        Err(errno) => format!(
            "PERSISTENT_EXECUTOR_SHUTDOWN: FAILED\n\
             errno {errno}: {}",
            errno_text(errno)
        ),
    }
}

fn configure_duress_report(files_dir: &str, pin: &str) -> String {
    let root = std::path::Path::new(files_dir);

    match duress::configure(root, pin.as_bytes()) {
        Ok(()) => String::from("DURESS_CONFIGURED"),
        Err(error) => format!("DURESS_CONFIG_FAILED\n{error}"),
    }
}

fn duress_status_report(files_dir: &str) -> String {
    let root = std::path::Path::new(files_dir);

    if duress::configured(root) {
        String::from("DURESS_CONFIGURED")
    } else {
        String::from("DURESS_NOT_CONFIGURED")
    }
}

fn check_duress_and_wipe_report(files_dir: &str, pin: &str) -> String {
    let root = std::path::Path::new(files_dir);

    let matched = match duress::matches(root, pin.as_bytes()) {
        Ok(value) => value,
        Err(error) => return format!("DURESS_CHECK_FAILED\n{error}"),
    };

    if !matched {
        return String::from("NO_MATCH");
    }

    // Stop the guest before touching its filesystem.
    if let Err(errno) = guest::stop_guest() {
        return format!("DURESS_STOP_FAILED\nerrno {errno}: {}", errno_text(errno));
    }

    match duress::wipe_instances(root) {
        Ok(()) => String::from("DURESS_TRIGGERED"),
        Err(error) => format!("DURESS_WIPE_FAILED\n{error}"),
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_securegsi_RustBridge_sha256Fd(
    env: JNIEnv,
    _class: JClass,
    fd: i32,
) -> jstring {
    // SAFETY: fd is supplied by the JNI caller; dup validates it in the kernel
    // and returns either an independently owned descriptor or -1.
    let duplicated_fd = unsafe { os::dup_fd(fd) };

    if duplicated_fd < 0 {
        return std::ptr::null_mut();
    }

    // SAFETY: duplicated_fd is a fresh descriptor owned by this function and
    // ownership is intentionally transferred to sha256_fd.
    let hash = match unsafe { image::sha256_fd(duplicated_fd) } {
        Ok(hash) => hash,
        Err(_) => return std::ptr::null_mut(),
    };

    to_jstring(&env, &hash)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_securegsi_RustBridge_readHeader(
    env: JNIEnv,
    _class: JClass,
    fd: i32,
) -> jstring {
    // SAFETY: fd is supplied by the JNI caller; dup validates it in the kernel
    // and returns either an independently owned descriptor or -1.
    let duplicated_fd = unsafe { os::dup_fd(fd) };

    if duplicated_fd < 0 {
        return std::ptr::null_mut();
    }

    // SAFETY: duplicated_fd is a fresh descriptor owned by this function and
    // ownership is intentionally transferred to read_header_fd.
    let header = match unsafe { image::read_header_fd(duplicated_fd, 64) } {
        Ok(header) => header,
        Err(_) => return std::ptr::null_mut(),
    };

    let hex = header
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();

    to_jstring(&env, &hex)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_securegsi_RustBridge_enableNoNewPrivsNative(
    env: JNIEnv,
    _class: JClass,
) -> jstring {
    let report = no_new_privs_report();

    to_jstring(&env, &report)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_securegsi_RustBridge_testContainerRuntimeNative(
    env: JNIEnv,
    _class: JClass,
) -> jstring {
    /*
     * Kept only for Kotlin/JNI compatibility.
     *
     * Namespace probing is deprecated because the current architecture does
     * not depend on Linux user/mount/PID namespaces.
     */
    const REPORT: &str = "SecureGSI Container Backend\n\
         ===========================\n\
         Legacy namespace probe: DEPRECATED\n\
         Current backend: isolatedProcess + Guest Executor + seccomp\n\
         Namespace support is not required by the current architecture.";

    to_jstring(&env, REPORT)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_securegsi_RustBridge_startGuestProbeNative(
    env: JNIEnv,
    _class: JClass,
) -> jstring {
    let report = start_guest_report();

    to_jstring(&env, &report)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_securegsi_RustBridge_stopGuestNative(
    env: JNIEnv,
    _class: JClass,
) -> jstring {
    let report = stop_guest_report();

    to_jstring(&env, &report)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_securegsi_RustBridge_guestStatusNative(
    env: JNIEnv,
    _class: JClass,
) -> jstring {
    let report = guest_status_report();

    to_jstring(&env, &report)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_securegsi_RustBridge_installMinimalSeccompNative(
    env: JNIEnv,
    _class: JClass,
) -> jstring {
    let report = seccomp_install_report();

    to_jstring(&env, &report)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_securegsi_RustBridge_testMinimalSeccompNative(
    env: JNIEnv,
    _class: JClass,
) -> jstring {
    let report = seccomp_runtime_report();

    to_jstring(&env, &report)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_securegsi_RustBridge_testDirectSvcSeccompNative(
    env: JNIEnv,
    _class: JClass,
) -> jstring {
    let report = direct_svc_report();

    to_jstring(&env, &report)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_securegsi_RustBridge_runIsolatedExecutorProofNative(
    env: JNIEnv,
    _class: JClass,
) -> jstring {
    let report = isolated_executor_proof_report();

    to_jstring(&env, &report)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_securegsi_RustBridge_startPersistentExecutorNative(
    env: JNIEnv,
    _class: JClass,
) -> jstring {
    let report = start_persistent_executor_report();

    to_jstring(&env, &report)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_securegsi_RustBridge_pingPersistentExecutorNative(
    env: JNIEnv,
    _class: JClass,
) -> jstring {
    let report = ping_persistent_executor_report();

    to_jstring(&env, &report)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_securegsi_RustBridge_persistentExecutorStatusNative(
    env: JNIEnv,
    _class: JClass,
) -> jstring {
    let report = persistent_executor_status_report();

    to_jstring(&env, &report)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_securegsi_RustBridge_shutdownPersistentExecutorNative(
    env: JNIEnv,
    _class: JClass,
) -> jstring {
    let report = shutdown_persistent_executor_report();

    to_jstring(&env, &report)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_securegsi_RustBridge_configureDuressNative(
    mut env: JNIEnv,
    _class: JClass,
    files_dir: JString,
    pin: JString,
) -> jstring {
    let files_dir: String = match env.get_string(&files_dir) {
        Ok(value) => value.into(),
        Err(_) => {
            return to_jstring(&env, "DURESS_CONFIG_FAILED\ninvalid filesDir");
        }
    };

    let pin: String = match env.get_string(&pin) {
        Ok(value) => value.into(),
        Err(_) => {
            return to_jstring(&env, "DURESS_CONFIG_FAILED\ninvalid PIN");
        }
    };

    let pin = Zeroizing::new(pin);
    let report = configure_duress_report(&files_dir, pin.as_str());

    to_jstring(&env, &report)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_securegsi_RustBridge_duressStatusNative(
    mut env: JNIEnv,
    _class: JClass,
    files_dir: JString,
) -> jstring {
    let files_dir: String = match env.get_string(&files_dir) {
        Ok(value) => value.into(),
        Err(_) => return to_jstring(&env, "DURESS_STATUS_FAILED"),
    };

    let report = duress_status_report(&files_dir);
    to_jstring(&env, &report)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_securegsi_RustBridge_checkDuressAndWipeNative(
    mut env: JNIEnv,
    _class: JClass,
    files_dir: JString,
    pin: JString,
) -> jstring {
    let files_dir: String = match env.get_string(&files_dir) {
        Ok(value) => value.into(),
        Err(_) => {
            return to_jstring(&env, "DURESS_CHECK_FAILED\ninvalid filesDir");
        }
    };

    let pin: String = match env.get_string(&pin) {
        Ok(value) => value.into(),
        Err(_) => {
            return to_jstring(&env, "DURESS_CHECK_FAILED\ninvalid PIN");
        }
    };

    let pin = Zeroizing::new(pin);
    let report = check_duress_and_wipe_report(&files_dir, pin.as_str());

    to_jstring(&env, &report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_works() {
        let hash = sha256(b"hello");

        assert_eq!(
            hash,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn rust_ready_works() {
        assert_eq!(2 + 2, 4);
    }

    #[test]
    fn wait_status_helpers_work() {
        assert!(os::wait_if_exited(0));

        assert_eq!(os::wait_exit_status(0), 0);

        let exit_7 = 7 << 8;

        assert!(os::wait_if_exited(exit_7,));

        assert_eq!(os::wait_exit_status(exit_7,), 7);

        let sig_9 = 9;

        assert!(os::wait_if_signaled(sig_9,));

        assert_eq!(os::wait_term_signal(sig_9,), 9);
    }
}

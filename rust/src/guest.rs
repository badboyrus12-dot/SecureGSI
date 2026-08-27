//! Android/Linux guest runtime.
//!
//! The real implementation is compiled on Android and Linux.
//! Linux is intentionally included so WSL/CI `cargo check` still validates
//! the syscall/seccomp/fork code. On non-Unix host analyzers (notably Windows
//! rust-analyzer), small stubs are exposed instead; this prevents platform-
//! specific `libc` symbols such as `fork`, `prctl`, `waitpid`, and `SYS_*`
//! from being resolved against the Windows libc surface.

#[cfg(any(target_os = "android", target_os = "linux"))]
mod platform_impl {
    #[cfg(target_os = "android")]
    use std::ffi::CString;
    use std::fs;
    use std::io;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicI32, Ordering};

    static GUEST_PID: AtomicI32 = AtomicI32::new(0);

    #[cfg(target_os = "android")]
    const LOG_TAG: &str = "SecureGSI-Runtime";
    const ANDROID_LOG_INFO: i32 = 4;
    const ANDROID_LOG_WARN: i32 = 5;
    const ANDROID_LOG_ERROR: i32 = 6;

    const PR_SET_PDEATHSIG: libc::c_int = 1;

    #[cfg(target_os = "android")]
    #[link(name = "log")]
    unsafe extern "C" {
        fn __android_log_write(
            prio: i32,
            tag: *const libc::c_char,
            text: *const libc::c_char,
        ) -> i32;
    }

    fn log(priority: i32, message: &str) {
        #[cfg(target_os = "android")]
        {
            let tag = match CString::new(LOG_TAG) {
                Ok(value) => value,
                Err(_) => return,
            };

            let message = match CString::new(message) {
                Ok(value) => value,
                Err(_) => return,
            };

            // SAFETY: tag and message are live CStrings, so both pointers are
            // NUL-terminated and valid for the duration of the synchronous log call.
            unsafe {
                __android_log_write(priority, tag.as_ptr(), message.as_ptr());
            }
        }

        #[cfg(not(target_os = "android"))]
        {
            let _ = priority;
            eprintln!("{message}");
        }
    }

    fn log_info(message: &str) {
        log(ANDROID_LOG_INFO, message);
    }

    fn log_warn(message: &str) {
        log(ANDROID_LOG_WARN, message);
    }

    fn log_error(message: &str) {
        log(ANDROID_LOG_ERROR, message);
    }

    fn last_errno() -> i32 {
        io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO)
    }

    /// Enables and verifies PR_SET_NO_NEW_PRIVS for the current executor task.
    ///
    /// This is deliberately done inside the forked payload child, not in the
    /// supervisor, so the supervisor remains outside the guest lockdown boundary.
    fn enable_executor_no_new_privs() -> Result<(), i32> {
        const PR_SET_NO_NEW_PRIVS: libc::c_int = 38;
        const PR_GET_NO_NEW_PRIVS: libc::c_int = 39;

        // SAFETY: PR_SET_NO_NEW_PRIVS takes integer arguments only and the return
        // value is checked before the executor proceeds.
        let set_result = unsafe { libc::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };

        if set_result != 0 {
            return Err(last_errno());
        }

        // SAFETY: PR_GET_NO_NEW_PRIVS takes integer arguments only; the returned
        // state is validated immediately below.
        let get_result = unsafe { libc::prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) };

        if get_result == 1 {
            Ok(())
        } else if get_result < 0 {
            Err(last_errno())
        } else {
            Err(libc::EPERM)
        }
    }

    /// Installs the first Guest Executor seccomp probe policy.
    ///
    /// IMPORTANT:
    /// This is still a PoC policy, NOT the final Android guest allowlist.
    ///
    /// Current policy:
    ///   getppid() -> EPERM
    ///   everything else -> ALLOW
    ///
    /// The purpose of this stage is to prove that the actual forked payload
    /// executes under a kernel-enforced seccomp boundary before we start moving
    /// Android guest execution into it.
    fn install_executor_probe_seccomp() -> Result<(), i32> {
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

        const PR_SET_SECCOMP: libc::c_int = 22;
        const SECCOMP_MODE_FILTER: libc::c_ulong = 2;

        const BPF_LD_W_ABS: u16 = 0x20;
        const BPF_JMP_JEQ_K: u16 = 0x15;
        const BPF_RET_K: u16 = 0x06;

        const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
        const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;

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
                k: libc::SYS_getppid as u32,
            },
            SockFilter {
                code: BPF_RET_K,
                jt: 0,
                jf: 0,
                k: SECCOMP_RET_ERRNO | libc::EPERM as u32,
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

        // SAFETY: program and its filter slice remain alive for the entire
        // synchronous prctl call, and the kernel only reads the supplied program.
        let result = unsafe {
            libc::prctl(
                PR_SET_SECCOMP,
                SECCOMP_MODE_FILTER,
                &program as *const SockFprog,
                0,
                0,
            )
        };

        if result == 0 {
            Ok(())
        } else {
            Err(last_errno())
        }
    }

    /// Issues a zero-argument Linux syscall directly using ARM64 `svc #0`.
    ///
    /// This bypasses libc completely. Linux raw syscall errors are returned as
    /// negative errno values in x0.
    #[cfg(target_arch = "aarch64")]
    fn direct_svc_syscall0(syscall_number: i64) -> i64 {
        let result: i64;

        // SAFETY: This issues a zero-argument syscall using the AArch64 Linux ABI;
        // it declares the used registers and does not access Rust memory or the stack.
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

    /// Proves that the forked Guest Executor payload is actually executing behind
    /// the seccomp filter, including against a direct ARM64 syscall attempt.
    #[cfg(target_arch = "aarch64")]
    fn verify_executor_seccomp_boundary() -> Result<(i64, i64), i32> {
        let getpid_result = direct_svc_syscall0(libc::SYS_getpid as i64);
        let getppid_result = direct_svc_syscall0(libc::SYS_getppid as i64);
        let expected_block = -(libc::EPERM as i64);

        if getpid_result > 0 && getppid_result == expected_block {
            Ok((getpid_result, getppid_result))
        } else {
            Err(libc::EPERM)
        }
    }

    #[cfg(not(target_arch = "aarch64"))]
    fn verify_executor_seccomp_boundary() -> Result<(i64, i64), i32> {
        Err(libc::ENOTSUP)
    }

    fn guest_root() -> PathBuf {
        PathBuf::from("/data/data/com.securegsi/files/instances/default")
    }

    fn runtime_dir(root: &Path) -> PathBuf {
        root.join("runtime")
    }

    fn ensure_dir(path: &Path) -> Result<(), i32> {
        fs::create_dir_all(path).map_err(|error| error.raw_os_error().unwrap_or(libc::EIO))
    }

    fn write_text(path: &Path, value: &str) -> Result<(), i32> {
        fs::write(path, value).map_err(|error| error.raw_os_error().unwrap_or(libc::EIO))
    }

    fn prepare_guest_filesystem() -> Result<PathBuf, i32> {
        let root = guest_root();

        log_info(&format!(
            "prepare_guest_filesystem(): root={}",
            root.display()
        ));

        ensure_dir(&root)?;

        for name in ["system", "data", "cache", "tmp", "runtime"] {
            let path = root.join(name);

            ensure_dir(&path)?;

            log_info(&format!(
                "prepare_guest_filesystem(): ensured {}",
                path.display()
            ));
        }

        let runtime = runtime_dir(&root);

        write_text(&runtime.join("status"), "STOPPED\n")?;

        for name in [
            "pid",
            "payload_pid",
            "payload_status",
            "heartbeat",
            "bootstrap_pid",
            "bootstrap_status",
            "bootstrap_heartbeat",
        ] {
            let _ = fs::remove_file(runtime.join(name));
        }

        log_info("prepare_guest_filesystem(): status=STOPPED");

        Ok(root)
    }

    fn write_supervisor_pid(root: &Path, pid: i32) -> Result<(), i32> {
        write_text(&runtime_dir(root).join("pid"), &format!("{pid}\n"))
    }

    fn write_payload_pid(root: &Path, pid: i32) -> Result<(), i32> {
        write_text(&runtime_dir(root).join("payload_pid"), &format!("{pid}\n"))
    }

    fn write_status(root: &Path, status: &str) -> Result<(), i32> {
        write_text(&runtime_dir(root).join("status"), &format!("{status}\n"))
    }

    fn write_payload_status(root: &Path, status: &str) -> Result<(), i32> {
        write_text(
            &runtime_dir(root).join("payload_status"),
            &format!("{status}\n"),
        )
    }

    fn clear_runtime_pids(root: &Path) {
        for name in ["pid", "payload_pid", "bootstrap_pid"] {
            if let Err(error) = fs::remove_file(runtime_dir(root).join(name))
                && error.kind() != io::ErrorKind::NotFound
            {
                log_warn(&format!(
                    "clear_runtime_pids(): failed to remove {name}: {error}"
                ));
            }
        }
    }

    fn process_alive(pid: i32) -> bool {
        if pid <= 0 {
            return false;
        }

        // SAFETY: kill(pid, 0) sends no signal and dereferences no pointers; pid
        // is range-checked above and errno is interpreted below.
        let result = unsafe { libc::kill(pid, 0) };

        if result == 0 {
            return true;
        }

        last_errno() == libc::EPERM
    }

    fn run_native_bootstrap(root: &Path) -> ! {
        // SAFETY: getpid has no arguments and no caller-side preconditions.
        let pid = unsafe { libc::getpid() };

        let runtime = runtime_dir(root);

        let _ = write_text(&runtime.join("bootstrap_pid"), &format!("{pid}\n"));

        let _ = write_text(&runtime.join("bootstrap_status"), "RUNNING\n");

        let _ = write_payload_status(root, "RUNNING");

        log_info(&format!("native bootstrap started pid={pid}"));

        let heartbeat = runtime.join("bootstrap_heartbeat");

        let mut counter: u64 = 0;

        loop {
            counter = counter.wrapping_add(1);

            let _ = write_text(&heartbeat, &format!("{counter}\n"));

            if counter == 1 || counter.is_multiple_of(5) {
                log_info(&format!(
                    "native bootstrap heartbeat pid={pid} count={counter}"
                ));
            }

            // SAFETY: sleep takes only a bounded integer duration and has no
            // pointer or aliasing preconditions.
            unsafe {
                libc::sleep(2);
            }
        }
    }

    fn run_builtin_payload(root: &Path) -> ! {
        // SAFETY: getpid has no arguments and no caller-side preconditions.
        let payload_pid = unsafe { libc::getpid() };

        // SAFETY: PR_SET_PDEATHSIG uses integer arguments only; SIGTERM is a valid
        // signal number and the result is checked.
        let prctl_result = unsafe { libc::prctl(PR_SET_PDEATHSIG, libc::SIGTERM, 0, 0, 0) };

        if prctl_result != 0 {
            log_warn(&format!(
                "payload: PR_SET_PDEATHSIG failed errno={}",
                last_errno()
            ));
        }

        let _ = write_payload_pid(root, payload_pid);
        let _ = write_payload_status(root, "EXECUTOR_LOCKDOWN_STARTING");

        log_info(&format!("guest executor starting pid={payload_pid}"));

        if let Err(errno) = enable_executor_no_new_privs() {
            let _ = write_payload_status(root, "EXECUTOR_NNP_FAILED");

            log_error(&format!(
                "guest executor: PR_SET_NO_NEW_PRIVS failed pid={payload_pid} errno={errno}"
            ));

            // SAFETY: _exit terminates only the current forked child immediately
            // and does not return through Rust frames.
            unsafe {
                libc::_exit(123);
            }
        }

        log_info(&format!(
            "guest executor: NoNewPrivs verified pid={payload_pid}"
        ));

        if let Err(errno) = install_executor_probe_seccomp() {
            let _ = write_payload_status(root, "EXECUTOR_SECCOMP_FAILED");

            log_error(&format!(
                "guest executor: seccomp install failed pid={payload_pid} errno={errno}"
            ));

            // SAFETY: _exit terminates only the current forked child immediately
            // and does not return through Rust frames.
            unsafe {
                libc::_exit(124);
            }
        }

        log_info(&format!(
            "guest executor: probe seccomp installed pid={payload_pid}"
        ));

        match verify_executor_seccomp_boundary() {
            Ok((direct_getpid, direct_getppid)) => {
                let _ = write_payload_status(root, "EXECUTOR_BOUNDARY_VERIFIED");

                log_info(&format!(
                    "guest executor: DIRECT_SVC_BOUNDARY PASSED pid={payload_pid}                  getpid={direct_getpid} getppid={direct_getppid}"
                ));
            }
            Err(errno) => {
                let _ = write_payload_status(root, "EXECUTOR_BOUNDARY_FAILED");

                log_error(&format!(
                    "guest executor: DIRECT_SVC_BOUNDARY FAILED pid={payload_pid} errno={errno}"
                ));

                // SAFETY: _exit terminates only the current forked child immediately
                // and does not return through Rust frames.
                unsafe {
                    libc::_exit(125);
                }
            }
        }

        /*
         * For this milestone we continue into the existing native bootstrap only
         * after the executor boundary has been established and verified.
         *
         * The current seccomp program is intentionally permissive except for
         * getppid(), so the heartbeat/bootstrap can still use normal host syscalls.
         * The next phase will replace this probe policy with a real guest allowlist
         * plus userspace syscall virtualization.
         */
        let _ = write_payload_status(root, "BOOTSTRAP_STARTING");

        log_info(&format!(
            "guest executor launching native bootstrap pid={payload_pid}"
        ));

        run_native_bootstrap(root);
    }

    fn run_supervisor(root: &Path) -> ! {
        // SAFETY: getpid has no arguments and no caller-side preconditions.
        let supervisor_pid = unsafe { libc::getpid() };

        if let Err(errno) = write_status(root, "STARTING") {
            log_error(&format!(
                "supervisor: failed to write STARTING errno={errno}"
            ));

            // SAFETY: _exit terminates only this supervisor child and never
            // returns into Rust.
            unsafe {
                libc::_exit(120);
            }
        }

        log_info(&format!("guest supervisor started pid={supervisor_pid}"));

        // SAFETY: fork itself has no pointer arguments. Both return paths are
        // checked immediately; the child enters run_builtin_payload and never returns.
        let payload_pid = unsafe { libc::fork() };

        if payload_pid < 0 {
            let errno = last_errno();

            let _ = write_status(root, "ERROR");

            let _ = write_payload_status(root, "FAILED");

            log_error(&format!("supervisor: payload fork failed errno={errno}"));

            // SAFETY: _exit terminates only this supervisor child and never
            // returns into Rust.
            unsafe {
                libc::_exit(121);
            }
        }

        if payload_pid == 0 {
            run_builtin_payload(root);
        }

        let _ = write_payload_pid(root, payload_pid);

        let _ = write_payload_status(root, "RUNNING");

        let _ = write_status(root, "RUNNING");

        log_info(&format!("supervisor: payload started pid={payload_pid}"));

        let mut status: libc::c_int = 0;

        // SAFETY: status is a valid writable libc::c_int and payload_pid is the
        // positive PID returned by the successful fork above.
        let wait_result = unsafe { libc::waitpid(payload_pid, &mut status, 0) };

        if wait_result < 0 {
            let errno = last_errno();

            let _ = write_payload_status(root, "WAIT_ERROR");

            let _ = write_status(root, "ERROR");

            log_error(&format!(
                "supervisor: waitpid failed payload_pid={payload_pid} errno={errno}"
            ));

            // SAFETY: _exit terminates only this supervisor child and never
            // returns into Rust.
            unsafe {
                libc::_exit(122);
            }
        }

        if libc::WIFEXITED(status) {
            let code = libc::WEXITSTATUS(status);

            let _ = write_payload_status(root, &format!("EXITED:{code}"));

            log_warn(&format!(
                "supervisor: payload exited pid={payload_pid} code={code}"
            ));
        } else if libc::WIFSIGNALED(status) {
            let signal = libc::WTERMSIG(status);

            let _ = write_payload_status(root, &format!("SIGNALED:{signal}"));

            log_warn(&format!(
                "supervisor: payload signaled pid={payload_pid} signal={signal}"
            ));
        } else {
            let _ = write_payload_status(root, "UNKNOWN_EXIT");

            log_warn(&format!(
                "supervisor: payload ended with unknown status pid={payload_pid}"
            ));
        }

        let _ = write_status(root, "STOPPED");

        let _ = write_text(&runtime_dir(root).join("bootstrap_status"), "STOPPED\n");

        log_info(&format!("guest supervisor exiting pid={supervisor_pid}"));

        // SAFETY: supervisor work is complete; _exit terminates this forked
        // process immediately and never returns into Rust.
        unsafe {
            libc::_exit(0);
        }
    }

    pub fn start_guest() -> Result<i32, i32> {
        log_info("start_guest(): requested");

        let current = GUEST_PID.load(Ordering::SeqCst);

        if process_alive(current) {
            log_info(&format!("start_guest(): already running pid={current}"));

            return Ok(current);
        }

        let root = match prepare_guest_filesystem() {
            Ok(root) => root,

            Err(errno) => {
                log_error(&format!(
                    "start_guest(): filesystem prepare failed errno={errno}"
                ));

                return Err(errno);
            }
        };

        log_info("start_guest(): calling fork()");

        // SAFETY: fork itself has no pointer arguments. The return value is
        // checked immediately and the child enters run_supervisor without returning.
        let pid = unsafe { libc::fork() };

        if pid < 0 {
            let errno = last_errno();

            log_error(&format!("start_guest(): fork failed errno={errno}"));

            return Err(errno);
        }

        if pid == 0 {
            run_supervisor(&root);
        }

        GUEST_PID.store(pid, Ordering::SeqCst);

        if let Err(errno) = write_supervisor_pid(&root, pid) {
            log_error(&format!(
                "start_guest(): write supervisor pid failed pid={pid} errno={errno}"
            ));

            // SAFETY: pid is the positive child PID returned by fork; SIGTERM is a
            // valid signal and no pointers are involved.
            let _ = unsafe { libc::kill(pid, libc::SIGTERM) };

            // SAFETY: pid is our child PID and a null status pointer is explicitly
            // permitted by waitpid when the status value is not needed.
            let _ = unsafe { libc::waitpid(pid, std::ptr::null_mut(), 0) };

            GUEST_PID.store(0, Ordering::SeqCst);

            return Err(errno);
        }

        log_info(&format!("start_guest(): supervisor started pid={pid}"));

        Ok(pid)
    }

    pub fn stop_guest() -> Result<(), i32> {
        log_info("stop_guest(): requested");

        let pid = GUEST_PID.load(Ordering::SeqCst);

        let root = guest_root();

        if pid <= 0 {
            log_info("stop_guest(): guest already stopped");

            let _ = write_status(&root, "STOPPED");

            let _ = write_payload_status(&root, "STOPPED");

            let _ = write_text(&runtime_dir(&root).join("bootstrap_status"), "STOPPED\n");

            clear_runtime_pids(&root);

            return Ok(());
        }

        if !process_alive(pid) {
            log_warn(&format!(
                "stop_guest(): supervisor pid={pid} is no longer alive"
            ));

            GUEST_PID.store(0, Ordering::SeqCst);

            let _ = write_status(&root, "STOPPED");

            let _ = write_payload_status(&root, "STOPPED");

            let _ = write_text(&runtime_dir(&root).join("bootstrap_status"), "STOPPED\n");

            clear_runtime_pids(&root);

            return Ok(());
        }

        log_info(&format!(
            "stop_guest(): sending SIGTERM supervisor_pid={pid}"
        ));

        // SAFETY: pid is the tracked positive supervisor PID; SIGTERM is valid and
        // kill has no pointer arguments.
        if unsafe { libc::kill(pid, libc::SIGTERM) } != 0 {
            let errno = last_errno();

            if errno != libc::ESRCH {
                log_error(&format!(
                    "stop_guest(): kill failed pid={pid} errno={errno}"
                ));

                return Err(errno);
            }

            log_warn(&format!("stop_guest(): supervisor pid={pid} already gone"));
        }

        // SAFETY: pid is the tracked supervisor PID and waitpid permits a null
        // status pointer because the exit status is not consumed here.
        let wait_result = unsafe { libc::waitpid(pid, std::ptr::null_mut(), 0) };

        if wait_result < 0 {
            let errno = last_errno();

            if errno != libc::ECHILD {
                log_error(&format!(
                    "stop_guest(): waitpid failed pid={pid} errno={errno}"
                ));

                return Err(errno);
            }

            log_warn(&format!(
                "stop_guest(): supervisor pid={pid} is not our child anymore"
            ));
        }

        GUEST_PID.store(0, Ordering::SeqCst);

        let _ = write_status(&root, "STOPPED");

        let _ = write_payload_status(&root, "STOPPED");

        let _ = write_text(&runtime_dir(&root).join("bootstrap_status"), "STOPPED\n");

        clear_runtime_pids(&root);

        log_info(&format!("stop_guest(): guest stopped supervisor_pid={pid}"));

        Ok(())
    }

    pub fn guest_pid() -> Option<i32> {
        let pid = GUEST_PID.load(Ordering::SeqCst);

        if process_alive(pid) { Some(pid) } else { None }
    }
}

#[cfg(any(target_os = "android", target_os = "linux"))]
pub use platform_impl::{guest_pid, start_guest, stop_guest};

#[cfg(not(any(target_os = "android", target_os = "linux")))]
pub fn start_guest() -> Result<i32, i32> {
    // Host-analysis stub only. The real runtime is Android/Linux-only.
    Err(-1)
}

#[cfg(not(any(target_os = "android", target_os = "linux")))]
pub fn stop_guest() -> Result<(), i32> {
    Err(libc::ENOTSUP)
}

#[cfg(not(any(target_os = "android", target_os = "linux")))]
pub fn guest_pid() -> Option<i32> {
    None
}

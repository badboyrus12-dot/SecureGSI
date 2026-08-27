use std::fs;
use std::path::Path;
use std::thread;
use std::time::Duration;

pub fn run(root: &Path) -> ! {
    // SAFETY: getpid has no arguments and no caller-side preconditions.
    let pid = unsafe {
        libc::getpid()
    };

    let runtime =
        root.join("runtime");

    let _ = fs::write(
        runtime.join("bootstrap_pid"),
        format!("{pid}\n"),
    );

    let _ = fs::write(
        runtime.join("bootstrap_status"),
        "RUNNING\n",
    );

    let mut counter: u64 = 0;

    loop {
        counter += 1;

        let _ = fs::write(
            runtime.join("bootstrap_heartbeat"),
            format!("{counter}\n"),
        );

        // SAFETY: sleep takes an integer duration and has no pointer or aliasing
        // preconditions.
        unsafe {
            libc::sleep(2);
        }
    }
}
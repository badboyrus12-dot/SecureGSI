use std::env;
use std::fs;
use std::thread;
use std::time::Duration;

fn main() {
    let pid = std::process::id();

    println!("SecureGSI bootstrap started");
    println!("PID={pid}");

    println!("ARGS:");
    for (i, arg) in env::args().enumerate() {
        println!("  {i}: {arg}");
    }

    println!("ENV SECUREGSI_GUEST={:?}", env::var("SECUREGSI_GUEST"));

    let runtime_dir =
        "/data/data/com.securegsi/files/instances/default/runtime";

    let status_path =
        format!("{runtime_dir}/bootstrap_status");

    let pid_path =
        format!("{runtime_dir}/bootstrap_pid");

    fs::write(
        &status_path,
        "RUNNING\n",
    )
    .expect("failed to write bootstrap_status");

    fs::write(
        &pid_path,
        format!("{pid}\n"),
    )
    .expect("failed to write bootstrap_pid");

    let mut counter: u64 = 0;

    loop {
        counter += 1;

        let heartbeat_path =
            format!("{runtime_dir}/bootstrap_heartbeat");

        let _ = fs::write(
            heartbeat_path,
            format!("{counter}\n"),
        );

        thread::sleep(
            Duration::from_secs(2)
        );
    }
}
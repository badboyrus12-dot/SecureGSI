#![no_main]

use libfuzzer_sys::fuzz_target;

#[path = "../../src/ipc_protocol.rs"]
mod ipc_protocol;

fuzz_target!(|data: &[u8]| {
    // Exercise the exact-length gate with the original arbitrary slice.
    let _ = ipc_protocol::parse_slice(data);

    // Also force every fuzz input through the structural parser so short/long
    // inputs still mutate all protocol fields instead of being rejected only by
    // the length check.
    let mut packet = [0_u8; ipc_protocol::PACKET_LEN];
    let copied = data.len().min(ipc_protocol::PACKET_LEN);
    packet[..copied].copy_from_slice(&data[..copied]);

    let _ = ipc_protocol::parse(&packet);
});

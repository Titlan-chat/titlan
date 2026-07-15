// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

//! Fuzz target: the WebSocket ack-frame parser handles attacker-controlled
//! frames. It must return an Option on any input — never panic (INV-4). A
//! parsed ack must have come from a well-formed 17-byte `0x02`-tagged frame.

#![no_main]

use libfuzzer_sys::fuzz_target;
use tezca_relay::wire::parse_ack_frame;

fuzz_target!(|data: &[u8]| {
    if let Some(id) = parse_ack_frame(data) {
        assert_eq!(data.len(), 17);
        assert_eq!(data[0], 0x02);
        assert_eq!(&data[1..17], &id);
    }
});

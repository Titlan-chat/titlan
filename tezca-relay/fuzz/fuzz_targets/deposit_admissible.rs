// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

//! Fuzz target: the deposit admission check touches attacker-controlled bytes
//! before anything is queued. It must return a bool on any input — never
//! panic (INV-4). When it admits, the invariant (magic+version+min-length)
//! must hold.

#![no_main]

use libfuzzer_sys::fuzz_target;
use tezca_relay::wire::deposit_admissible;

fuzz_target!(|data: &[u8]| {
    if deposit_admissible(data) {
        assert!(data.len() >= 9);
        assert_eq!(&data[..4], b"TZCA");
        assert_eq!(data[4], 0x01);
    }
});

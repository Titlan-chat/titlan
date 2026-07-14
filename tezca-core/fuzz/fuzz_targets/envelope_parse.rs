// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

//! Fuzz target: the outer envelope parser must return a typed result on any
//! input — never panic, never crash (INV-4).

#![no_main]

use libfuzzer_sys::fuzz_target;
use tezca_core::envelope::Envelope;

fuzz_target!(|data: &[u8]| {
    if let Ok(envelope) = Envelope::parse(data) {
        // Round-trip oracle: anything that parses re-encodes to the same bytes.
        assert_eq!(envelope.encode(), data);
    }
});

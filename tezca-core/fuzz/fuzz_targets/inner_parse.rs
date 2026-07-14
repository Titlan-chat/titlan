// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

//! Fuzz target: the inner-frame parser must return a typed result on any
//! input — never panic, never crash (INV-4). Parsed frames must round-trip
//! stably through encode/parse (encode normalizes to the smallest bucket).

#![no_main]

use libfuzzer_sys::fuzz_target;
use tezca_core::config::PaddingProfile;
use tezca_core::envelope::InnerFrame;

fuzz_target!(|data: &[u8]| {
    let profile = PaddingProfile::default_profile();
    if let Ok(frame) = InnerFrame::parse(data, &profile) {
        let reencoded = frame
            .encode(&profile)
            .expect("a parsed frame must re-encode");
        let reparsed = InnerFrame::parse(&reencoded, &profile)
            .expect("a re-encoded frame must re-parse");
        assert_eq!(reparsed, frame);
    }
});

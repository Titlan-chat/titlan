// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

//! `tezca-relay` — blind message relay for the Tezca platform.
//!
//! Phase 1 scaffold: the server (mailbox create / blob deposit / WebSocket
//! delivery / TTL sweep) lands in Phase 3 per the work order. This placeholder
//! keeps the binary wired into CI, packaging, and the reproducibility pipeline.
//!
//! Standing constraints for all future code in this crate:
//! - INV-2: never receive, parse, store, or log sender identity, plaintext,
//!   contact graphs, or PII. No log line may pair a mailbox ID with a source IP.
//! - INV-3: RAM-only mailboxes; no database, no temp files, no swap/core dumps
//!   of mailbox memory (process hardening flags land with the server).

fn main() {
    println!(
        "tezca-relay {} (Phase 1 scaffold; server lands in Phase 3)",
        env!("CARGO_PKG_VERSION")
    );
}

#[cfg(test)]
mod tests {
    #[test]
    fn crate_version_is_wired() {
        assert!(!env!("CARGO_PKG_VERSION").is_empty());
    }
}

// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

//! `tezca-relay` — blind, stateless message relay (work order §6 Phase 3).
//!
//! Standing constraints:
//! - INV-2: the relay never receives, parses, or stores sender identity,
//!   plaintext, contact graphs, or PII. It inspects exactly the first five
//!   bytes of a deposit (magic + version, per proto/envelope.md) and nothing
//!   else. No log line may pair a mailbox ID with a source address — in
//!   fact, nothing in this crate logs at all (zero-logging policy, enforced
//!   by scripts/check-invariants.sh and the zero_knowledge test suite).
//! - INV-3: RAM-only mailboxes. No database, no files, no swap (mlockall +
//!   deploy-level controls), no core dumps (rlimit + dumpable off).
//! - INV-5: nothing here knows about "the" relay — no self-URL, no client
//!   registry; addressing lives entirely in client conversation config.

// tezca-relay is an internal binary crate (publish = false), not a reusable
// library like tezca-core, so the workspace `missing_docs` lint is relaxed
// here — module-level docs cover the design; per-field docs would be noise.
#![allow(missing_docs)]

pub mod api;
pub mod config;
pub mod hardening;
pub mod limits;
pub mod state;
pub mod wire;

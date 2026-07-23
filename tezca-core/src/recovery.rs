// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

//! §10.7 derived recovery mailboxes (frozen 4b-2 design §8; specs amended
//! 2026-07-19, maintainer-ratified B1/B2).
//!
//! Both mailboxes of a conversation share a relay, so a relay restart is TOTAL
//! routing loss while the Double Ratchet state survives in SQLCipher on both
//! ends. Recovery re-establishes routing WITHOUT re-pairing by deriving a
//! per-conversation sequence of unguessable mailbox IDs and converging both
//! parties onto the same generation.
//!
//! Root (B2, dual-contribution): each party contributes 32 CSPRNG bytes at
//! pairing — the responder's in `pair-ack/2`, the offerer's in the
//! `inbox-handoff` (`mailbox-update/2`). Neither contribution is ever in the
//! offer/QR, so a QR photographer cannot compute the recovery-mailbox sequence
//! (the 2a `pairing_secret`-derived-root option was rejected for exactly that
//! reason). The root is `HMAC-SHA256(A_contribution, B_contribution)`.
//!
//! KDF (B1): libsignal exposes no public HKDF, so mailbox IDs are derived with
//! HMAC-SHA256 as a PRF (HKDF-Expand ≡ HMAC-PRF for a uniformly-random root).
//! All MAC bytes come from libsignal's signal-crypto (INV-6).

use crate::pairing::{RECOVERY_CONTRIB_LEN, hmac_sha256};
use crate::{CoreError, Result};

/// `recovery-hello` version (`proto/inner-frame.md`).
pub(crate) const RECOVERY_HELLO_VERSION: u8 = 1;
/// `recovery-hello` nonce length (makes redeliveries dedup-detectable).
pub(crate) const RECOVERY_HELLO_NONCE_LEN: usize = 16;

/// Encodes a `recovery-hello` inner payload: version + generation + nonce.
pub(crate) fn encode_recovery_hello(
    generation: u32,
    nonce: &[u8; RECOVERY_HELLO_NONCE_LEN],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 4 + RECOVERY_HELLO_NONCE_LEN);
    out.push(RECOVERY_HELLO_VERSION);
    out.extend_from_slice(&generation.to_be_bytes());
    out.extend_from_slice(nonce);
    out
}

/// Parses a `recovery-hello` → (generation, nonce). Strict length + version.
pub(crate) fn parse_recovery_hello(bytes: &[u8]) -> Result<(u32, [u8; RECOVERY_HELLO_NONCE_LEN])> {
    if bytes.len() != 1 + 4 + RECOVERY_HELLO_NONCE_LEN {
        return Err(CoreError::Malformed("recovery-hello wrong length"));
    }
    if bytes[0] != RECOVERY_HELLO_VERSION {
        return Err(CoreError::Malformed("unknown recovery-hello version"));
    }
    let generation = u32::from_be_bytes(bytes[1..5].try_into().expect("4 bytes"));
    let nonce: [u8; RECOVERY_HELLO_NONCE_LEN] = bytes[5..].try_into().expect("16 bytes");
    Ok((generation, nonce))
}

/// Generation-convergence window `W` (frozen §8; config, approved default 4).
/// A relative generation offset `≥ W` is unrecoverable in-band and surfaces
/// `conversation-needs-repair`.
pub(crate) const RECOVERY_WINDOW: u32 = 4;

/// Probe cycles attempted before declaring exhaustion when no verified peer
/// contact is seen (frozen §8; config, approved default 3 across 24 h).
pub(crate) const RECOVERY_PROBE_CYCLES: u32 = 3;

/// Domain-separation prefix for the mailbox-ID PRF.
const MAILBOX_LABEL: &[u8] = b"titlan-recovery-mailbox-v1";

/// The pairing role of a derived mailbox's OWNER, mixed into the PRF so the two
/// directions never collide on an ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Role {
    /// The party that displayed the offer.
    Offerer,
    /// The party that scanned the offer.
    Responder,
}

impl Role {
    fn label(self) -> &'static [u8] {
        match self {
            Role::Offerer => b"offerer",
            Role::Responder => b"responder",
        }
    }
}

/// Derives the per-conversation recovery root from the two contributions
/// (B2): `root = HMAC-SHA256(A_contribution, B_contribution)`.
pub(crate) fn derive_root(
    a_contribution: &[u8; RECOVERY_CONTRIB_LEN],
    b_contribution: &[u8; RECOVERY_CONTRIB_LEN],
) -> [u8; 32] {
    hmac_sha256(a_contribution, b_contribution)
}

/// Derived mailbox ID for the mailbox OWNED by `owner_role` at `generation`:
/// `base64url_nopad(HMAC-SHA256(root, LABEL || role_label || generation_be))`
/// — 43 chars, 256-bit, unguessable, opaque to the relay.
pub(crate) fn derive_mailbox_id(root: &[u8; 32], owner_role: Role, generation: u32) -> String {
    let mut info = Vec::with_capacity(MAILBOX_LABEL.len() + 16);
    info.extend_from_slice(MAILBOX_LABEL);
    info.extend_from_slice(owner_role.label());
    info.extend_from_slice(&generation.to_be_bytes());
    base64url_nopad(&hmac_sha256(root, &info))
}

/// RFC 4648 §5 base64url, no padding. 32 bytes → 43 chars (matches the relay's
/// mailbox-id alphabet, `relay-api.md`).
fn base64url_nopad(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[((n >> 18) & 0x3f) as usize] as char);
        out.push(ALPHABET[((n >> 12) & 0x3f) as usize] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[((n >> 6) & 0x3f) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[(n & 0x3f) as usize] as char);
        }
    }
    out
}

/// Persisted convergence state for one conversation: this party's own
/// generation `g` and the last-known peer generation (frozen §8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct GenerationState {
    /// This party's own current generation `g`.
    pub own: u32,
    /// Last generation observed from a verified peer control frame.
    pub peer: u32,
}

impl GenerationState {
    /// Sender-side recovery: the peer generations `[peer_g … peer_g+(W-1)]` to
    /// PUT-CREATE (before depositing) and drop an idempotent `recovery-hello`
    /// into. Creating the peer inboxes first is load-bearing for the 2W bound.
    pub(crate) fn outbound_window(&self) -> Vec<u32> {
        (self.peer..self.peer.saturating_add(RECOVERY_WINDOW)).collect()
    }

    /// Convergence on a verified control receipt: both sides adopt
    /// `max(own, peer_generation)`. Returns `true` when this changed local
    /// state and a rotation must run.
    pub(crate) fn converge(&mut self, peer_generation: u32) -> bool {
        self.peer = self.peer.max(peer_generation);
        let target = self.own.max(peer_generation);
        if target != self.own {
            self.own = target;
            true
        } else {
            false
        }
    }

    /// `true` when the relative offset has reached the window `W` — the
    /// in-band-unrecoverable condition that raises
    /// [`crate::CoreError::ConversationNeedsRepair`].
    pub(crate) fn is_exhausted(&self) -> bool {
        self.own.abs_diff(self.peer) >= RECOVERY_WINDOW
    }
}

/// Tracks probe cycles toward the 3-cycle / 24h exhaustion bound. Relay `429`s
/// are PACING signals and MUST NOT advance the counter (frozen §8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ExhaustionTracker {
    cycles: u32,
}

impl ExhaustionTracker {
    pub(crate) fn new() -> Self {
        ExhaustionTracker { cycles: 0 }
    }

    /// A completed probe cycle with no verified peer contact. Called ONCE per
    /// recovery ATTEMPT — never per deposit — so relay `429`s within an attempt
    /// (absorbed as pacing at the deposit layer) cannot advance the counter.
    pub(crate) fn note_probe_cycle(&mut self) {
        self.cycles = self.cycles.saturating_add(1);
    }

    /// Reset on any verified peer contact.
    pub(crate) fn reset(&mut self) {
        self.cycles = 0;
    }

    /// `true` once the probe-cycle bound is reached.
    pub(crate) fn is_exhausted(&self) -> bool {
        self.cycles >= RECOVERY_PROBE_CYCLES
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn contrib(seed: u8) -> [u8; RECOVERY_CONTRIB_LEN] {
        [seed; RECOVERY_CONTRIB_LEN]
    }

    #[test]
    fn root_is_symmetric_across_parties_but_order_sensitive() {
        let a = contrib(0xAA);
        let b = contrib(0xBB);
        // Both parties compute HMAC(A_contrib, B_contrib) → identical root.
        assert_eq!(derive_root(&a, &b), derive_root(&a, &b));
        // Distinct from the swapped keying (A and B roles are fixed by pairing).
        assert_ne!(derive_root(&a, &b), derive_root(&b, &a));
    }

    #[test]
    fn mailbox_ids_are_43_chars_and_role_generation_separated() {
        let root = derive_root(&contrib(1), &contrib(2));
        let a0 = derive_mailbox_id(&root, Role::Offerer, 0);
        assert_eq!(a0.len(), 43);
        // deterministic
        assert_eq!(a0, derive_mailbox_id(&root, Role::Offerer, 0));
        // role-separated
        assert_ne!(a0, derive_mailbox_id(&root, Role::Responder, 0));
        // generation-separated
        assert_ne!(a0, derive_mailbox_id(&root, Role::Offerer, 1));
        // base64url alphabet only
        assert!(
            a0.bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
        );
    }

    #[test]
    fn sender_forward_window_is_w_wide() {
        let g = GenerationState { own: 0, peer: 2 };
        assert_eq!(g.outbound_window(), vec![2, 3, 4, 5]); // [peer_g … peer_g+W-1]
    }

    #[test]
    fn double_restart_desync_converges_to_max() {
        // A at n+1, B at n (frozen §9c double-restart).
        let mut a = GenerationState { own: 2, peer: 0 };
        let mut b = GenerationState { own: 1, peer: 0 };
        // A receives B's hello at gen 1 → no bump (2 > 1), records peer.
        assert!(!a.converge(1));
        assert_eq!(a.own, 2);
        // B receives A's hello at gen 2 → bumps to 2, rotation required.
        assert!(b.converge(2));
        assert_eq!(b.own, 2);
        // Both now at 2.
        assert_eq!(a.own, b.own);
    }

    #[test]
    fn offset_at_or_beyond_window_is_exhausted() {
        assert!(!GenerationState { own: 3, peer: 0 }.is_exhausted()); // offset 3 < 4
        assert!(GenerationState { own: 4, peer: 0 }.is_exhausted()); // offset 4 == W
        assert!(GenerationState { own: 0, peer: 9 }.is_exhausted()); // symmetric
    }

    #[test]
    fn recovery_hello_round_trips_and_rejects_malformed() {
        let nonce = [0x5Au8; RECOVERY_HELLO_NONCE_LEN];
        let enc = encode_recovery_hello(7, &nonce);
        assert_eq!(enc.len(), 1 + 4 + RECOVERY_HELLO_NONCE_LEN);
        let (g, n) = parse_recovery_hello(&enc).unwrap();
        assert_eq!(g, 7);
        assert_eq!(n, nonce);
        // Wrong length and wrong version are clean rejections.
        assert!(parse_recovery_hello(&enc[..enc.len() - 1]).is_err());
        let mut bad = enc.clone();
        bad[0] = 0x02;
        assert!(parse_recovery_hello(&bad).is_err());
    }

    #[test]
    fn cycle_exhaustion_counts_attempts_and_429_within_an_attempt_cannot_advance() {
        // The counter advances ONLY via note_probe_cycle — called once per
        // recovery ATTEMPT (never per deposit). Relay 429s are absorbed as
        // pacing at the deposit layer and have NO input to the tracker, so any
        // number of 429s within a single attempt still counts as one cycle.
        let mut t = ExhaustionTracker::new();
        assert!(!t.is_exhausted());
        // Two attempts (each may have hit arbitrarily many 429s internally).
        t.note_probe_cycle();
        t.note_probe_cycle();
        assert!(!t.is_exhausted(), "two attempts < 3 cycles");
        // Third attempt with no verified contact → exhausted.
        t.note_probe_cycle();
        assert!(t.is_exhausted());
        // A verified recovery-hello resets the counter.
        t.reset();
        assert!(!t.is_exhausted());
    }
}

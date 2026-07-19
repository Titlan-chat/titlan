// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

//! §10.7 derived recovery mailboxes (frozen 4b-2 design §8) — PRODUCTION HOME,
//! stubbed in the 4b-2 RED commit.
//!
//! Both mailboxes of a conversation share a relay, so a relay restart is
//! TOTAL routing loss while the Double Ratchet state survives in SQLCipher on
//! both ends. Recovery re-establishes routing WITHOUT re-pairing by deriving a
//! per-conversation sequence of unguessable mailbox IDs from the session's
//! shared secret and converging both parties onto the same generation.
//!
//! Nothing here is wired yet: the 4b-2 GREEN commit implements the bodies
//! (`todo!()` today) and connects them to [`crate::relay_client`]. Every
//! primitive (HKDF, MAC) MUST come from libsignal per INV-6 — this module
//! never pulls a bare crypto crate; the stubs exist precisely so the green
//! implementation has a typed home and the tests have a target.
//!
//! Wire framing for the in-band control messages this module drives
//! (`recovery-hello`, `inbox-handoff`) is normative in `proto/inner-frame.md`.

#![allow(dead_code)] // green wires these into the sync engine; red only declares the surface.

use crate::Result;

/// Generation-convergence window `W` (frozen design §8; config, approved
/// default 4). A relative generation offset `≥ W` between the two parties is
/// unrecoverable in-band and surfaces `conversation-needs-repair`.
pub(crate) const RECOVERY_WINDOW: u32 = 4;

/// Probe cycles attempted before declaring exhaustion when no verified peer
/// contact is seen (frozen design §8; config, approved default 3 across 24 h).
pub(crate) const RECOVERY_PROBE_CYCLES: u32 = 3;

/// Which direction of the conversation a derived mailbox serves. The label is
/// mixed into the HKDF so the two directions never collide on an ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Direction {
    /// Mailboxes this party owns and subscribes to.
    Inbound,
    /// The peer's mailboxes this party deposits into.
    Outbound,
}

impl Direction {
    /// The domain-separation label fed to HKDF alongside the generation.
    fn label(self) -> &'static [u8] {
        match self {
            Direction::Inbound => b"titlan/recovery/inbound",
            Direction::Outbound => b"titlan/recovery/outbound",
        }
    }
}

/// Per-conversation recovery root, derived once at pairing from the session's
/// shared secret and persisted in SQLCipher. Zeroized on drop in green.
pub(crate) struct RecoveryRoot {
    // 32-byte derived secret; a fixed-size array in green so it zeroizes.
    _seed: Vec<u8>,
}

impl RecoveryRoot {
    /// Derives the recovery root from the freshly established session's shared
    /// secret (libsignal HKDF, INV-6).
    pub(crate) fn derive(_session_shared_secret: &[u8]) -> Result<RecoveryRoot> {
        todo!("4b-2 green: HKDF(session_shared_secret, \"titlan/recovery/root\") via libsignal")
    }

    /// Derived mailbox ID for `direction` at `generation`:
    /// `HKDF(root, direction-label, generation)` → 256-bit, base64url — opaque
    /// and unguessable to the relay.
    pub(crate) fn mailbox_id(&self, _direction: Direction, _generation: u32) -> Result<String> {
        todo!("4b-2 green: HKDF expand → 32 bytes → base64url mailbox id")
    }
}

/// Persisted convergence state for one conversation: this party's generation
/// and the last-known peer generation (frozen design §8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct GenerationState {
    /// This party's own current generation `g`.
    pub own: u32,
    /// Last generation observed from a verified peer control frame.
    pub peer: u32,
}

impl GenerationState {
    /// Receiver-side loss detection: bump own generation, returning the set of
    /// own inbound generations `[g-(W-1) … g]` to PUT-create and subscribe.
    pub(crate) fn on_loss_detected(&mut self) -> Vec<u32> {
        todo!("4b-2 green: bump own generation; return the inbound window to create+subscribe")
    }

    /// Sender-side recovery: the peer generations `[peer_g … peer_g+(W-1)]` to
    /// PUT-CREATE (before depositing) and drop an idempotent `recovery-hello`
    /// into. Creating the peer inboxes first is load-bearing for the 2W bound.
    pub(crate) fn outbound_window(&self) -> Vec<u32> {
        todo!("4b-2 green: return the peer generation window to create-then-deposit")
    }

    /// Convergence on a verified control receipt: both sides adopt
    /// `max(g_A, g_B)`. Returns `true` when this changed local state and a
    /// rotation must run.
    pub(crate) fn converge(&mut self, _peer_generation: u32) -> bool {
        todo!("4b-2 green: adopt max(own, peer); signal rotation")
    }

    /// `true` when the relative offset has reached the window `W` — the
    /// in-band-unrecoverable condition that raises
    /// [`crate::CoreError::ConversationNeedsRepair`].
    pub(crate) fn is_exhausted(&self) -> bool {
        self.own.abs_diff(self.peer) >= RECOVERY_WINDOW
    }
}

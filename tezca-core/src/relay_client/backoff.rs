// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

//! Exponential backoff with jitter for reconnect loops. Deterministic when
//! seeded (tests); OS-random in production.

use std::time::Duration;

/// Reconnect backoff: 1s → ×2 → cap 60s, ±20% jitter.
pub(crate) struct Backoff {
    current_secs: f64,
    max_secs: f64,
    // Simple LCG so jitter is deterministic under a fixed seed (tests) yet
    // varied in production (seeded from the OS CSPRNG). Not a security RNG.
    state: u64,
}

impl Backoff {
    pub(crate) fn new(seed: u64) -> Self {
        Backoff {
            current_secs: 1.0,
            max_secs: 60.0,
            state: seed | 1,
        }
    }

    /// Returns the next delay and advances the schedule.
    pub(crate) fn next_delay(&mut self) -> Duration {
        let base = self.current_secs;
        self.current_secs = (self.current_secs * 2.0).min(self.max_secs);
        // LCG (Numerical Recipes constants).
        self.state = self
            .state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        // 64 - 33 = 31 significant bits: fits u32 (and f64) exactly.
        let hi31 = u32::try_from(self.state >> 33).expect("31-bit value fits u32");
        let unit = f64::from(hi31) / f64::from(1u32 << 31); // [0,1)
        let jitter = 1.0 + (unit - 0.5) * 0.4; // ±20%
        Duration::from_secs_f64((base * jitter).max(0.05))
    }

    /// Resets to the initial delay after a successful connection.
    pub(crate) fn reset(&mut self) {
        self.current_secs = 1.0;
    }

    /// Whole seconds of the current step (for the Backoff connection state).
    // Intentional whole-second truncation of a float bounded to
    // [0.05, max_secs] — always non-negative, far below u32::MAX; no
    // checked float→int conversion exists to express this instead.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    pub(crate) fn current_secs(&self) -> u32 {
        self.current_secs as u32
    }
}

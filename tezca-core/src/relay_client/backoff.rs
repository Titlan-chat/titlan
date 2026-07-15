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
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let unit = (self.state >> 33) as f64 / (1u64 << 31) as f64; // [0,1)
        let jitter = 1.0 + (unit - 0.5) * 0.4; // ±20%
        Duration::from_secs_f64((base * jitter).max(0.05))
    }

    /// Resets to the initial delay after a successful connection.
    pub(crate) fn reset(&mut self) {
        self.current_secs = 1.0;
    }

    /// Whole seconds of the current step (for the Backoff connection state).
    pub(crate) fn current_secs(&self) -> u32 {
        self.current_secs as u32
    }
}

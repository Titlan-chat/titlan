// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

//! Process hardening (INV-3): no core dumps of mailbox memory, not
//! ptrace-dumpable, and best-effort mlockall to keep mailbox RAM out of
//! swap. All via rustix's safe wrappers — no `unsafe` in this crate.
//! Deploy-level companions: systemd `MemorySwapMax=0` / `LimitCORE=0`,
//! docker `--memory-swap == --memory` (see deploy/).

use rustix::process::{DumpableBehavior, Resource, Rlimit, set_dumpable_behavior, setrlimit};

/// Applies hardening at startup. mlockall is best-effort: it silently
/// continues on EPERM (needs CAP_IPC_LOCK / LimitMEMLOCK=infinity) because
/// the zero-logging policy leaves no channel to warn on — the systemd unit
/// grants the limit, and swap is additionally disabled at the cgroup level.
pub fn apply() {
    let zero = Rlimit {
        current: Some(0),
        maximum: Some(0),
    };
    let _ = setrlimit(Resource::Core, zero);
    let _ = set_dumpable_behavior(DumpableBehavior::NotDumpable);
    let _ = rustix::mm::mlockall(
        rustix::mm::MlockAllFlags::CURRENT | rustix::mm::MlockAllFlags::FUTURE,
    );
}

/// Test hook: verify the limits actually took (used by unit test + CI).
pub fn core_limit_is_zero() -> bool {
    let lim = rustix::process::getrlimit(Resource::Core);
    lim.current == Some(0) && lim.maximum == Some(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hardening_applies_core_limit() {
        apply();
        assert!(core_limit_is_zero(), "RLIMIT_CORE must be 0 after apply()");
    }
}

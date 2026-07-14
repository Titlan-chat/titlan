<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- SPDX-FileCopyrightText: 2026 Oculux Technologies LLC -->

# CLAUDE.md — rules for AI-assisted work in this repository

The development process is described publicly in [DEVELOPMENT.md](DEVELOPMENT.md).
Architecture decisions and invariants live in a locked work order maintained
by the human maintainer; the agent may not deviate from locked decisions, and
anything requiring judgment is flagged to the maintainer rather than decided
autonomously.

## Commit discipline

- **Each phase lands in two commits minimum: (1) failing acceptance tests,
  committed red; (2) implementation turning them green. The red state must
  be a distinct, pushed commit so test-first is git-provable.** (Adopted
  2026-07-14, effective Phase 3 onward.) Red and green go up in the same
  push/PR so "no merge on red" gates the head commit while the red commit
  remains in history.
- Every commit carries the `Co-Authored-By` trailer identifying AI
  authorship. History is never rewritten to obscure it.

## Dependency rules

- Coupled dependencies: `rand`, and any crate sharing types with libsignal's
  public API, must never be bumped independently — they move only in lockstep
  with a libsignal bump, verified against the RNG trait bounds in
  identity/session key generation. See work-order §10.2 ledger.

## Standing constraints (enforced by CI — see DEVELOPMENT.md)

- No custom cryptography: all primitives via libsignal; `deny.toml` bans
  primitive crates outside libsignal's tree. Extending a ban-list wrapper
  requires explicit maintainer approval.
- Every file carries an SPDX header; the Android `applicationId` is
  single-sourced; reserved brand strings never appear in user-facing
  resources (`scripts/check-invariants.sh`).
- Builds must stay reproducible (`scripts/repro-build.sh`); lockfiles are
  committed; toolchains are pinned.

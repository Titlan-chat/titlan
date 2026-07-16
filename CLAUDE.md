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
- Valid red (adopted 2026-07-16): a test that fails at setup/plumbing
  rather than at its intended assertion is NOT a valid red for that test.
  If the CI red run shows any test erroring before reaching its predicted
  assertion, the red commit is amended before any green work proceeds.
- Revision mechanics (adopted 2026-07-16): revisions are made by
  amend/rebase on a named branch, never by reset-and-recommit from the
  base — reset cycles orphan hashes and make reports cite superseded
  commits.
- Stop-for-push reports (adopted 2026-07-16): every stop-for-push report
  is written to a file outside the repo and embeds fresh `git branch -v`
  and `git log --oneline --all -8` output generated at write time, never
  recalled.

## Design gate

- A design gate is not passed until the maintainer explicitly approves.
  Presenting a strong design is not self-authorization to begin work. After
  presenting a design, stop and do nothing — no proto docs, no tests, no
  scaffolding — until the maintainer says "approved". This holds even when the
  design is sound and even when the maintainer resolved the open flags: the
  explicit "approved" is the gate, not your assessment that it is ready.

## Push boundary

- Push boundary: the agent commits locally but NEVER pushes, merges, or
  modifies remote state — even where credentials permit it. Every push is
  performed manually by the maintainer as the human release gate. When work
  is ready, stop and say so.
- Exception (adopted 2026-07-16): merge/close/comment on dependency-update
  PRs only, and only under an explicit per-instance maintainer instruction
  naming the PR(s). Never feature branches, never main pushes, never
  releases. All other remote state remains maintainer-only.
- Agent-executed merges must set the squash commit message explicitly
  (subject and body, including the `Co-Authored-By` trailer) — GitHub's
  squash default takes the PR body and drops trailers.
- **Instruction-conflict rule:** if a direct instruction conflicts with
  CLAUDE.md or the work order, flag the conflict and wait for confirmation
  before acting — even when the instruction comes from the maintainer.
- Deviation record (2026-07-16): the Dependabot triage of this date
  (merging #12/#17, closing #14/#16/#18, rationale comments) was executed
  on maintainer instruction BEFORE this exception existed, and the conflict
  with the then-absolute boundary was not flagged. The #17 squash merge
  (`ed4d382`) also carries no `Co-Authored-By` trailer identifying the
  agent-executed merge (GitHub squash default; not rewritten — history is
  never rewritten). This note is the durable record of both.

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

<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- SPDX-FileCopyrightText: 2026 Oculux Technologies LLC -->

# How Titlan Is Developed

Titlan is developed by Oculux Technologies LLC using an AI-assisted process,
with a human decision-maker accountable for every security-relevant choice.
This document explains that process plainly, because a security product's
development provenance is part of its security posture. We would rather you
evaluate our process than take our word for anything.

## The short version

- Code is substantially written by an AI coding agent (Anthropic's Claude,
  via Claude Code). Commits carry a `Co-Authored-By` trailer identifying
  this. We do not remove these trailers or rewrite history to obscure them.
- A human (the maintainer) reviews and approves every design before
  implementation, reviews every phase of work before the next begins, and
  is the named decision-maker for all cryptographic and protocol choices.
- The rules the agent must follow are written down, versioned, and — where
  possible — enforced by machines rather than promises.

## The process

Development runs against a locked work order: a versioned document defining
architecture decisions (numbered, e.g. "A2: crypto via libsignal, no custom
cryptography anywhere") and non-negotiable invariants (numbered, e.g.
"INV-2: the relay never receives, parses, or stores sender identity,
message plaintext, or PII"). The agent may not deviate from locked
decisions; anything requiring judgment is flagged to the human rather than
decided autonomously.

Each phase of work follows the same gate sequence:

1. **Design before code.** The agent produces a written design (byte
   layouts, schemas, API surfaces, file plan). The human reviews and
   approves — or pushes back — before implementation starts.
2. **Tests before implementation.** Acceptance criteria are written into
   the work order in advance. Tests are written first and shown failing,
   then the implementation is written, then real test output is reviewed.
3. **Phase review.** Work stops at each phase boundary for human review of
   the diff, the test evidence, and an invariant-by-invariant audit before
   the next phase is authorized.

## What is enforced by machines, not promises

- **No custom cryptography (INV-6):** all cryptographic operations go
  through libsignal. This is enforced by `cargo-deny` rules that fail CI if
  any cryptographic primitive crate is imported outside libsignal's
  dependency tree — not by convention.
- **Reproducible builds:** release artifacts are built twice from fresh
  source and byte-compared in CI. Toolchains are pinned; lockfiles are
  committed.
- **Provenance:** every tagged release publishes CycloneDX SBOMs, build
  provenance attestations, and the reproducibility report.
- **License and structure rules:** SPDX headers, the license split between
  components, and the single-source application ID are checked by CI
  scripts on every commit.
- **Parser safety:** the wire-format parsers (the code that touches
  attacker-controlled bytes before authentication) are fuzzed in CI with a
  committed seed corpus.

## What is reviewed by a human

Wire format and protocol decisions, cryptographic API usage, key handling
and storage design, threat-model tradeoffs (e.g. padding/traffic-analysis
parameters), dependency changes that touch the pinned toolchain, and
anything the automated gates cannot judge. No cryptographic or
protocol-level decision ships without a named human having read it,
understood it, and accepted responsibility for it.

## Why we work this way

Titlan's design principle is that trust should be verifiable or
unnecessary. We think that principle applies to authorship too. An
AI-assisted process leaves a more complete audit trail than most
conventional development: written designs approved before code existed,
tests that predate their implementations, mechanically enforced invariants,
and phase gates — all timestamped in this repository's history. We publish
the process rather than laundering it, and we invite scrutiny of both the
code and how it came to be.

Questions, criticism, and audits are welcome. See SECURITY.md for how to
report vulnerabilities.

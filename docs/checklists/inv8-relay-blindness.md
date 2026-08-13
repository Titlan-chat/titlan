<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- SPDX-FileCopyrightText: 2026 Oculux Technologies LLC -->

# Review checklist — relay semantic blindness (INV-8, freeze H4.1)

Apply to **every PR touching `tezca-relay/`** (G4.4 ratified 2026-08-10; report
p5-5b2-inv-matrix T3(c)4). The relay is a blind, stateless byte pipe: it must
never acquire group, blob, directory, or any payload-semantic awareness
(freeze H4.1). Dependency creep and interior-dependent behavior are the two
leading indicators; this checklist is the human leg, and the mechanical
complements are:

- **Family 11** in `scripts/check-invariants.sh` — asserts tezca-relay's
  NORMAL dependency graph excludes `tezca-core` (`cargo tree -e normal
  --locked`; dev-dependencies exempt).
- **The interior-invariance pipeline test** —
  `tezca-relay/tests/zero_knowledge.rs::relay_treatment_is_byte_identical_for_differing_inner_payload_types`
  — asserts the pipeline's observable behavior (admission, responses,
  delivery framing, rate accounting) is independent of envelope interiors.

A change that passes both mechanical checks can still creep semantically;
every point below is reviewed by a human on every relay PR.

## The six points

1. **No new `[dependencies]`.** tezca-relay's normal dependency list does not
   grow. Anything an envelope-aware feature "needs" is the tell that the
   feature does not belong in the relay (see point 6). Dev-dependencies for
   the acceptance harness are exempt (family 11's `-e normal` boundary).

2. **No read past `blob[4]` on any path.** Admission touches magic
   (`blob[..4]`) and version (`blob[4]`) only; no code path — handler,
   helper, or test-support in `src/` — indexes, slices, parses, or branches
   on any deposited byte beyond index 4.

3. **Mailbox IDs remain shape-checked opaque tokens.** IDs are validated for
   shape and used as lookup keys, nothing else — no classes, no namespaces,
   no structure inferred from or encoded into the ID space.

4. **Storage/TTL/limits stay uniform per mailbox.** One policy for every
   mailbox — no directory table, no blob references, no per-mailbox
   differentiation derived from anything but the uniform configured limits.

5. **Delivery remains byte-transparent.** The delivery-frame payload equals
   the deposited bytes exactly (framing adds only the fixed prefix and
   message id); nothing rewrites, annotates, or filters envelope bytes.

6. **Server-side semantics go elsewhere.** Any feature that needs the server
   to understand payloads goes to its own service with its own invariant
   ledger — never into the relay (freeze H4.1).

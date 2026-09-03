<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- SPDX-FileCopyrightText: 2026 Oculux Technologies LLC -->

# 5d Release-Infrastructure Design Freeze — ratified 2026-09-02

Status: **FROZEN.** Maintainer ratification 2026-09-02, three verdicts of
record, each: "Package as recommended" (D4, D5, D6). This document is the
decision record for Phase 5d (work order §6 Phase 5, §7); deviations
require a governed amendment. Referenced by governance ledger item 31.

## D4 — Release signing key ceremony (FROZEN)

- The key is permanent: all future updates must be signed by it. The
  ceremony is the maintainer's hands only, on the titlan-dev VM. Key
  material never enters any repository, any agent session, any report,
  or any evidence log — no exceptions.
- Specification: `keytool`; RSA 4096; validity 10958 days (30 years);
  PKCS12 keystore; alias `titlan-release`; path
  `~/keys/titlan-release.p12` (outside both repositories); mode 600.
- Passphrase: generated random, held only in the maintainer's password
  manager.
- Backups: exactly two — (1) a passphrase-protected encrypted archive of
  the keystore in the maintainer's OneDrive backup location; (2) one
  offline USB copy. Backup-archive passphrase is distinct and
  password-manager-held.
- Public output: the signing certificate's SHA-256 digest — the ONLY
  ceremony artifact that leaves the VM. It is published on the D6
  verification page and recorded in the governance ledger alongside the
  ceremony record (dates, alias, digest, backup attestations; never
  material, never passphrases).
- Rotation: none at MVP. Any future rotation is a governed event with
  its own design gate.
- Execution vehicle: a hash-published maintainer runbook (checklist with
  WHERE labels), executed by hand; the agent drafts artifacts only.

## D5 — Production relay (FROZEN)

- Provider/size/OS/region: DigitalOcean, smallest droplet tier (>= 1 GiB
  RAM), Ubuntu 24.04 LTS, region SFO.
- Hostname: `relay.titlan.chat`. DNS at Cloudflare, **DNS-only (grey
  cloud), never proxied**: the relay terminates its own TLS under the
  anchor/pinning design; interposing Cloudflare's certificate is a
  design violation.
- TLS: Let's Encrypt on the droplet. Issuance mechanism (standalone vs
  DNS-01) is selected and recorded at the deploy-runbook order; either
  satisfies this freeze.
- Service: the repository's `deploy/tezca-relay.service` verbatim (the
  eighteen content-asserted hardening directives). Artifact form (single
  binary vs the `ghcr.io/titlan-chat/titlan-relay` container) is
  selected and recorded at the deploy-runbook order.
- Network: inbound 443 plus key-authenticated SSH only; password
  authentication disabled.
- Client default: the INV-5 single default-relay constant becomes
  `relay.titlan.chat` at the release-candidate unit, in the existing
  config schema's form.
- Scope: **minimal-first** — droplet plus a documented runbook ship 5d.
  The Ansible cycle/purge automation (`titlan-ops`, items O1–O8;
  decisions OD-1..OD-9) is the named successor and does not gate 5d.
- Boundary: the droplet's shell is the maintainer's exclusively
  (push-boundary-equivalent). Agents never hold droplet credentials;
  every deploy command is `WHERE: droplet · by-hand` from a drafted
  runbook.

## D6 — Site and downloads (FROZEN)

- Host: Cloudflare Pages, bound to the public monorepo; site source at
  `/site` in the monorepo. Site sources carry AGPL-3.0 SPDX headers and
  follow A11 branding (Titlan-only; the publisher line only in an
  about/imprint context).
- MVP scope: a landing page and a **verification page** — the D4
  certificate SHA-256 digest, the latest release APK's SHA-256,
  reproducible-build instructions, and links to the repository, wire
  protocol spec 1.0, threat model 1.0, and SECURITY.md. No trackers, no
  third-party scripts, no cookies.
- Download origin: **GitHub Releases** — the signed APK ships beside its
  SBOMs and provenance attestations via release.yml, so the download and
  its proof are co-located. `titlan.app` redirects to the latest release
  (redirect form selected and recorded at the site unit); `titlan.net`
  redirects to `titlan.chat`.
- DNS/proxying: the Pages hostnames may be proxied normally — a static
  site has no pinning model. This is explicitly distinct from the D5
  grey-cloud rule.

## Sequencing (FROZEN)

1. **D4 first** — the key gates the release checklist and supplies the
   verification page's digest.
2. D5 and D6 proceed in parallel after the D4 ceremony record exists.
   No placeholders are ever committed: the verification page ships a
   section only when its literal exists.
3. Execution pieces flowing from this freeze: the D4 ceremony runbook
   (maintainer-executed), the D5 deploy runbook plus any client-config
   unit, the D6 site unit, and the release-candidate unit that pins the
   default relay constant and executes the Phase 5 release checklist
   end to end.
4. Interleave permitted: the docs-rider bundle, the
   AGP-9/compileSdk-37 unit, and the relay-harness ack-await chore.

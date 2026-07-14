<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- SPDX-FileCopyrightText: 2026 Oculux Technologies LLC -->

# Security Policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately — do not open a public
issue.

- Contact: **oculuxsectech@gmail.com**
  <!-- TODO: switch to security@<final Titlan domain> once the domain is
       secured (work order §10.4), and publish a PGP key. -->
- Include: affected component (`tezca-core`, `tezca-relay`,
  `titlan-android`), version or commit, reproduction steps, and impact
  assessment if you have one.

## Response SLA (placeholder — to be confirmed before first release)

- Acknowledgement: within 3 business days
- Initial assessment: within 10 business days
- Fix or mitigation plan for confirmed critical issues: within 30 days

## Scope notes

- The relay is designed to be blind: it must never receive, parse, store, or
  log sender identity, message plaintext, contact graphs, or PII. Reports
  demonstrating any violation of that property are treated as critical.
- No custom cryptography exists in this codebase by policy; cryptographic
  primitives come from libsignal (and mainstream audited crates such as ring
  or rustls). Reports of any deviation are treated as defects.

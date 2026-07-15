<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- SPDX-FileCopyrightText: 2026 Oculux Technologies LLC -->

# Titlan brand assets

Source imagery for the Titlan mark and wordmark. These are raster (PNG)
concepts; the production pipeline traces a clean vector master from the
line-art source below (see "Vector source"). The user-visible product name is
**Titlan** everywhere (A11); "Oculux Technologies" appears only on the About
screen.

## Files

| File | Contents | Style | Background | Use |
|------|----------|-------|------------|-----|
| `titlan-lockup-vertical-lineart.png` | Mark + `TITLAN` + "ENCRYPTED MESSAGING" | **Flat white line-art** | dark checkerboard (baked) | **Vector-tracing source** — trace the mark for the launcher icon |
| `titlan-mark-render.png` | Mark only (diamond + padlock) | Glossy 3-D render | checkerboard (baked) | Splash / onboarding hero; icon render reference |
| `titlan-lockup-vertical-render-dark.png` | Full vertical lockup | Glossy 3-D render | solid near-black | Dark-theme splash / marketing |
| `titlan-lockup-vertical-render-light.png` | Full vertical lockup | Glossy 3-D render | light | Light-theme marketing |
| `titlan-lockup-horizontal-render-light.png` | Horizontal lockup (mark left, text right) | Glossy 3-D render | light | Wide headers, store banner |

The mark is a faceted diamond/rhombus enclosing a padlock, with a teal edge
glow — "a vault you can see through," matching the blind-relay thesis.

### Vector source

**`titlan-lockup-vertical-lineart.png` is the vector-tracing master.** It is
the only flat, single-colour (white) rendition, so it traces cleanly to SVG.
The launcher icon is derived by tracing the **upper diamond mark** from this
file (drop the wordmark and tagline); the glossy renders are lighting
treatments, not tracing sources.

> **Gotcha — no real transparency.** All five PNGs are 8-bit **RGB with no
> alpha channel**. The "transparent" checkerboards in the line-art and
> mark-render files are *painted in*, not an alpha layer. A truly transparent
> master must come from the SVG trace, not from keying these PNGs.

## Brand palette (design tokens)

Sampled directly from these assets (pure-Python PNG decode, not eyeballed).
Hex values are rounded to clean tokens; use the token names in code.

### Teal (primary accent + edge glow)

| Token | Hex | Role |
|-------|-----|------|
| `titlan-teal-glow` | `#8FF6F8` | hot glow highlight, focus rings |
| `titlan-teal` | `#2ED9DC` | **primary brand teal**, accents on dark |
| `titlan-teal-core` | `#22BEC9` | mid teal, filled controls |
| `titlan-teal-deep` | `#1AA6BC` | tagline / pressed / accent on light |

### Silver (wordmark metal)

| Token | Hex | Role |
|-------|-----|------|
| `titlan-silver-hi` | `#EFEEEE` | highlight, primary text on dark |
| `titlan-silver` | `#DBDBDA` | mid metal, secondary text |
| `titlan-silver-lo` | `#848585` | shadow, disabled / tertiary text |

### Ink & graphite (surfaces, facets)

| Token | Hex | Role |
|-------|-----|------|
| `titlan-ink` | `#050708` | near-black primary surface (dark theme) |
| `titlan-facet` | `#0A1416` | teal-tinted dark facet, elevated surface |
| `titlan-graphite` | `#15191B` | facet edge, dividers, cards |
| `titlan-white` | `#FFFFFF` | line-art, text on teal |

### Usage notes

- Dark theme is the brand default (the renders live on near-black). Teal is
  the single accent — use it sparingly for security-affirmative states
  (verified, encrypted, online), not for chrome.
- `titlan-teal` on `titlan-ink` clears WCAG AA for large text/icons; for body
  text on dark, prefer `titlan-silver-hi`. Verify any teal-on-light pairing
  against AA before shipping — `titlan-teal-deep` is the safer on-light accent.
- These tokens feed the Phase 4 Compose theme (`app.titlan.ui.theme`) and the
  adaptive launcher icon's background/monochrome layers.

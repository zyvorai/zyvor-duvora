# Social cards

Duvora's share card for GitHub's link previews, the console's Open Graph image
(`web/public/duvora-share-card.png`, kept byte-identical to the light card), and any other place a
hero image is needed.

## Palette

Apple-style light/dark, matching the rest of the Zyvor project family:

| | Light | Dark |
|---|---|---|
| Background | `#ffffff` → `#f5f5f7` | `#000000` → `#0b0b0f` |
| Ink (text) | `#1d1d1f` | `#f5f5f7` |
| Secondary text | `#6e6e73` | `#a1a1a6` |
| Card | `#ffffff` / `#d2d2d7` border | `#1c1c1e` / `#3a3a3c` border |
| Blue accent | `#0071e3` → `#2997ff` | `#0a84ff` → `#5eb0ff` |
| Orange accent | `#ff6a2a` (exactly one dot per image, on the `bf3-01` device card) | same |

Fonts: Helvetica Neue (headings/body), Menlo (labels, pills, footer path). The Zyvor "Z" mark is
drawn inline in blue — never the orange brand tile.

## Files

- `build-share-cards.py` — generates the SVG sources from one palette dict.
- `duvora-share-card.svg` / `.png` — 1200×630, light. GitHub Social Preview image and the console's
  `og:image`.
- `duvora-share-card-dark.svg` / `.png` — 1200×630, dark. Used by the README `<picture>` element in
  dark mode.

## Rebuild

```bash
python3 docs/social/build-share-cards.py docs/social
rsvg-convert -w 1200 docs/social/duvora-share-card.svg      -o docs/social/duvora-share-card.png
rsvg-convert -w 1200 docs/social/duvora-share-card-dark.svg -o docs/social/duvora-share-card-dark.png
cp docs/social/duvora-share-card.png web/public/duvora-share-card.png
```

`rsvg-convert` ships with `librsvg` (`brew install librsvg` on macOS).

## Honesty note

Duvora is an evaluation release: it simulates changes and reads inventory, but does not flash
firmware, provision DPUs, or enforce policy on hardware. The card carries an
"EVALUATION RELEASE · SIMULATION-FIRST" line because it gets shared standalone (link previews,
socials) without the README's capability matrix. Do not remove that line, and do not add hardware or
performance claims to the card.

## Manual step: GitHub Social Preview

GitHub's repository Social Preview is **not** settable via the API — upload
`docs/social/duvora-share-card.png` by hand:

Settings → General → Social preview → Edit → upload `docs/social/duvora-share-card.png`.

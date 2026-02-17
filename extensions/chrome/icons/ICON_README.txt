AngelClaw AGI Guardian — Extension Icons

Required icon files (replace these placeholders with actual PNGs):

  icon16.png   — 16x16 px, toolbar icon (small)
  icon48.png   — 48x48 px, extensions page icon
  icon128.png  — 128x128 px, Chrome Web Store / install dialog

Design spec:
  - Shield shape with angel wing motif
  - Primary color: #4f6df5 (blue-violet)
  - Accent: gold halo (#f0c850) at top of shield
  - Clean, modern, minimal — must be legible at 16x16
  - Transparent background (PNG-24 with alpha)

To generate icons from SVG:
  1. Create an SVG at 128x128
  2. Export to PNG at 128, 48, and 16 sizes
  3. Ensure transparency is preserved

For a quick placeholder, use any 16/48/128 PNG or generate via:
  convert -size 128x128 xc:#4f6df5 -fill white -gravity center \
    -pointsize 64 -annotate 0 "AC" icon128.png

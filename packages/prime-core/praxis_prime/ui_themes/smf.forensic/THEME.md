# Forensic Engineering

A lab bench. Light mode is a cool grey page with blueprint blue. Dark mode is graphite with safety amber. Measurements and chain-of-custody identifiers use Praxis Forensic Mono Subset, a subset of IBM Plex Mono. It is monospaced, so the figures line up. The IBM Plex Sans source has no OpenType `tnum` feature, so body text is not forced into tabular figures.

## Colours

The core colours are the Addendum A §1.7 pairs, including the status colours checked by `scripts/contrast_check.py`. `borderStrong` is the muted colour and `ring` is the accent. Both clear 3:1 on the background and on the raised surface, so they were not moved off that core. `accentFg` is white on blueprint blue and the graphite ground on safety amber.

Light: background `#f4f6f8`, raised `#ffffff`, text `#15191d`, muted `#4f5a65`, accent `#0b5c8c`, accent text `#ffffff`. Status: ok `#1f7a45`, warn `#8a5a00`, danger `#b3261e`.

Dark: background `#121416`, raised `#1b1f23`, text `#e6e9ec`, muted `#9aa4ae`, accent `#f2a900`, accent text `#121416`. Status: ok `#5ccf8a`, warn `#f2a900`, danger `#ff6b5e`. The amber accent is also the warn colour. Both pairs clear 4.5:1.

Contrast level is WCAG 2.2 AA in both modes. Optional tokens are derived by the engine.

## Fonts

Display and body are Praxis Forensic Sans Subset (one variable WOFF2, weight 100–700), a Latin subset of IBM Plex Sans. Code is Praxis Forensic Mono Subset regular and bold, a Latin subset of IBM Plex Mono. Plex is a Reserved Font Name, so the subset files do not use it. The sources are the `ofl/` tree of github.com/google/fonts. SIL Open Font License 1.1. The licence text is `assets/fonts/OFL.txt`. The package does not load fonts from a network.

## Ornaments

`assets/ornaments/grid.svg` is an 8 pixel grid. It is the header band, the divider, and the watermark. Watermark opacity is 0.03. The engine paints the watermark as a small corner mark, which is the ornament hook the stylesheet has. There is no extra canvas layer.

## Credits

Font copyrights stay with IBM and are copied in `OFL.txt`. The palette, the grid, and this text are MIT, the same licence as the package `LICENSE`.

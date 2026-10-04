# Medical Office

Calm and clinical. The accent is the medical pack's teal. Motion is `none`. There are no ornaments and no clinical imagery. PHI badges stay on the `info` and `warn` tokens, with a text label. Colour is never the only signal.

## Colours

The core colours are the Addendum A §1.7 pairs. `borderStrong` is the muted colour and `ring` is the accent. Both clear 3:1 on the background and on the raised surface, so they were not moved. `accentFg` is white on the light teal and the dark ground on the lighter teal.

Light: background `#f7fafa`, raised `#ffffff`, text `#10222a`, muted `#46606a`, accent `#0e7490`, accent text `#ffffff`. Status: ok `#1b7a4b`, warn `#8a5a00`, danger `#b42318`.

Dark: background `#0c1a1f`, raised `#13262d`, text `#e8f2f4`, muted `#9db7bf`, accent `#4fc3d9`, accent text `#0c1a1f`. Status: ok `#6fd3a0`, warn `#f2c14e`, danger `#f28b82`.

Contrast level is WCAG 2.2 AA in both modes. Optional tokens are derived by the engine.

## Fonts

Display and body are Inter, the same subset file as `smf.praxis`, copied into this package. That subset keeps the OpenType `tnum` feature. The stylesheet does not turn the feature on, because a theme cannot set `font-feature-settings` on body text. Code is JetBrains Mono, also copied from `smf.praxis`. Both are SIL Open Font License 1.1. The licence text is `assets/fonts/OFL.txt`. The package does not load fonts from a network.

## Credits

Font copyrights stay with their authors and are copied in `OFL.txt`. The palette and this text are MIT, the same licence as the package `LICENSE`.

# Legal Office

Chambers and case reporters. Light mode is parchment and navy. Dark mode is a blue-black ground with a brass accent. Burgundy `#8c1c2b` is the light-mode danger colour only. It is not an accent and it is not used for ordinary text.

## Colours

The core colours are the Addendum A §1.7 pairs. `borderStrong` is the muted colour and `ring` is the accent. Both already clear 3:1 on the background and on the raised surface, so those two tokens were not moved off the core palette. `accentFg` is white on navy and the dark ground on brass.

Light: background `#f7f3ea`, raised `#ffffff`, text `#1b2233`, muted `#4d5566`, accent `#1f3a68`, accent text `#ffffff`. Status: ok `#2e6b3f`, warn `#8a5a00`, danger `#8c1c2b`.

Dark: background `#0f1522`, raised `#172033`, text `#ece6d8`, muted `#a9b0bf`, accent `#c9a45c`, accent text `#0f1522`. Status: ok `#7cc48a`, warn `#e0b04a`, danger `#e57373`.

Contrast level is WCAG 2.2 AA in both modes. Optional tokens are derived by the engine.

## Fonts

Display is Praxis Legal Display Subset, a Latin subset of Libre Baskerville. Body is Praxis Office Sans Subset, a Latin subset of Source Sans 3. Code is Praxis Office Mono Subset, a Latin subset of Source Code Pro. Those upstream names are Reserved Font Names, so the subset files do not use them. Each file is from the `ofl/` tree of github.com/google/fonts. Each family is SIL Open Font License 1.1. The licence text is `assets/fonts/OFL.txt`. The package does not load fonts from a network.

## Ornaments

`assets/ornaments/rule.svg` is a hairline double rule. There is no watermark and no crest.

## Credits

Font copyrights stay with their authors and are copied in `OFL.txt`. The palette, the rule, and this text are MIT, the same licence as the package `LICENSE`.

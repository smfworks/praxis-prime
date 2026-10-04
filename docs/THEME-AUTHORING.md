# Authoring a Praxis Prime theme

A theme package changes colours, type, and ornaments. It does not add controls, run code, or contact the network. The Python validator in `praxis_prime.themes` is the judge. `schemas/theme.v1.json` is the shape you can check before lint. When they disagree, the validator wins, and this guide is written to match the validator.

`praxis-prime theme lint <dir> --json` prints the machine-readable result. `praxis-prime theme pack <dir>` writes `<id>-<version>.praxis-theme.zip` after the same check.

## Checker facts

These lines are compared to the code. Keep the values exact.

- Required colour tokens: bg bgRaised fg fgMuted accent accentFg border borderStrong ring ok warn danger
- Font licences: OFL-1.1, Apache-2.0, MIT, CC0-1.0, Ubuntu-font-1.0
- Package licences: MIT, Apache-2.0, CC-BY-4.0, CC0-1.0
- Zip compressed bytes: 5242880
- Zip expanded bytes: 15728640
- Zip max files: 200
- Zip max file bytes: 4194304
- Ornament max bytes: 262144
- Theme css max bytes: 32768
- Preview max bytes: 1048576
- Text contrast AA: 4.5
- UI contrast AA: 3.0
- Text contrast AAA: 7.0
- UI contrast AAA: 4.5
- Decorative selectors: pp-header-band pp-sidebar-texture pp-divider pp-ornament-[a-z0-9-]+
- SVG elements: circle, defs, desc, ellipse, g, line, lineargradient, path, polygon, polyline, radialgradient, rect, stop, svg, title, use
- SVG banned elements: animate, filter, foreignobject, iframe, image, script, set, style

## Package layout

A package is a directory. Packing it does not follow symlinks.

| Path | Required | Role |
|---|---|---|
| `theme.toml` | yes | Manifest. Schema `praxis.theme/v1`. |
| `THEME.md` | yes | What the theme is for, in plain text. |
| `LICENSE` or `LICENSE.txt` | yes | Package licence text. Non-empty. |
| `theme.css` | no | Restricted decoration only. |
| `NOTICE`, `OFL.txt` | when needed | `OFL.txt` is required at `assets/fonts/OFL.txt` when any font file is bundled under OFL-1.1. |
| `assets/fonts/<name>.woff2` | no | One Latin subset per file. WOFF2 only. |
| `assets/ornaments/<name>.svg` | no | Also `.png` or `.webp`. |
| `assets/preview.png` or `assets/preview.webp` | no | Gallery image. Not a CSS `url()`. |

Every other path is rejected. A name is one segment of letters, digits, `.`, `_`, and `-`. No `..`, no absolute path, no second slash inside `assets/fonts/` or `assets/ornaments/`. Script suffixes (`.js`, `.mjs`, `.cjs`, `.html`, `.htm`, `.wasm`) are rejected.

`id` matches `^[a-z0-9][a-z0-9.-]{0,63}$`. Do not use `smf` or `smf.*`. Those ids are reserved for built-ins. `version` is `MAJOR.MINOR.PATCH`. `name` is at most 80 characters. `description` is at most 400 characters. `license` is one of the package licences above. `contrast` is `AA` (the default) or `AAA`. `modes` must list both `light` and `dark`. `default_mode` is `light`, `dark`, or `system`.

## Tokens

Put colours in `[tokens.light]` and `[tokens.dark]`. `[modes.light]` and `[modes.dark]` are the same tables. Unknown keys are rejected.

### Required colours

Every mode needs the required colour tokens listed above. A missing one fails lint. Do not invent a thirteenth required name.

### Optional colours

Omit these and the validator fills them in OKLCH from the required colours. An author value is kept and then checked. `fgSubtle` is decorative and is not a contrast pair.

| Token | Derivation when omitted |
|---|---|
| `bgSunken` | `bg` with OKLCH lightness shifted by −0.06 |
| `overlay` | `bg` at alpha 0.92 |
| `fgSubtle` | mix of `fgMuted` toward `bg` (weight 0.45) |
| `accentMuted` | mix of `accent` toward `bg` (weight 0.62) |
| `info` | hue 250, chroma 0.12, lightness moved until text contrast on `bg` and `bgRaised` |
| `okFg`, `warnFg`, `dangerFg`, `infoFg` | black or white, then lightness moved until text contrast on that status colour |
| `tool` | hue 190, chroma 0.1, lightness moved until text contrast on `bg` |
| `selection` | mix of `bg` toward `accent` until `fg` clears text contrast |
| `approval` | copy of `accent`, then lightness moved until UI contrast on `bg` |
| `dialOff` | copy of `fgMuted`, then UI contrast on `bg` |
| `dialMonitor` | copy of `warn`, then UI contrast on `bg` |
| `dialEnforce` | copy of `danger`, then UI contrast on `bg` |
| `codeBg` | `bgSunken` when `fg` already clears it, otherwise `bg` |
| `codeFg` | `fg`, lightness moved until text contrast on `codeBg` |
| `syn1` … `syn8` | hues 25, 80, 150, 200, 250, 290, 330, 50 on `codeBg` |

Lightness moves at most 0.25. If a derived colour cannot clear its pair inside that bound, lint fails. Change a required colour. Do not relax the check.

### Colour formats

`#rgb`, `#rgba`, `#rrggbb`, `#rrggbbaa`, or `oklch(L C H)` / `oklch(L C H / alpha)`. Nothing else. Named colours, `rgb()`, `hsl()`, `var()`, and `url()` are not colours.

### Contrast

Checked after derivation, separately for `light` and for `dark`.

Text pairs need the text floor (4.5 at AA, 7.0 at AAA):

- `fg` and `fgMuted` on `bg` and on `bgRaised`
- `accentFg` on `accent`
- `ok`, `warn`, `danger`, `info`, and `tool` on `bg` (status and `info` also on `bgRaised`)
- `okFg` on `ok`, `warnFg` on `warn`, `dangerFg` on `danger`, `infoFg` on `info`
- `codeFg` and `syn1` … `syn8` on `codeBg`
- `fg` on `selection`

UI pairs need the UI floor (3.0 at AA, 4.5 at AAA):

- `borderStrong`, `ring`, and `accent` on `bg` and on `bgRaised`
- `approval`, `dialOff`, `dialMonitor`, and `dialEnforce` on `bg`

`border` itself is not a contrast pair. `borderStrong` is.

### Type, shape, ornaments

`[fonts.display]`, `[fonts.body]`, and `[fonts.mono]` each take `family`, `fallback` (`serif`, `sans-serif`, or `monospace`), `license`, and `files`. An empty `files` list uses the generic fallback and does not need `OFL.txt`. A file entry is `{ path, weight, style }`. `weight` is `400` or `100 900` (one or two CSS weights). `style` is `normal` or `italic`. The same file may be named by display and body.

`[shape]` defaults, and the accepted ranges:

| Key | Default | Range |
|---|---|---|
| `scale` | 1.25 | 1.125–1.333 |
| `baseSize` | 16 | 15–18 |
| `lineHeight` | 1.5 | 1.2–2.0 |
| `radius` | 6 | 0–16 |
| `density` | `cozy` | `compact`, `cozy`, `comfortable` |
| `borderWidth` | 1 | 1–4 |
| `motion` | `subtle` | `none`, `subtle`, `standard` |

`[ornaments]` keys are `header`, `divider`, and `watermark`. Each value is `assets/ornaments/<name>.svg` (or `.png` / `.webp`). `watermarkOpacity` is 0–0.06. The SPA paints the watermark. A theme does not add a new hook.

## Fonts

Bundle a font only when its licence is on the font allowlist above. Prefer a subset WOFF2 from the `ofl/` tree of `google/fonts`. Do not hot-link a font host and do not put a remote URL in `theme.toml`, `theme.css`, or an SVG. Ship the licence text beside the files. For OFL-1.1 the file is `assets/fonts/OFL.txt` and it must contain the words `SIL Open Font License`. One `OFL.txt` may concatenate several families. The package `LICENSE` stays the package licence. Fonts are not relicensed.

Each family keeps its own copyright. Record it where the project asks (for a built-in, `CREDITS.md` and `THIRD_PARTY.md` in the same change as the file).

## theme.css

Optional. Parsed with tinycss2. At most 32 KiB. Comments are dropped. The served stylesheet is generated from the token maps. Custom properties in `theme.css` update those maps. They are not copied into the served CSS.

Allowed selectors, exactly one per rule, with no combinator and no comma:

- `:root`
- `:root[data-mode=light]`, `:root[data-mode=dark]`, and the same with single or double quotes
- `[data-mode=light]` and `[data-mode=dark]`, quoted or not
- `.pp-header-band`
- `.pp-sidebar-texture`
- `.pp-divider`
- `.pp-ornament-` plus lowercase letters, digits, and hyphens

On `:root` and `[data-mode]`, the only declarations are `--pp-*` tokens that exist (`--pp-bg`, `--pp-fontBody`, and the rest of the colour and type names). A colour token must be a colour. `density` must be one of the three names. `motion` must be one of the three names.

On a decorative selector the allowed properties are: `color`, `background`, `background-color`, `background-image`, `background-repeat`, `background-position`, `background-size`, `border`, `border-color`, `border-style`, `border-width`, the four `border-top` / `border-right` / `border-bottom` / `border-left` shorthands and their `-color`, `-style`, and `-width` longhands, `border-radius` and the four corner radii, `box-shadow`, `letter-spacing`, `text-transform`, `font-feature-settings`.

Rejected, from the raw scan and the parser:

- `@import`, `@font-face`, `@namespace`, and every other at-rule
- `javascript:`, `expression(`, `!important`, `:has(`
- any selector containing `.pp-approval`, `.pp-dial`, or `.pp-audit`
- `http://`, `https://`, `data:`, and a `url()` that contains `//`
- properties `content`, `display`, `visibility`, `opacity`, `position`, `z-index`, `transform`, `pointer-events`, `clip`, `clip-path`, `filter`, any property whose name starts with `clip` or `animation`
- any function other than `oklch()` and `url()`
- attribute selectors, combinators, and selector lists

`url()` is allowed only on a decorative selector. The target is a file in the package, not the preview image, not `..`, and not an absolute or scheme URL. Decorative lengths are `px` only, from 0 to 16. Shadow offsets may be −16px to 16px. Percentages, viewport units, `calc()`, and `var()` on those properties are rejected.

## SVG ornaments

The sanitizer re-serializes a clean SVG. Store that output if you need the bytes to stay stable. The root is an `svg` element in the SVG namespace `http://www.w3.org/2000/svg`. `http://www.w3.org/1999/xlink` is only for `xlink:` attributes. Every element is in the SVG namespace. Tag names are compared in lowercase against the element list in the checker facts. The banned list is refused even if someone adds it to a drawing.

Also refused: a DOCTYPE, a comment, an `ENTITY`, a processing instruction other than one leading XML declaration, an event-handler attribute (`on…`), a `style` attribute, a backslash in an attribute value, a foreign namespace other than `xlink`, and a paint value whose `url()` is anything but a same-document `#id`. `javascript:` and `data:` are checked on the entity-decoded value. `image-set()` and `src()` are refused.

Allowed attributes include `xmlns`, `viewBox`, geometry (`x`, `y`, `width`, `height`, `cx`, `cy`, `r`, `rx`, `ry`, `d`, `points`, and the `x1`–`y2` pairs), `fill`, `stroke`, the stroke longhands on the allowlist, gradient attributes (`offset`, `stop-color`, `stop-opacity`, `gradientUnits`, `gradientTransform`), `id`, `href`, `xlink:href`, `role`, and `aria-*`. `opacity` is not an allowed SVG attribute. Use `watermarkOpacity` in `theme.toml` for the watermark.

`href` and `xlink:href` may point at a `#id` in the same file. They may not point at a remote URL.

## Preview image and zip limits

`assets/preview.png` or `assets/preview.webp` only. Magic bytes are checked. The cap is the preview max in the checker facts. The served stylesheet does not mention that path. It is served at `GET /themes/<id>/<hash>/assets/preview.png` (or `.webp`) with the SPA Content-Security-Policy.

Zip limits, in bytes unless noted, are the checker facts: 5 MiB compressed, 15 MiB expanded, 200 files, 4 MiB per file, 256 KiB per ornament, 32 KiB for `theme.css`, 1 MiB for the preview. Absolute paths, `..`, symlinks, encrypted entries, duplicate names, and a damaged zip are refused.

## Recipe

1. Create a directory with `theme.toml`, `THEME.md`, and `LICENSE`.
2. Set `schema = "praxis.theme/v1"`, an `id` that is not `smf` or `smf.*`, `name`, `version`, `license`, `authors`, `description`, and both modes.
3. Write the required colours for `light` and `dark`. Use the formats above. Set `[shape]` if you need a size, radius, density, or motion other than the defaults.
4. Add WOFF2 files only under an allowlisted licence, plus `assets/fonts/OFL.txt` when the licence is OFL-1.1. Or skip `files` and use the generic fallbacks.
5. Add ornaments only if they pass the SVG rules. Point `[ornaments]` at those files. Keep `watermarkOpacity` at or below 0.06.
6. Run `praxis-prime theme lint <dir> --json`. Fix every issue in `error.issues`. Each issue has `code`, `message`, optional `path`, and optional `fix`. A passing run prints `{"ok": true, "id", "version", "contrast"}`.
7. Run `praxis-prime theme pack <dir>`. Install with `praxis-prime theme install <zip>`. `theme set <id> --mode light|dark|system` selects it for a profile.

A contrast failure names the mode, the two tokens, the ratio, and the floor. Change a colour. Do not add a selector that hides a control to make a pair look better.

## Worked example

Calm mint, no bundled fonts, no ornament. Both modes use colours that already clear AA. Copy the three files into an empty directory and lint it.

```text
# theme.toml
schema = "praxis.theme/v1"
id = "lab.calm-mint"
name = "Calm mint"
version = "1.0.0"
license = "MIT"
authors = ["Example Author"]
description = "A calm mint example for a dental office. No bundled fonts."
modes = ["light", "dark"]
default_mode = "light"
min_praxis = "0.1.0"
contrast = "AA"

[shape]
radius = 12
density = "comfortable"
motion = "subtle"
baseSize = 16

[tokens.light]
bg = "#f6fbfa"
bgRaised = "#ffffff"
fg = "#12302c"
fgMuted = "#4a6661"
accent = "#0f766e"
accentFg = "#ffffff"
border = "#cde5e1"
borderStrong = "#4a6661"
ring = "#0f766e"
ok = "#1b7a4b"
warn = "#8a5a00"
danger = "#b42318"

[tokens.dark]
bg = "#0d1b1a"
bgRaised = "#142826"
fg = "#e9f6f4"
fgMuted = "#9fc2bc"
accent = "#5eead4"
accentFg = "#0d1b1a"
border = "#24403c"
borderStrong = "#9fc2bc"
ring = "#5eead4"
ok = "#86efac"
warn = "#fcd34d"
danger = "#f28b82"
```

```text
# THEME.md
# Calm mint

A worked example for a dental office. Colours are mint and ink. There is no clinical imagery and no bundled font. The package text is MIT.
```

```text
# LICENSE
MIT License

Copyright (c) 2026 the theme author

Permission is hereby granted, free of charge, to any person obtaining a copy of this theme package to deal in the package without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the package, and to permit persons to whom the package is furnished to do so, subject to the license conditions. The package is provided as is, without warranty of any kind.
```

Lint that directory. Optional colours are derived. Both modes must come back clean before you pack.

## What a theme cannot do

No JavaScript, no HTML, no WASM, no remote URL, no `@import`, no new UI, no selector aimed at approval, dial, or audit controls. System (Omarchy) is not a package. It is the rendered file the adapter reads when a profile chooses it, and that palette still has to pass this validator.

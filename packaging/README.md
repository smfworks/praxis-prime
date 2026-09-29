# Packaging

Placeholders for the layout in ARCHITECTURE §27. No package is built or published by CI.

| Path | What it will become |
|---|---|
| `deb/` | Debian source package (`debian/` control files) |
| `apt-repo/` | Signed APT repository notes |
| `appimage/` | Tauri AppImage notes |
| `aur/` | `praxis-prime-git` / `praxis-prime-bin` PKGBUILD notes |
| `flatpak/` | Later UI-only Flatpak notes |
| `systemd/` | `systemd --user` units |

The Python package installs `praxis-prime`, `pprime`, and `praxis-primed` with pip. That is the only install path that works today.

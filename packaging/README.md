# Packaging

Local installers live next to the layout in ARCHITECTURE §27. Nothing here is published. There is no APT repository and no AUR submission. `get.smfworks.com` and `apt.smfworks.com` are not live.

| Path | What it is |
|---|---|
| `deb/` | Debian binary package. `deb/build-deb.sh` builds a `.deb` with `dpkg-deb` and no root. |
| `aur/` | `praxis-prime-git` PKGBUILD. `praxis-prime-bin` is a note until a release tarball exists. |
| `systemd/` | `systemd --user` units. Packages copy them to `/usr/lib/systemd/user/` and do not enable them. |
| `apt-repo/` | Signed APT repository notes. Not a running repo. |
| `appimage/` | Tauri AppImage notes. Not built. |
| `flatpak/` | Later UI-only Flatpak notes. Not built. |

A development checkout can still use pip. See the repository README.

# Packaging

Local installers live next to the layout in ARCHITECTURE §27. Nothing here is published. There is no APT repository and no AUR submission. `get.smfworks.com` and `apt.smfworks.com` are not live.

| Path | What it is |
|---|---|
| `deb/` | Debian binary package. `deb/build-deb.sh` builds a `.deb` with `dpkg-deb` and no root. |
| `aur/` | `praxis-prime-git` PKGBUILD. `praxis-prime-bin` is a note until a release tarball exists. |
| `systemd/` | `systemd --user` units. Packages install `praxis-prime.service` and `praxis-prime-workers.slice` to `/usr/lib/systemd/user/` and do not enable them. Stub units stay in the repo. |
| `requirements-runtime.txt` | Hashed runtime pins from `uv.lock`, for the `.deb` pip fallback and the PKGBUILD. |
| `apt-repo/` | Signed APT repository notes. Not a running repo. |
| `appimage/` | Tauri AppImage notes. Not built. |
| `flatpak/` | Later UI-only Flatpak notes. Not built. |

A development checkout can still use pip. See the repository README.

The six regulated packs ship in the main package as wheel data (`packs/regulated` → `praxis_prime/_data/packs/regulated`). There is no `praxis-prime-packs` package. Compliance dials stay off.

## Regenerating hashed runtime requirements

`packaging/requirements-runtime.txt` is the locked runtime set with hashes. The `.deb` build prefers `uv export` from `uv.lock` at build time. The pip fallback and the PKGBUILD install this file with `pip install --require-hashes`, then the project wheel with `--no-deps`. After `uv.lock` changes, regenerate the file from the repository root:

```bash
unset XAI_API_KEY
uv export --frozen --no-dev --no-emit-project --no-header \
  -o packaging/requirements-runtime.txt
```

Do not resolve those dependencies without hashes. The `.deb` and AUR packages bundle the resulting wheels under each project's own license. See [CREDITS.md](../CREDITS.md) and [THIRD_PARTY.md](../THIRD_PARTY.md). `python-licenses.txt` is generated when the package is built.

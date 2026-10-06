# Debian packaging

`praxis-prime` is a local binary package. It is **not** in the Ubuntu archive, and there is no APT repository. `get.smfworks.com` and `apt.smfworks.com` are not live. The maintainer address `maintainers@praxis-prime.invalid` is a placeholder on the reserved `.invalid` domain and does not receive mail.

The supported build is [`build-deb.sh`](build-deb.sh). It does not use debhelper and does not need root. `debian/rules` only points at that script.

## What the package contains

Architecture is the **build host**, not `all`. On Ubuntu 24.04 x86_64 that is `amd64`. `cryptography` and `argon2-cffi` (and their transitive native wheels) are compiled extensions, so a package built on one architecture will not run on another. The virtualenv's `python` symlink points at the system interpreter used for the build, and the binary `Depends` on that package (`python3.12` when built with `/usr/bin/python3.12`).

| Path | Role |
|---|---|
| `/opt/praxis-prime` | Virtualenv: Praxis Prime plus the locked runtime wheels (`argon2-cffi`, `cryptography`, `joserfc`, `pyotp`, `tinycss2`, `webauthn`, and their dependencies). `textual` is not installed. pip is not installed. |
| `/usr/bin/praxis-prime`, `/usr/bin/pprime`, `/usr/bin/praxis-primed` | Symlinks into `/opt/praxis-prime/bin`. |
| `/usr/lib/systemd/user/` | `praxis-prime.service` and `praxis-prime-workers.slice` only. Stub units stay in [`../systemd`](../systemd). Not enabled. Linger is not enabled. There are no maintainer scripts. |
| `/usr/share/doc/praxis-prime/` | `copyright`, `LICENSE`, `NOTICE`, `CREDITS.md`, `THIRD_PARTY.md`, `THIRD_PARTY_NOTICES.md`, `changelog.Debian.gz`, and `python-licenses.txt`. |

`praxis-prime service install` is still the supported way to enable the user daemon. It copies a unit into the user config directory and does not enable linger. The copies under `/usr/lib/systemd/user/` are there so `systemctl --user` can see them. Nothing in the package starts the daemon.

The package Depends on the interpreter it was built against and on `bubblewrap`.

The optional Textual TUI stays out of the package, and so does pip. After install, bootstrap pip from the standard library and then install the extra. On Debian and Ubuntu, `ensurepip` is in the matching `python3.X-venv` package (for example `python3.12-venv`):

```bash
/opt/praxis-prime/bin/python -m ensurepip --upgrade
/opt/praxis-prime/bin/python -m pip install 'textual>=8.2,<9'
```

## Build (no sudo)

From the repository root, on Ubuntu 24.04 with Python 3.12 and `dpkg-deb`:

```bash
packaging/deb/build-deb.sh --help
packaging/deb/build-deb.sh --dry-run
packaging/deb/build-deb.sh
```

`uv` is preferred. The script exports the locked runtime set from `uv.lock` and checks hashes. Without `uv`, it falls back to `python3 -m pip wheel` and a stdlib virtualenv (`python3-venv` and `python3-pip`), then installs [`../requirements-runtime.txt`](../requirements-runtime.txt) with `pip install --require-hashes`. That file is generated from `uv.lock`. Regenerate it after a lock change; see [../README.md](../README.md). The fallback does not resolve unpinned dependencies from PyPI. The script does not run `sudo` to install those tools.

The build refuses a dirty git tree (`git status --porcelain`). `--dry-run` does not check. Pass `--allow-dirty` to build anyway.

The interpreter must resolve to `/usr/bin/python3.X`. A pyenv or uv-managed interpreter under a home directory is refused so the package does not embed a user path.

```bash
packaging/deb/build-deb.sh --python /usr/bin/python3.12
```

Output: `dist/praxis-prime_0.1.0_amd64.deb` (version from `packages/prime-core/praxis_prime/__init__.py`, architecture from `dpkg --print-architecture`). `dist/` is gitignored.

Inspect it:

```bash
dpkg-deb -I dist/praxis-prime_0.1.0_amd64.deb
dpkg-deb -c dist/praxis-prime_0.1.0_amd64.deb
```

## Install (needs sudo; the build script does not do this)

```bash
sudo apt install ./dist/praxis-prime_0.1.0_amd64.deb
```

Or:

```bash
sudo dpkg -i dist/praxis-prime_0.1.0_amd64.deb
sudo apt-get install -f
```

Then, if you want the daemon for your user:

```bash
praxis-prime service install
```

## nfpm

[ARCHITECTURE §23](../../docs/ARCHITECTURE.md) allows nfpm as another way to assemble the `.deb`. This tree uses `dpkg-deb` staging because `dpkg-deb` is already on a normal Ubuntu system. An nfpm config is not required for the build.

## Not in this package

The six regulated packs ship in this package as wheel data at `praxis_prime/_data/packs/regulated`. Dials stay off. There is no separate `praxis-prime-packs` package. Desktop (Tauri), voice, an APT repository, AppImage, and Flatpak are follow-ups. See [`../apt-repo`](../apt-repo), [`../appimage`](../appimage), and [`../flatpak`](../flatpak).

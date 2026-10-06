# AUR

`packaging/aur/PKGBUILD` builds **`praxis-prime-git`**. It is **not submitted to the AUR**. Do not `yay -S praxis-prime-git` and do not `yay -S praxis-prime-bin`. Whether Basecamp accepts a package into pkgs.omarchy.org is still an open question (ARCHITECTURE §31).

The maintainer address `maintainers@praxis-prime.invalid` does not receive mail.

## What it installs

`makepkg` builds a wheel and installs it into a virtualenv at `/opt/praxis-prime`. Runtime dependencies come from `packaging/requirements-runtime.txt` with `pip install --require-hashes`, then the project wheel with `--no-deps`. `joserfc` and `webauthn` are not assumed to exist as pacman packages, so the PKGBUILD does not use `python -m installer --destdir` for the runtime tree. `python-installer` stays in `makedepends` for the standard wheel toolchain. pip is removed from the virtualenv before the package is finished.

| Path | Role |
|---|---|
| `/opt/praxis-prime` | Virtualenv. Locked runtime wheels are bundled here. The six regulated packs ship inside the project wheel at `praxis_prime/_data/packs/regulated`. `textual` is not installed. pip is not installed. |
| `/usr/bin/praxis-prime`, `/usr/bin/pprime`, `/usr/bin/praxis-primed` | Symlinks into that virtualenv. |
| `/usr/lib/systemd/user/` | `praxis-prime.service` and `praxis-prime-workers.slice` only. Stub units stay in [`../systemd`](../systemd). Not enabled. Linger is not enabled. There is no `.install` script. |
| `/usr/share/licenses/praxis-prime-git/` | `LICENSE`, `NOTICE`, `CREDITS.md`, `THIRD_PARTY.md`, `THIRD_PARTY_NOTICES.md`, `copyright`, and `python-licenses.txt` (generated at package build time from each wheel's `METADATA`). |

`arch=('x86_64' 'aarch64')`. `makepkg` builds on that machine, so the native wheels match it. This is not a prebuilt binary. The virtualenv embeds the ABI of the `python` used at build time. After an Arch Python minor bump (3.12 to 3.13, and so on), rebuild and reinstall the package. `depends` stays `python>=3.12` plus `bubblewrap`; the rebuild is what tracks the new ABI. Runtime wheels come from [`../requirements-runtime.txt`](../requirements-runtime.txt) installed with `--require-hashes`, then the project wheel with `--no-deps`.

`provides=('praxis-prime')` and `conflicts=('praxis-prime-bin')`.

Enable the daemon the same way as on Ubuntu, after install:

```bash
praxis-prime service install
```

That command does not enable linger.

Optional Textual TUI, after install. The package does not ship pip. Bootstrap it, then install the extra:

```bash
/opt/praxis-prime/bin/python -m ensurepip --upgrade
/opt/praxis-prime/bin/python -m pip install 'textual>=8.2,<9'
```

## Build on Arch from this checkout

`makepkg` is not available on Ubuntu. On Arch or Omarchy, build the committed checkout (a `file://` clone does not see uncommitted files):

```bash
repo=$(git rev-parse --show-toplevel)
mkdir -p /tmp/praxis-prime-aur
cd /tmp/praxis-prime-aur
cp "$repo/packaging/aur/PKGBUILD" .
sed -i "s|git+https://github.com/smfworks/praxis-prime.git|git+file://${repo}|" PKGBUILD
makepkg -si
```

After this PKGBUILD is on the default branch, the GitHub source line works without the `sed`:

```bash
git clone https://github.com/smfworks/praxis-prime.git
cd praxis-prime/packaging/aur
makepkg -si
```

`makepkg` needs network access to fetch the runtime wheels from PyPI. It does not publish the package.

Check the recipe without Arch:

```bash
bash -n packaging/aur/PKGBUILD
```

## `praxis-prime-bin` (not implemented)

A future `praxis-prime-bin` package would install a versioned release tarball (or a built `.deb`-equivalent tree) and would name a real architecture. It waits on that artifact. Do not add the name to the AUR before the tarball exists.

## Not in this package

The six regulated packs are in the main package, not a separate `praxis-prime-packs` package. After the package is installed, `praxis-prime omarchy install` writes the theme template and the Hyprland keybind. The Quickshell bar plugin is still a follow-up. See [apps/omarchy](../../apps/omarchy) and [docs/USAGE.md](../../docs/USAGE.md).

# AUR

`packaging/aur/PKGBUILD` builds **`praxis-prime-git`**. It is **not submitted to the AUR**. Do not `yay -S praxis-prime-git` and do not `yay -S praxis-prime-bin`. Whether Basecamp accepts a package into pkgs.omarchy.org is still an open question (ARCHITECTURE §31).

The maintainer address `maintainers@praxis-prime.invalid` does not receive mail.

## What it installs

`makepkg` builds a wheel and installs it, with PyPI runtime dependencies, into a virtualenv at `/opt/praxis-prime`. `joserfc` and `webauthn` are not assumed to exist as pacman packages, so the PKGBUILD does not use `python -m installer --destdir` for the runtime tree. `python-installer` stays in `makedepends` for the standard wheel toolchain.

| Path | Role |
|---|---|
| `/opt/praxis-prime` | Virtualenv. `textual` is not installed. |
| `/usr/bin/praxis-prime`, `/usr/bin/pprime`, `/usr/bin/praxis-primed` | Symlinks into that virtualenv. |
| `/usr/lib/systemd/user/` | Units from [`../systemd`](../systemd). Not enabled. Linger is not enabled. There is no `.install` script. |
| `/usr/share/licenses/praxis-prime-git/` | `LICENSE`, `NOTICE`, `THIRD_PARTY.md`, `THIRD_PARTY_NOTICES.md`. |

`arch=('any')` means each person builds on their own machine, so the native wheels match that machine. This is not a prebuilt binary.

`provides=('praxis-prime')` and `conflicts=('praxis-prime-bin')`.

Enable the daemon the same way as on Ubuntu, after install:

```bash
praxis-prime service install
```

That command does not enable linger.

Optional Textual TUI, after install:

```bash
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

The Omarchy theme template, Hyprland keybind, Quickshell bar plugin, and `praxis-prime omarchy install` are follow-ups. See [apps/omarchy](../../apps/omarchy).

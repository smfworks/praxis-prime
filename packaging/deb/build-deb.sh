#!/usr/bin/env bash
# Build a local praxis-prime .deb without debhelper and without root.
# Installing the result may need sudo. This script never calls sudo,
# never enables systemd units, and never enables linger.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd "$SCRIPT_DIR/../.." && pwd)

unset XAI_API_KEY
unset PIP_INDEX_URL PIP_EXTRA_INDEX_URL UV_INDEX UV_INDEX_URL UV_EXTRA_INDEX_URL UV_DEFAULT_INDEX
export UV_NO_MANAGED_PYTHON=1
export UV_PYTHON_DOWNLOADS=never
export PYTHONNOUSERSITE=1
export TMPDIR=/tmp
umask 022

usage() {
  cat <<'EOF'
Usage: packaging/deb/build-deb.sh [--dry-run] [--output-dir DIR] [--python PATH]

Build a Debian binary package for Praxis Prime. The build does not need
root or debhelper. It stages a virtual environment under /opt/praxis-prime
using the system Python (3.12+), links praxis-prime, pprime, and
praxis-primed into /usr/bin, and copies systemd user units to
/usr/lib/systemd/user. Units are not enabled. Linger is not enabled.

The package architecture is the build host (amd64 on Ubuntu 24.04 x86_64).
cryptography and argon2-cffi ship compiled extensions, so the package is
not Architecture: all.

Requires: dpkg-deb, and either uv (preferred; installs locked hashes) or
python3-venv plus python3-pip. This script does not install those itself.

Options:
  -h, --help           Show this help and exit.
  -n, --dry-run        Print version, architecture, and output path. Do not
                       download, stage, or write a .deb.
  --output-dir DIR     Directory for the .deb (default: <repo>/dist).
  --python PATH        System interpreter to link (default: /usr/bin/python3).
                       Must resolve to /usr/bin/python3.X.

Install the result yourself (this script does not):
  sudo apt install ./dist/praxis-prime_<version>_<arch>.deb
  # or: sudo dpkg -i ./dist/praxis-prime_<version>_<arch>.deb && sudo apt-get install -f

The maintainer address maintainers@praxis-prime.invalid does not receive mail.
The package is not published to an APT repository.
EOF
}

die() {
  echo "build-deb.sh: $*" >&2
  exit 1
}

read_version() {
  local init="$ROOT/packages/prime-core/praxis_prime/__init__.py"
  local version
  version=$(sed -n 's/^__version__ = "\([^"]*\)"/\1/p' "$init")
  [[ -n "$version" ]] || die "could not read __version__ from $init"
  printf '%s\n' "$version"
}

resolve_python() {
  local requested=${1:-}
  local candidate real minor
  if [[ -n "$requested" ]]; then
    candidate=$requested
  else
    candidate=/usr/bin/python3
  fi
  [[ -x "$candidate" ]] || die "python interpreter is not executable: $candidate"
  real=$(readlink -f "$candidate")
  case "$real" in
    /usr/bin/python3.*) ;;
    *) die "refusing interpreter outside /usr/bin ($real). Pass --python /usr/bin/python3.12" ;;
  esac
  minor=$("$real" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 12) else 1)') \
    || die "python >= 3.12 required ($real)"
  printf '%s\n' "$real"
}

dry_run=0
output_dir=""
python_arg=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
    -n|--dry-run)
      dry_run=1
      shift
      ;;
    --output-dir)
      [[ $# -ge 2 ]] || die "--output-dir needs a directory"
      output_dir=$2
      shift 2
      ;;
    --python)
      [[ $# -ge 2 ]] || die "--python needs a path"
      python_arg=$2
      shift 2
      ;;
    *)
      echo "build-deb.sh: unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

version=$(read_version)
python=$(resolve_python "$python_arg")
command -v dpkg-deb >/dev/null 2>&1 || die "dpkg-deb is required"
command -v dpkg >/dev/null 2>&1 || die "dpkg is required"
arch=$(dpkg --print-architecture)
py_pkg=$(basename "$python")
output_dir=${output_dir:-$ROOT/dist}
deb_name="praxis-prime_${version}_${arch}.deb"
deb_path="$output_dir/$deb_name"

if [[ "$dry_run" -eq 1 ]]; then
  cat <<EOF
dry-run: not writing a .deb
version: $version
architecture: $arch
python: $python
depends: $py_pkg
prefix: /opt/praxis-prime
commands: /usr/bin/praxis-prime /usr/bin/pprime /usr/bin/praxis-primed
units: /usr/lib/systemd/user
output: $deb_path
dpkg-deb: skipped
EOF
  exit 0
fi

if command -v uv >/dev/null 2>&1; then
  builder=uv
elif "$python" -m venv --help >/dev/null 2>&1 && "$python" -m pip --version >/dev/null 2>&1; then
  builder=pip
else
  die "need uv, or python3-venv and python3-pip. This script does not call sudo."
fi

work=$(mktemp -d /tmp/praxis-prime-deb.XXXXXX)
cleanup() {
  rm -rf "$work"
}
trap cleanup EXIT

stage="$work/stage"
venv="$stage/opt/praxis-prime"
wheel_dir="$work/wheel"
mkdir -p "$wheel_dir" "$output_dir"

echo "building wheel with $builder" >&2
if [[ "$builder" == uv ]]; then
  uv --no-config build --wheel --python "$python" --no-python-downloads \
    --no-create-gitignore --out-dir "$wheel_dir" "$ROOT"
else
  export PIP_CACHE_DIR="$work/pip-cache"
  export PIP_DISABLE_PIP_VERSION_CHECK=1
  export PIP_CONFIG_FILE=/dev/null
  "$python" -m pip wheel --no-deps --wheel-dir "$wheel_dir" "$ROOT"
fi

wheel=$(find "$wheel_dir" -maxdepth 1 -type f -name '*.whl' -print)
[[ -n "$wheel" && ! "$wheel" == *$'\n'* ]] || die "expected one wheel in $wheel_dir"

echo "creating virtualenv at staging $venv" >&2
if [[ "$builder" == uv ]]; then
  uv --no-config venv "$venv" --python "$python" --no-python-downloads --no-managed-python
  req="$work/requirements.txt"
  uv --no-config export --frozen --no-dev --no-emit-project --no-header \
    --directory "$ROOT" --python "$python" \
    --default-index https://pypi.org/simple \
    --output-file "$req" >/dev/null
  uv --no-config pip install --python "$venv/bin/python" --no-cache --require-hashes \
    --default-index https://pypi.org/simple -r "$req"
  uv --no-config pip install --python "$venv/bin/python" --no-cache --no-deps \
    --offline "$wheel"
  uv --no-config pip install --python "$venv/bin/python" --no-cache \
    --default-index https://pypi.org/simple pip
else
  "$python" -m venv "$venv"
  "$venv/bin/pip" install --disable-pip-version-check --no-cache-dir --no-compile \
    --index-url https://pypi.org/simple "$wheel"
fi

find "$venv" -type d -name '__pycache__' -print0 | xargs -0 -r rm -rf
find "$venv" -type f -name '*.pyc' -delete
find "$venv" -type f -name 'direct_url.json' -delete
rm -f "$venv/.gitignore" "$venv/.lock" "$venv/CACHEDIR.TAG"
find "$venv" -type d -exec chmod 0755 {} +
find "$venv" -type f -exec chmod 0644 {} +
find "$venv/bin" -type f -exec chmod 0755 {} +

echo "rewriting staged paths to /opt/praxis-prime" >&2
while IFS= read -r -d '' file; do
  if grep -I -q -F "$venv" "$file"; then
    sed -i "s|$venv|/opt/praxis-prime|g" "$file"
  fi
done < <(find "$venv" -type f -print0)

for cmd in praxis-prime pprime praxis-primed; do
  [[ -x "$venv/bin/$cmd" ]] || die "missing entry point: $cmd"
  shebang=$(head -n 1 "$venv/bin/$cmd")
  [[ "$shebang" == '#!/opt/praxis-prime/bin/python'* ]] \
    || die "entry point $cmd does not use the /opt/praxis-prime shebang"
done

bindir="$stage/usr/bin"
mkdir -p "$bindir"
for cmd in praxis-prime pprime praxis-primed; do
  ln -s "/opt/praxis-prime/bin/$cmd" "$bindir/$cmd"
done

unit_dest="$stage/usr/lib/systemd/user"
mkdir -p "$unit_dest"
found_unit=0
while IFS= read -r -d '' unit; do
  cp -a "$unit" "$unit_dest/"
  found_unit=1
done < <(find "$ROOT/packaging/systemd" -maxdepth 1 -type f \
  \( -name '*.service' -o -name '*.timer' -o -name '*.slice' \) -print0)
[[ "$found_unit" -eq 1 ]] || die "no systemd units under packaging/systemd"

doc="$stage/usr/share/doc/praxis-prime"
mkdir -p "$doc"
cp -a "$ROOT/LICENSE" "$ROOT/NOTICE" "$ROOT/THIRD_PARTY.md" "$ROOT/THIRD_PARTY_NOTICES.md" "$doc/"
cp -a "$SCRIPT_DIR/debian/copyright" "$doc/copyright"
gzip -n -c "$SCRIPT_DIR/debian/changelog" > "$doc/changelog.Debian.gz"
{
  echo "Third-party Python distributions installed under /opt/praxis-prime."
  echo "Each project keeps its own license in its dist-info directory."
  echo "Generated at package build time from METADATA."
  echo
  while IFS= read -r -d '' meta; do
    name=$(sed -n 's/^Name: //p' "$meta" | head -n 1)
    ver=$(sed -n 's/^Version: //p' "$meta" | head -n 1)
    lex=$(sed -n 's/^License-Expression: //p' "$meta" | head -n 1)
    lic=$(sed -n 's/^License: //p' "$meta" | head -n 1)
    printf '%s %s %s\n' "$name" "$ver" "${lex:-$lic}"
  done < <(find "$venv/lib" -path '*.dist-info/METADATA' -print0 | sort -z)
} > "$doc/python-licenses.txt"

# cryptography's SSH parser mentions the OpenSSH banner as a Python literal.
# Only a line that is the banner itself is treated as key material.
while IFS= read -r -d '' file; do
  base=$(basename "$file")
  case "$base" in
    secrets.env|secrets.env.age|id_rsa|id_ed25519)
      die "refusing to pack $file"
      ;;
  esac
  if grep -I -q -F -e "$work" -e '/home/' "$file"; then
    die "refusing to pack a staging path or a /home path in $file"
  fi
  if grep -I -q -E '^-----BEGIN (OPENSSH )?PRIVATE KEY-----$' "$file"; then
    die "refusing to pack a private key in $file"
  fi
done < <(find "$stage" -type f -print0)
while IFS= read -r -d '' link; do
  target=$(readlink "$link")
  case "$target" in
    /home/*|"$work"*|"$stage"*) die "symlink escapes the package prefix: $link -> $target" ;;
  esac
done < <(find "$stage" -type l -print0)

control="$stage/DEBIAN/control"
mkdir -p "$stage/DEBIAN"
installed_kb=$(du -sk --exclude=DEBIAN "$stage" | cut -f1)
cat > "$control" <<EOF
Package: praxis-prime
Version: $version
Architecture: $arch
Maintainer: SMF Works <maintainers@praxis-prime.invalid>
Section: python
Priority: optional
Homepage: https://github.com/smfworks/praxis-prime
Installed-Size: $installed_kb
Depends: $py_pkg
Description: local-first autonomous AI agent
 Praxis Prime is a local-first autonomous AI agent for Linux (pre-alpha).
 This package installs a virtual environment at /opt/praxis-prime and puts
 praxis-prime, pprime, and praxis-primed on PATH.
 .
 The optional Textual TUI (extra [tui]) is not included. Add it with the
 virtualenv pip if you want it:
 /opt/praxis-prime/bin/python -m pip install 'textual>=8.2,<9'
 .
 systemd user units are installed under /usr/lib/systemd/user and are not
 enabled. The package does not enable linger and has no maintainer scripts.
 Built for $arch against $python because cryptography and argon2-cffi ship
 compiled extensions. Not published to an APT repository. The maintainer
 address uses the reserved .invalid domain and does not receive mail.
EOF

(
  cd "$stage"
  find . -type f ! -path './DEBIAN/*' -printf '%P\0' | sort -z | xargs -0 md5sum
) > "$stage/DEBIAN/md5sums"

echo "packing $deb_path" >&2
rm -f "$deb_path"
dpkg-deb --root-owner-group --build "$stage" "$deb_path"

info=$(dpkg-deb -I "$deb_path")
contents=$(dpkg-deb -c "$deb_path")
control_files=$(dpkg-deb --ctrl-tarfile "$deb_path" | tar -t)
grep -F -q " Package: praxis-prime" <<<"$info" || die "control Package field missing"
grep -F -q " Version: $version" <<<"$info" || die "control Version field missing"
grep -F -q " Architecture: $arch" <<<"$info" || die "control Architecture field missing"
require_fixed() {
  grep -F -q "$1" <<<"$contents" || die "package missing $1"
}
require_fixed './opt/praxis-prime/'
require_fixed './usr/bin/praxis-prime ->'
require_fixed './usr/bin/pprime ->'
require_fixed './usr/bin/praxis-primed ->'
require_fixed './usr/lib/systemd/user/praxis-prime.service'
require_fixed './usr/share/doc/praxis-prime/copyright'
require_fixed './usr/share/doc/praxis-prime/LICENSE'
if grep -E -q 'postinst|preinst|prerm|postrm' <<<"$control_files"; then
  die "package must not ship maintainer scripts"
fi
if awk '$1 ~ /^-/ && substr($1, 9, 1) == "w" { found = 1 } END { exit !found }' <<<"$contents"; then
  die "package contains a world-writable file"
fi

echo "wrote $deb_path"
echo "install with: sudo apt install ./$deb_name"
echo "(from $output_dir; this script does not install the package)"

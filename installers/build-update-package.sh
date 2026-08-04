#!/usr/bin/env bash
# Build an OFFLINE UPDATE PACKAGE — application code + every pinned wheel.
#
# This is NOT the offline install bundle. The install bundle carries OS packages
# (.deb/.rpm) and stands up a node from nothing; this carries only what an
# update needs, so it is a quarter of the size and applies from the web console
# on a node with no route to the internet.
#
# The build host holds NO secret. Signing is a separate step, run wherever the
# private key lives:
#
#     bash installers/build-update-package.sh
#     python3 deploy/sign_update_package.py sign dist/satom-update-<v>.tar.gz --key <key>
#
# An unsigned package is refused by every node, so shipping one is a mistake
# that fails closed.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP="$(cd "$HERE/.." && pwd)"
OUT="${OUT_DIR:-$APP/dist}"
PY="${PYTHON:-$APP/venv/bin/python3}"
MIN_FROM="${MIN_FROM_VERSION:-1.0}"

[ -x "$PY" ] || PY="$(command -v python3)"
[ -n "$PY" ] || { echo "no python3 found" >&2; exit 1; }

VERSION="$(tr -d ' \t\n\r' < "$APP/VERSION")"
[ -n "$VERSION" ] || { echo "VERSION is empty" >&2; exit 1; }
COMMIT="$(git -C "$APP" rev-parse HEAD 2>/dev/null || echo "")"
BUILT_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

NAME="satom-update-$VERSION"
STAGE="$(mktemp -d "${TMPDIR:-/tmp}/satom-updpkg-XXXXXX")"
PKG="$STAGE/$NAME"
trap 'rm -rf "$STAGE"' EXIT
mkdir -p "$PKG/wheels" "$OUT"

echo "==> SATOM update package $VERSION (${COMMIT:0:12})"

# ---------------------------------------------------------------- app tree
# git archive, not a copy of the working tree: the package must contain the
# committed revision, never whatever happens to be lying around on the build
# host (a stale or dirty tree already shipped once in this project's history).
if [ -n "$COMMIT" ]; then
  echo "--> app.tar.gz from git archive HEAD"
  git -C "$APP" archive --format=tar HEAD | gzip -9 > "$PKG/app.tar.gz"
else
  echo "!!! not a git checkout — refusing to build from an untracked tree" >&2
  exit 1
fi

# ------------------------------------------------------------------- wheels
echo "--> downloading wheels for requirements.txt"
"$PY" -m pip download --quiet --only-binary=:all: \
      --dest "$PKG/wheels" -r "$APP/requirements.txt" \
  || { echo "!!! pip download failed — the package would apply with no deps" >&2; exit 1; }
WHEELS=$(find "$PKG/wheels" -name '*.whl' | wc -l)
[ "$WHEELS" -gt 0 ] || { echo "!!! no wheels downloaded" >&2; exit 1; }
echo "    $WHEELS wheel(s)"

# --------------------------------------------------------------- manifest
echo "--> manifest.json"
MIN_FROM="$MIN_FROM" PKG_DIR="$PKG" APP_DIR="$APP" \
VERSION="$VERSION" COMMIT="$COMMIT" BUILT_AT="$BUILT_AT" \
"$PY" - <<'PYEOF'
import os, re, sys, sysconfig
from pathlib import Path

app = Path(os.environ["APP_DIR"])
pkg = Path(os.environ["PKG_DIR"])
sys.path.insert(0, str(app / "deploy"))
import update_package as up

files = {}
for p in sorted(pkg.rglob("*")):
    if p.is_file():
        rel = str(p.relative_to(pkg))
        files[rel] = {"sha256": up.sha256_file(p), "size": p.stat().st_size}

reqs = []
for line in (app / "requirements.txt").read_text().splitlines():
    line = line.split("#", 1)[0].strip()
    if line:
        reqs.append(line)

# A package whose wheels are ALL pure-python applies on any CPython the app
# supports; one with a compiled wheel is pinned to the tag it was built for.
# Getting this wrong is the RHEL-9 trap (system python 3.9 vs cp311 wheels):
# the apply would fail deep inside pip instead of in preflight.
names = [w.name for w in (pkg / "wheels").glob("*.whl")]
pure = all(re.search(r"-(?:py2\.)?py3-none-any\.whl$", n) for n in names)
if pure:
    tags = ["*"]
else:
    tags = ["cp%d%d" % sys.version_info[:2]]

manifest = up.build_manifest(
    version=os.environ["VERSION"],
    commit=os.environ["COMMIT"],
    built_at=os.environ["BUILT_AT"],
    python_tags=tags,
    requirements=reqs,
    files=files,
    min_from_version=os.environ.get("MIN_FROM", ""),
    notes="Offline update package: application code + pinned wheels. "
          "Apply from Settings -> Software Update, or with "
          "'satom execute update package'.",
)
(pkg / "manifest.json").write_bytes(up.dump_manifest(manifest))
print("    version %s, %d file(s), python tags %s"
      % (manifest["version"], len(files), ",".join(tags)))
PYEOF

# ------------------------------------------------------------------ pack
TARBALL="$OUT/$NAME.tar.gz"
rm -f "$TARBALL" "$TARBALL.sha256"
tar -C "$STAGE" -czf "$TARBALL" "$NAME"
( cd "$OUT" && sha256sum "$NAME.tar.gz" > "$NAME.tar.gz.sha256" )

SIZE=$(du -h "$TARBALL" | cut -f1)
echo
echo "==> $TARBALL ($SIZE)"
echo "    $(cut -d' ' -f1 < "$TARBALL.sha256")"
echo
echo "UNSIGNED. Every node refuses an unsigned package. Sign it where the key lives:"
echo "    python3 deploy/sign_update_package.py sign $TARBALL --key <release.key>"

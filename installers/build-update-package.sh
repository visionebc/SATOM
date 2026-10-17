#!/usr/bin/env bash
# Build an OFFLINE UPDATE PACKAGE — application code + the pinned wheels a
# supported node may be missing.
#
# Without WHEEL_BASELINE the package carries every pinned wheel (full). With it
# (JSON {version: [name==ver]} from published packages' `wheelset`), it carries
# only the wheels that not every baseline release already has, and
# min_from_version rises to the oldest baseline release (see select_wheels in
# deploy/update_package.py). The full resolved set is always recorded in the
# manifest as `wheelset`.
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
# The release pipeline builds from the REDACTED payload it already ships in the
# offline bundles and the image (APP_TARBALL), unpacked into a plain directory
# that is not a git checkout -- so it hands over the commit too. Both or neither.
APP_TARBALL="${APP_TARBALL:-}"
# Wheels for every supported node, not for the build host. All three families
# run CPython 3.11; manylinux_2_28 is the newest glibc baseline every one of
# them satisfies (RHEL 9 ships glibc 2.34, Debian 12 2.36, Leap 15.6 2.38).
# A wheel resolved for the build host's own glibc can be one RHEL 9 cannot load.
WHEEL_PY="${WHEEL_PYTHON_VERSION:-3.11}"
WHEEL_PLATFORMS="${WHEEL_PLATFORMS:-manylinux_2_28_x86_64 manylinux2014_x86_64}"

[ -x "$PY" ] || PY="$(command -v python3)"
[ -n "$PY" ] || { echo "no python3 found" >&2; exit 1; }

VERSION="$(tr -d ' \t\n\r' < "$APP/VERSION")"
[ -n "$VERSION" ] || { echo "VERSION is empty" >&2; exit 1; }
if [ -n "$APP_TARBALL" ]; then
  COMMIT="${COMMIT:-}"
  [ -f "$APP_TARBALL" ] || { echo "APP_TARBALL $APP_TARBALL does not exist" >&2; exit 1; }
  [[ "$COMMIT" =~ ^[0-9a-f]{40}$ ]] \
    || { echo "APP_TARBALL needs COMMIT=<full sha> of the revision it was archived from" >&2; exit 1; }
else
  COMMIT="$(git -C "$APP" rev-parse HEAD 2>/dev/null || echo "")"
fi
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
if [ -n "$APP_TARBALL" ]; then
  echo "--> app.tar.gz from $APP_TARBALL"
  cp "$APP_TARBALL" "$PKG/app.tar.gz"
elif [ -n "$COMMIT" ]; then
  echo "--> app.tar.gz from git archive HEAD"
  git -C "$APP" archive --format=tar HEAD | gzip -9 > "$PKG/app.tar.gz"
else
  echo "!!! not a git checkout — refusing to build from an untracked tree" >&2
  exit 1
fi

# ------------------------------------------------------------------- wheels
# Resolve the FULL set into a side directory first: it is recorded in the
# manifest (`wheelset`) whatever the package ends up shipping, because the
# next release computes its delta against it.
ALL_WHEELS="$STAGE/all-wheels"
mkdir -p "$ALL_WHEELS"
echo "--> downloading wheels for requirements.txt (cp${WHEEL_PY/./}, ${WHEEL_PLATFORMS// /, })"
PLAT_ARGS=()
for p in $WHEEL_PLATFORMS; do PLAT_ARGS+=(--platform "$p"); done
"$PY" -m pip download --quiet --only-binary=:all: \
      --python-version "$WHEEL_PY" --implementation cp "${PLAT_ARGS[@]}" \
      --dest "$ALL_WHEELS" -r "$APP/requirements.txt" \
  || { echo "!!! pip download failed — the package would apply with no deps" >&2; exit 1; }
WHEELS=$(find "$ALL_WHEELS" -name '*.whl' | wc -l)
[ "$WHEELS" -gt 0 ] || { echo "!!! no wheels downloaded" >&2; exit 1; }
echo "    $WHEELS wheel(s) resolved"

# WHEEL_BASELINE (optional): JSON {"<version>": ["name==ver", ...]} -- the
# `wheelset` of every published package that has one. The release pipeline
# builds it from the packages it published. Unset or empty = full package.
WHEEL_BASELINE="${WHEEL_BASELINE:-}"
if [ -n "$WHEEL_BASELINE" ] && [ ! -f "$WHEEL_BASELINE" ]; then
  echo "!!! WHEEL_BASELINE $WHEEL_BASELINE does not exist" >&2; exit 1
fi

# --------------------------------------------------------------- manifest
echo "--> wheel selection + manifest.json"
MIN_FROM="$MIN_FROM" PKG_DIR="$PKG" APP_DIR="$APP" WHEEL_PY="$WHEEL_PY" \
VERSION="$VERSION" COMMIT="$COMMIT" BUILT_AT="$BUILT_AT" \
ALL_WHEELS="$ALL_WHEELS" WHEEL_BASELINE="$WHEEL_BASELINE" \
"$PY" - <<'PYEOF'
import json, os, re, shutil, sys, sysconfig
from pathlib import Path

app = Path(os.environ["APP_DIR"])
pkg = Path(os.environ["PKG_DIR"])
sys.path.insert(0, str(app / "deploy"))
import update_package as up

all_dir = Path(os.environ["ALL_WHEELS"])
all_names = sorted(w.name for w in all_dir.glob("*.whl"))
baseline = {}
if os.environ.get("WHEEL_BASELINE"):
    baseline = json.loads(Path(os.environ["WHEEL_BASELINE"]).read_text())
    if not isinstance(baseline, dict):
        sys.exit("!!! WHEEL_BASELINE must be a JSON object {version: [name==ver]}")
sel = up.select_wheels(all_names, baseline, os.environ.get("MIN_FROM", ""),
                       os.environ["VERSION"])
for n in sel["keep"]:
    shutil.copy2(all_dir / n, pkg / "wheels" / n)
min_from = sel["min_from_version"]
if sel["mode"] == "delta":
    print("    delta against %s: shipping %d of %d wheel(s); min_from_version %s"
          % (", ".join(sel["baseline"]), len(sel["keep"]), len(all_names), min_from))
else:
    print("    full: shipping all %d wheel(s) (no package with a recorded wheelset)"
          % len(all_names))

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
# Judged on the FULL resolved set, not on what a delta happens to ship: a
# delta with no compiled wheel still needs the venv the full set was built for.
names = all_names
pure = all(re.search(r"-(?:py2\.)?py3-none-any\.whl$", n) for n in names)
if pure:
    tags = ["*"]
else:
    # The interpreter the wheels were RESOLVED for, not the one running this.
    tags = ["cp" + os.environ["WHEEL_PY"].replace(".", "")]

manifest = up.build_manifest(
    version=os.environ["VERSION"],
    commit=os.environ["COMMIT"],
    built_at=os.environ["BUILT_AT"],
    python_tags=tags,
    requirements=reqs,
    files=files,
    min_from_version=min_from,
    notes=("Offline update package: application code + the pinned wheels a node "
           "on %s or newer may be missing. " % min_from
           if sel["mode"] == "delta" else
           "Offline update package: application code + pinned wheels. ")
          + "Apply from Settings -> Software Update, or with "
            "'satom execute update package'.",
    wheelset=[up.wheel_key(n) for n in all_names],
    wheels_mode=sel["mode"],
    wheels_baseline=sel["baseline"],
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

#!/bin/sh
# Re-vendor satom_guikit from a satom-harvester checkout/tag into app/vendor/
# and pin it by hash (tests/test_guikit_vendored.py recomputes the hashes, so a
# hand edit of the vendored copy fails). Usage: deploy/vendor_guikit.sh <harvester-dir> <ref-label>
set -eu
SRC="$1/satom_guikit"; REF="${2:-unknown}"
DST="$(dirname "$0")/../app/vendor/satom_guikit"
[ -f "$SRC/__init__.py" ] || { echo "no satom_guikit in $1" >&2; exit 1; }
# Replace the module's files, never the directory: a byte-code cache another
# user wrote (root running the app once) cannot be removed by this user, and an
# `rm -rf` that stops half-way under `set -e` left the module deleted on a live
# node (2026-10-09). Stale .py files of an older vendoring are removed first.
mkdir -p "$DST"
find "$DST" -maxdepth 1 -type f \( -name '*.py' -o -name 'VENDORED.*' \) -delete
cp "$SRC"/*.py "$DST"/
( cd "$DST" && sha256sum *.py > VENDORED.sha256 && echo "harvester $REF" > VENDORED.from )
echo "vendored satom_guikit from $REF"

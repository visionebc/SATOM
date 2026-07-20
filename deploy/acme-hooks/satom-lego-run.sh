#!/bin/sh
# satom-lego-run.sh — the {helper} of the generated ACME submit command.
#
#   satom-lego-run.sh <out.pem> lego [lego args…] --csr <req.csr> run
#
# WHY A WRAPPER: the Certificate Manager pipeline expects the signed cert at a
# path it chose ({out}) or on stdout. lego writes into its own --path tree
# (<path>/certificates/<domain>.crt) and has no --out. This copies the result
# where the caller asked and echoes it, WITHOUT a shell pipeline in the command
# template — the argv stays flat and injection-proof.
#
# It also never touches credentials: those reach lego through the environment
# built by cert_manager._build_env().
set -eu

OUT="${1:?usage: satom-lego-run.sh <out.pem> <lego> [args…]}"
shift

# The account/cert tree lego was told to use (mirrors {acme_path}).
LEGO_PATH=""
prev=""
for a in "$@"; do
    [ "$prev" = "--path" ] && LEGO_PATH="$a"
    prev="$a"
done
[ -n "$LEGO_PATH" ] || { echo "satom-lego-run: no --path in the lego command" >&2; exit 2; }

"$@"

CERTDIR="$LEGO_PATH/certificates"
[ -d "$CERTDIR" ] || { echo "satom-lego-run: $CERTDIR does not exist" >&2; exit 3; }

# Newest .crt lego just produced (excluding the .issuer.crt chain files).
NEWEST=""
for f in "$CERTDIR"/*.crt; do
    case "$f" in *.issuer.crt) continue ;; esac
    [ -f "$f" ] || continue
    if [ -z "$NEWEST" ] || [ "$f" -nt "$NEWEST" ]; then NEWEST="$f"; fi
done
[ -n "$NEWEST" ] || { echo "satom-lego-run: lego produced no certificate in $CERTDIR" >&2; exit 4; }

cp "$NEWEST" "$OUT"
chmod 600 "$OUT" 2>/dev/null || true
cat "$OUT"

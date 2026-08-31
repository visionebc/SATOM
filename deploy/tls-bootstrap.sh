#!/usr/bin/env sh
#
# tls-bootstrap.sh — every SATOM install serves HTTPS from its first boot.
#
# WHY THIS FILE EXISTS
# --------------------
# The turnkey installer (installers/install-satom.sh) has always issued an
# internal CA, signed a node certificate and put nginx in front of gunicorn. The
# OTHER install paths did not:
#
#   scripts/install.sh      the README's own quick start — gunicorn on :8000,
#                           plain HTTP, no proxy at all
#   deploy/install.sh       legacy bootstrap, same shape
#   deploy/docker/          the stack published :80 and DELEGATED TLS to a
#                           reverse proxy the operator had to supply
#
# Delegating is not a neutral choice. The container variant runs with
# FLASK_ENV=production, which sets SESSION_COOKIE_SECURE=True, and a browser
# will not return a Secure cookie over plain HTTP: the login POST arrives with
# no session, therefore no CSRF token, and is rejected before the password is
# ever compared. On 2026-08-31 that made a freshly installed node reject EVERY
# credential while /healthz answered 200 and the units were green.
#
# So TLS is now provisioned by the install itself, in every shape. The
# certificate is self-signed by a per-node internal CA, which a browser will
# warn about -- that is the intended state: the node is USABLE on day zero and
# the operator replaces the certificate afterwards, on their own schedule,
# through the Certificate Manager or by dropping files in place (see
# `import-cert` below).
#
# ONE AUTHOR FOR THE VHOST
# ------------------------
# The proxy settings below are not stylistic. `Host $http_host` (never $host)
# is what keeps Flask-WTF's CSRF referer check working behind a non-standard
# port -- $host drops the port and every POST fails with a message about a
# stale session. `X-Forwarded-Proto https` is what tells the application it is
# reached over TLS even though this hop speaks plain HTTP to gunicorn.
# `client_max_body_size 400M` must stay >= MAX_UPLOAD_BYTES or a valid update
# package dies with an nginx 413 the app never sees and therefore cannot
# explain. Each of those was learned once and must not be re-learned per
# install path -- which is the whole reason this is a shared file and
# tests/test_tls_by_default.py compares it against the turnkey installer.
#
# USAGE
#   tls-bootstrap.sh ensure-pki    [--pki DIR] [--names "a b"] [--ip ADDR]
#   tls-bootstrap.sh write-vhost   --out FILE [--pki DIR] [--names ...]
#                                  [--port N] [--upstream HOST:PORT]
#                                  [--acme-webroot DIR]
#   tls-bootstrap.sh import-cert   --cert F --key F [--chain F] [--pki DIR]
#
# Every subcommand is idempotent and safe to re-run on an installed node.
set -eu

CMD="${1:-}"; [ -n "$CMD" ] || { echo "tls-bootstrap: no subcommand" >&2; exit 2; }
shift

APP_DIR="${APP_DIR:-/opt/satom}"
PKI="${SATOM_PKI:-$APP_DIR/pki}"
NAMES="${SATOM_SERVED_NAMES:-}"
NODE_IP="${SATOM_NODE_IP:-}"
PORT="${SATOM_WEB_PORT:-443}"
UPSTREAM="${SATOM_UPSTREAM:-127.0.0.1:8000}"
ACME_WEBROOT="${SATOM_ACME_WEBROOT:-/var/www/satom-acme}"
OUT=""
IN_CERT=""; IN_KEY=""; IN_CHAIN=""

while [ $# -gt 0 ]; do
    case "$1" in
        --pki)           PKI="$2"; shift 2 ;;
        --names)         NAMES="$2"; shift 2 ;;
        --ip)            NODE_IP="$2"; shift 2 ;;
        --port)          PORT="$2"; shift 2 ;;
        --upstream)      UPSTREAM="$2"; shift 2 ;;
        --acme-webroot)  ACME_WEBROOT="$2"; shift 2 ;;
        --out)           OUT="$2"; shift 2 ;;
        --cert)          IN_CERT="$2"; shift 2 ;;
        --key)           IN_KEY="$2"; shift 2 ;;
        --chain)         IN_CHAIN="$2"; shift 2 ;;
        *) echo "tls-bootstrap: unknown option $1" >&2; exit 2 ;;
    esac
done

# The served names default to the node's own hostname. Kept as a FALLBACK and
# never as the first source: a certificate whose SAN does not cover the name the
# operator actually types produces a browser warning on a certificate that was
# just reported as successfully issued, and the only fix is to reissue it.
[ -n "$NAMES" ] || NAMES="$(hostname 2>/dev/null || echo satom)"
CN="$(printf '%s' "$NAMES" | awk '{print $1}')"

# ---------------------------------------------------------------------------
# ensure-pki
# ---------------------------------------------------------------------------
# Creates $PKI/internal-ca (once, 10 years) and $PKI/node (825 days), then
# publishes the leaf as $PKI/public/server.{crt,key} with a meta.json.
#
# meta.json's `source` is load-bearing, not decoration:
#   issued    -> this script owns the material and may reissue it
#   imported  -> an OPERATOR installed a real certificate here. Reissuing over
#                it would silently replace a trusted certificate with a
#                self-signed one at the next re-run of the installer, which is
#                exactly how CT 346 lost its wildcard on 2026-08-04.
# So an imported certificate is left alone and the function returns success.
ensure_pki() {
    mkdir -p "$PKI/internal-ca" "$PKI/node" "$PKI/public"
    chmod 700 "$PKI/internal-ca"

    if [ -f "$PKI/public/meta.json" ] \
       && grep -q '"source"[[:space:]]*:[[:space:]]*"imported"' "$PKI/public/meta.json" \
       && [ -s "$PKI/public/server.crt" ] && [ -s "$PKI/public/server.key" ]; then
        echo "tls-bootstrap: operator certificate present (source=imported) — left untouched"
        return 0
    fi

    if [ ! -f "$PKI/internal-ca/ca.key" ]; then
        openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
            -keyout "$PKI/internal-ca/ca.key" -out "$PKI/internal-ca/ca.crt" \
            -subj "/CN=SATOM Internal CA/O=$CN" >/dev/null 2>&1
        echo "tls-bootstrap: internal CA created (10 years)"
    fi
    chmod 600 "$PKI/internal-ca/ca.key"

    # An existing self-issued leaf that still covers the requested names and is
    # not close to expiry is kept. Reissuing on every installer re-run would
    # invalidate the fingerprint an operator may have pinned, for no gain.
    if [ -s "$PKI/public/server.crt" ] \
       && openssl x509 -in "$PKI/public/server.crt" -noout -checkend 2592000 >/dev/null 2>&1 \
       && _cert_covers "$PKI/public/server.crt"; then
        echo "tls-bootstrap: node certificate present and valid — reused"
        return 0
    fi

    san="DNS:$CN"
    for n in $NAMES; do
        [ "$n" = "$CN" ] || san="$san,DNS:$n"
    done
    [ -z "$NODE_IP" ] || san="$san,IP:$NODE_IP"

    ext="$(mktemp)"
    printf 'subjectAltName=%s\nextendedKeyUsage=serverAuth,clientAuth\n' "$san" > "$ext"
    openssl req -newkey rsa:2048 -sha256 -nodes \
        -keyout "$PKI/node/leaf.key" -out "$PKI/node/leaf.csr" \
        -subj "/CN=$CN" >/dev/null 2>&1
    openssl x509 -req -in "$PKI/node/leaf.csr" \
        -CA "$PKI/internal-ca/ca.crt" -CAkey "$PKI/internal-ca/ca.key" -CAcreateserial \
        -days 825 -sha256 -extfile "$ext" -out "$PKI/node/leaf.crt" >/dev/null 2>&1
    rm -f "$ext" "$PKI/node/leaf.csr"
    chmod 600 "$PKI/node/leaf.key"

    cp "$PKI/node/leaf.crt" "$PKI/public/server.crt"
    cp "$PKI/node/leaf.key" "$PKI/public/server.key"
    chmod 600 "$PKI/public/server.key"
    cat > "$PKI/public/meta.json" <<META
{"source": "issued", "issued_by": "internal-ca", "cn": "$CN", "san": "$san", "installed_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"}
META
    echo "tls-bootstrap: node certificate issued (CN=$CN, SAN=$san)"
}

# True when the certificate's SAN already covers every requested name. Without
# this an installer re-run that ADDS a served name would keep reporting success
# while the new name stays uncovered.
_cert_covers() {
    _txt="$(openssl x509 -in "$1" -noout -text 2>/dev/null || true)"
    for n in $NAMES; do
        printf '%s' "$_txt" | grep -q "DNS:$n\b" || return 1
    done
    return 0
}

# ---------------------------------------------------------------------------
# write-vhost
# ---------------------------------------------------------------------------
# The :80 server is NOT a leftover. ACME http-01 is always validated over plain
# :80 even for a host that only serves TLS, so the challenge location has to
# survive the redirect -- which is why the redirect is scoped to `location /`
# and not written as a server-level `return`, that runs before location
# selection and would swallow the challenge.
write_vhost() {
    [ -n "$OUT" ] || { echo "tls-bootstrap: write-vhost needs --out" >&2; exit 2; }
    mkdir -p "$(dirname "$OUT")" "$ACME_WEBROOT/.well-known/acme-challenge"
    chmod 755 "$ACME_WEBROOT"

    # An explicit :443 in a redirect is valid but propagates into the address
    # bar and into any proxy in front; omitted when it is the default port,
    # exactly as a browser does.
    redir_port=""
    [ "$PORT" = "443" ] || redir_port=":$PORT"

    cat > "$OUT" <<NGX
# Generated by deploy/tls-bootstrap.sh — do not edit by hand.
# Replace the CERTIFICATE, not this file: see \`tls-bootstrap.sh import-cert\`.
server {
    listen $PORT ssl;
    listen [::]:$PORT ssl;
    http2 on;
    server_name $NAMES${NODE_IP:+ $NODE_IP};

    ssl_certificate     $PKI/public/server.crt;
    ssl_certificate_key $PKI/public/server.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SATOM:10m;

    # Must stay >= MAX_UPLOAD_BYTES in update_package_service.py, or a valid
    # update package dies with an nginx 413 the application never sees.
    client_max_body_size 400M;

    location / {
        proxy_pass http://$UPSTREAM;
        # \$host DISCARDS the port; \$http_host passes the header through. Flask-WTF
        # builds the expected CSRF origin from the host the app believes it has and
        # compares it against the browser's Referer INCLUDING the port: behind a NAT
        # or a proxy on a non-standard port every POST -- the login included -- died
        # with an error that spoke about an expired session, not about a header.
        proxy_set_header Host              \$http_host;
        proxy_set_header X-Real-IP         \$remote_addr;
        proxy_set_header X-Forwarded-For   \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_read_timeout 120s;
    }
}

server {
    listen 80;
    listen [::]:80;
    server_name _;
    location ^~ /.well-known/acme-challenge/ {
        root $ACME_WEBROOT;
        default_type "text/plain";
        try_files \$uri =404;
    }
    location / { return 301 https://\$host$redir_port\$request_uri; }
}
NGX
    echo "tls-bootstrap: vhost written to $OUT (names: $NAMES, upstream: $UPSTREAM)"
}

# ---------------------------------------------------------------------------
# import-cert
# ---------------------------------------------------------------------------
# The operator-facing half of the promise: the install ships a working
# certificate, the operator replaces it later. Marking meta.json source=imported
# is what stops a later installer re-run from overwriting it.
import_cert() {
    [ -n "$IN_CERT" ] && [ -n "$IN_KEY" ] || {
        echo "tls-bootstrap: import-cert needs --cert and --key" >&2; exit 2; }
    openssl x509 -in "$IN_CERT" -noout >/dev/null 2>&1 || {
        echo "tls-bootstrap: --cert is not a certificate" >&2; exit 1; }
    # Refuse a mismatched pair HERE. nginx accepts the reload and then fails on
    # the first handshake, which reads as a network fault rather than a
    # configuration one.
    c="$(openssl x509 -in "$IN_CERT" -noout -pubkey 2>/dev/null | openssl sha256)"
    k="$(openssl pkey -in "$IN_KEY" -pubout 2>/dev/null | openssl sha256)"
    [ -n "$c" ] && [ "$c" = "$k" ] || {
        echo "tls-bootstrap: certificate and key do not match" >&2; exit 1; }

    mkdir -p "$PKI/public"
    if [ -n "$IN_CHAIN" ]; then
        cat "$IN_CERT" "$IN_CHAIN" > "$PKI/public/server.crt"
    else
        cp "$IN_CERT" "$PKI/public/server.crt"
    fi
    cp "$IN_KEY" "$PKI/public/server.key"
    chmod 600 "$PKI/public/server.key"
    cn="$(openssl x509 -in "$PKI/public/server.crt" -noout -subject 2>/dev/null | sed 's/.*CN *= *//; s/,.*//')"
    cat > "$PKI/public/meta.json" <<META
{"source": "imported", "cn": "$cn", "installed_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"}
META
    echo "tls-bootstrap: certificate imported (CN=$cn) — reissue will not overwrite it"
}

case "$CMD" in
    ensure-pki)  ensure_pki ;;
    write-vhost) write_vhost ;;
    import-cert) import_cert ;;
    *) echo "tls-bootstrap: unknown subcommand '$CMD'" >&2; exit 2 ;;
esac

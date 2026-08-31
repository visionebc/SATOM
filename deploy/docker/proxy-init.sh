#!/usr/bin/env sh
#
# proxy-init.sh — provisions TLS for the container stack, then exits.
#
# Runs ONCE per `up`, in the SATOM image (which carries openssl and
# deploy/tls-bootstrap.sh), as root, before the proxy starts. The proxy image
# is stock nginx:alpine with nothing added: everything node-specific is
# generated here, into volumes.
#
# Why an init container and not a custom proxy image: a second image is a
# second thing to build, tag, export to an air-gapped site and keep in step
# with the app. This way the offline delivery stays "one tarball plus two
# stock images".
#
# Why it must be root: the volumes are created empty and owned by root on first
# `up`. The app containers run as uid 999 and could not create pki/ there. The
# private key it writes stays 0600.
set -eu

PKI="${SATOM_PKI:-/opt/satom/pki}"
CONF_OUT="${SATOM_PROXY_CONF_OUT:-/out/satom.conf}"
ACME="${SATOM_ACME_WEBROOT:-/var/www/satom-acme}"

# The names the certificate must cover. Defaults to the compose project's
# service hostname only because SOMETHING has to be in the SAN -- an operator
# who reaches this node by any other name sets SATOM_SERVED_NAMES in .env, and
# env.example says so. A SAN that does not cover the name actually typed
# produces a browser warning on a certificate reported as freshly issued, and
# the only remedy is to reissue.
NAMES="${SATOM_SERVED_NAMES:-$(hostname)}"

echo "proxy-init: provisioning TLS for: $NAMES"

# The application container is the upstream, by SERVICE NAME. Not 127.0.0.1:
# inside a container that is the container itself, which is the same class of
# mistake that left the scheduler pointing at a database that was not there.
UPSTREAM="${SATOM_PROXY_UPSTREAM:-web:8000}"

SATOM_SERVED_NAMES="$NAMES" \
SATOM_ACME_WEBROOT="$ACME" \
/opt/satom/deploy/tls-bootstrap.sh ensure-pki --pki "$PKI"

SATOM_SERVED_NAMES="$NAMES" \
SATOM_ACME_WEBROOT="$ACME" \
/opt/satom/deploy/tls-bootstrap.sh write-vhost \
    --pki "$PKI" --out "$CONF_OUT" --port 443 --upstream "$UPSTREAM"

# The proxy runs its master as root and reads the key directly; the worker
# never opens it. Left at 0600 rather than widened for the container that will
# read it -- widening here is how a key ends up world-readable in an image
# someone later exports.
chmod 600 "$PKI/public/server.key"

echo "proxy-init: done — certificate source: $(cat "$PKI/public/meta.json")"

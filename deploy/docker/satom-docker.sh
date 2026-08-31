#!/usr/bin/env bash
# SATOM container stack — the one entry point.
#
# Exists so the -f order and the standby guard are not things anyone has to
# remember correctly at 03:00:
#
#   * Compose merges LEFT to RIGHT. With the files reversed, the production
#     overlay becomes the base and the development defaults win: the stack
#     comes up bound to a development configuration and reports success.
#   * The standby overlay REBUILDS PostgreSQL from a peer. Applied to a
#     primary, it discards that node's database, quietly, with a healthy
#     container afterwards. This script refuses unless SATOM_NODE_ROLE=standby.
#
# Usage:
#   ./satom-docker.sh gen-secrets      write real values into .env
#   ./satom-docker.sh build [TAG]      build the image from the repo root
#   ./satom-docker.sh config           render the merged config (dry run)
#   ./satom-docker.sh up | down | ps | logs [svc] | exec <svc> [cmd...]
#   ./satom-docker.sh export <TAG> <out.tar.gz>   image -> air-gapped tarball
#   ./satom-docker.sh import <in.tar.gz>          tarball -> local image store
#   ./satom-docker.sh health           what an operator should check
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
ENV_FILE="$HERE/.env"

die() { echo "satom-docker: $*" >&2; exit 1; }

compose_files() {
    # Development is the base alone. Production layers the prod overlay, and a
    # standby layers one more on top of THAT.
    local -a f=(-f "$HERE/compose.yaml")
    if [ "${SATOM_ENV:-dev}" = "prod" ]; then
        f+=(-f "$HERE/compose.prod.yaml")
        if [ "${SATOM_NODE_ROLE:-primary}" = "standby" ]; then
            f+=(-f "$HERE/compose.standby.yaml")
        fi
    fi
    printf '%s\n' "${f[@]}"
}

load_env() {
    [ -f "$ENV_FILE" ] || die "missing $ENV_FILE — copy env.example and run gen-secrets"
    set -a; . "$ENV_FILE"; set +a

    # The guard the whole script exists for. A standby overlay applied to a
    # primary is unrecoverable in the way that matters: it succeeds.
    if [ "${SATOM_ENV:-dev}" = "prod" ] && [ "${SATOM_NODE_ROLE:-primary}" = "standby" ]; then
        [ -n "${SATOM_PRIMARY_HOST:-}" ] || \
            die "SATOM_NODE_ROLE=standby but SATOM_PRIMARY_HOST is empty"
    fi
}

dc() { load_env; docker compose $(compose_files) --env-file "$ENV_FILE" "$@"; }

cmd="${1:-}"; shift || true
case "$cmd" in

gen-secrets)
    [ -f "$ENV_FILE" ] || cp "$HERE/env.example" "$ENV_FILE"
    # python from the venv is not guaranteed on a bare Docker node, so the
    # generator is openssl (present anywhere docker is) plus a base64 urlsafe
    # 32-byte key, which is exactly what Fernet.generate_key() produces.
    sk=$(openssl rand -hex 32)
    fk=$(openssl rand 32 | base64 | tr '+/' '-_')
    pg=$(openssl rand -hex 24)
    rp=$(openssl rand -hex 24)
    # Only ever REPLACES a placeholder. Regenerating FERNET_KEY on a stack that
    # already has encrypted device passwords makes every one of them
    # permanently undecryptable, so a real value is never touched.
    grep -q 'CHANGE_ME' "$ENV_FILE" || die "no CHANGE_ME placeholders left in $ENV_FILE — refusing to regenerate real secrets"
    sed -i "s|^SECRET_KEY=CHANGE_ME.*|SECRET_KEY=${sk}|" "$ENV_FILE"
    sed -i "s|^FERNET_KEY=CHANGE_ME.*|FERNET_KEY=${fk}|" "$ENV_FILE"
    sed -i "s|^POSTGRES_PASSWORD=CHANGE_ME.*|POSTGRES_PASSWORD=${pg}|" "$ENV_FILE"
    sed -i "s|^SATOM_REPL_PASSWORD=CHANGE_ME.*|SATOM_REPL_PASSWORD=${rp}|" "$ENV_FILE"
    chmod 0600 "$ENV_FILE"
    echo "wrote secrets to $ENV_FILE (mode 0600)"
    echo "BACK UP FERNET_KEY — it cannot be rotated once device passwords exist."
    ;;

build)
    tag="${1:-satom:local}"
    # Context is the REPO ROOT, not this directory: the Dockerfile copies app/,
    # migrations/ and the endpoint YAMLs. .dockerignore keeps the ~1.4 GB of
    # data/ and the 380 MB venv out of the tarball sent to the daemon.
    docker build -t "$tag" -f "$REPO/Dockerfile" "$REPO"
    docker image inspect "$tag" --format 'built {{.Id}} ({{.Size}} bytes)'
    ;;

config)   dc config ;;
up)       dc up -d "$@" ;;
down)     dc down "$@" ;;
ps)       dc ps ;;
logs)     dc logs --tail=200 -f "$@" ;;
exec)     svc="${1:?service}"; shift; dc exec "$svc" "${@:-sh}" ;;

export)
    tag="${1:?image tag}"; out="${2:?output path}"
    # The delivery path to production. The DMZ cannot reach the LAN registry
    # (measured 2026-08-31: 192.0.2.79:5000 is unreachable from 203.0.113.0/24),
    # and opening the firewall for it would be a state change to buy a
    # convenience. An image tarball is the same offline-bundle model the
    # product already ships installers with.
    docker save "$tag" | gzip -9 > "$out"
    sha256sum "$out" | tee "${out}.sha256"
    ;;

import)
    in="${1:?input path}"
    if [ -f "${in}.sha256" ]; then
        # Verify BEFORE loading. A truncated transfer produces a layer error
        # deep in `docker load`, which reads like a corrupt image rather than a
        # short file.
        sha256sum -c "${in}.sha256"
    else
        echo "warning: no ${in}.sha256 alongside the tarball — cannot verify" >&2
    fi
    gunzip -c "$in" | docker load
    ;;

health)
    load_env
    echo "== containers =="
    docker compose $(compose_files) --env-file "$ENV_FILE" ps
    echo
    echo "== postgres role (f=primary, t=standby) =="
    docker compose $(compose_files) --env-file "$ENV_FILE" \
        exec -T web /opt/satom/deploy/docker/node-role.sh || echo "(db not reachable)"
    echo
    echo "== app =="
    curl -fsS "http://127.0.0.1:${SATOM_HTTP_BIND##*:}/healthz" && echo
    echo
    echo "== runtime capabilities =="
    docker compose $(compose_files) --env-file "$ENV_FILE" \
        exec -T web python -c \
        "import json,app.runtime as r; print(json.dumps(r.summary(), indent=2))"
    ;;

*)
    sed -n '2,30p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    exit 64
    ;;
esac

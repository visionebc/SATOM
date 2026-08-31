# SATOM — container image (development and production).
#
# The image carries the APPLICATION ONLY. Everything SATOM normally installs on
# its host -- PostgreSQL, Redis, VictoriaMetrics, nginx, the systemd units --
# lives in sibling containers or in front of the stack. See deploy/docker/.
#
# Two stages so the runtime layer never carries a compiler. Most of the pinned
# set (cryptography, psycopg[binary], Pillow via pdfplumber) ships manylinux
# wheels, but pyrad/ldap3/reportlab have historically fallen back to a source
# build on a slim base, and a missing gcc there fails the build at minute six
# instead of minute zero.
#
# Python 3.11 on purpose: it is what the HA nodes run (verified 3.11.2 on
# satom-node-1), so the container and the host installs execute the same
# interpreter minor. A container that passes tests on 3.13 tells you nothing
# about the appliance.

# ---------------------------------------------------------------------------
# Stage 1 — build the virtualenv
# ---------------------------------------------------------------------------
FROM python:3.11-slim-bookworm AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        libpq-dev \
        libffi-dev \
        libssl-dev \
        libldap2-dev \
        libsasl2-dev \
    && rm -rf /var/lib/apt/lists/*

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY requirements.txt /tmp/requirements.txt
RUN pip install --upgrade pip setuptools wheel \
    && pip install -r /tmp/requirements.txt

# ---------------------------------------------------------------------------
# Stage 2 — runtime
# ---------------------------------------------------------------------------
FROM python:3.11-slim-bookworm AS runtime

# libpq5      psycopg runtime
# curl        HEALTHCHECK below and the entrypoint's readiness probes
# postgresql-client  entrypoint waits on pg_isready; bundle restore uses pg_restore
# git         the app shells out to git for the revision banner; the *updater*
#             is disabled here (app/runtime.py) but reading a SHA is not
# ca-certificates / tzdata  outbound TLS to appliances, and local timestamps
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpq5 \
        curl \
        postgresql-client \
        git \
        ca-certificates \
        tzdata \
    && rm -rf /var/lib/apt/lists/*

# uid/gid 999 matches the `satom` service account on the host installs, so a
# data/ directory rsynced from a node keeps its ownership instead of arriving
# as a pile of files the app cannot write.
RUN groupadd -g 999 satom && useradd -u 999 -g 999 -M -s /usr/sbin/nologin satom

COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /opt/satom

# Explicit COPY list, never `COPY . .`: the build context is a live appliance
# checkout that contains venv/, .git/ and ~1.4 GB of data/ (firmware images,
# system backups, SoT blobs). .dockerignore covers it, but an allowlist here
# means a new top-level directory does not silently enter the image.
COPY app/            ./app/
COPY migrations/     ./migrations/
COPY deploy/docker/  ./deploy/docker/
COPY scripts/        ./scripts/
COPY wsgi.py VERSION requirements.txt babel.cfg pytest.ini ./
COPY endpoints.yaml endpoints_fortiadc.yaml endpoints_fortianalyzer.yaml endpoints_fortiauthenticator.yaml ./
COPY acme_providers.yaml ./
COPY LICENSE NOTICE README.md CHANGELOG.md ./

# Runtime state lives on volumes. Created here so the container starts writable
# even when an operator forgets a mount (dev), instead of failing at first use.
RUN mkdir -p /opt/satom/data /opt/satom/instance /opt/satom/state \
             /opt/satom/reports /var/log/satom \
    && chown -R satom:satom /opt/satom/data /opt/satom/instance \
             /opt/satom/state /opt/satom/reports /var/log/satom

# THE declaration that subtracts the host-only capabilities. app/runtime.py
# explains why this is an env var and not autodetection: the HA nodes are LXC
# containers, so any /proc-based probe answers True there too and would disable
# self-update on production.
ENV SATOM_RUNTIME=container \
    FLASK_APP=wsgi.py \
    FLASK_ENV=production \
    SATOM_ROLE=web

ENTRYPOINT ["/opt/satom/deploy/docker/entrypoint.sh"]

EXPOSE 8000

# start-period is generous because the app factory runs db.create_all() on
# first boot against an empty database; on a cold volume that is not instant.
HEALTHCHECK --interval=30s --timeout=5s --start-period=90s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8000/healthz || exit 1

USER satom

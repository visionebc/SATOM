"""Guards for the container runtime and its packaging.

Nothing in this area fails loudly on its own. An image that boots and answers
/healthz 200 looks correct while four menu entries are dead; a compose file
that publishes VictoriaMetrics looks correct while the fleet's metrics are
world-readable; a capability declared and never consulted looks like a policy
while being decoration. Each of those is an assertion nobody makes, so each
one is made here.
"""
from __future__ import annotations

import ast
import io
import os
import re
import tokenize
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
DOCKERFILE = ROOT / "Dockerfile"
DOCKERIGNORE = ROOT / ".dockerignore"
DOCKER_DIR = ROOT / "deploy" / "docker"
COMPOSE = DOCKER_DIR / "compose.yaml"
COMPOSE_PROD = DOCKER_DIR / "compose.prod.yaml"
COMPOSE_STANDBY = DOCKER_DIR / "compose.standby.yaml"
ENV_EXAMPLE = DOCKER_DIR / "env.example"
ENTRYPOINT = DOCKER_DIR / "entrypoint.sh"
WRAPPER = DOCKER_DIR / "satom-docker.sh"


def code_of(path: Path) -> str:
    """Source with comments and string literals removed.

    Required, not tidy. This repository has produced the same false PASS nine
    times: an assertion of the form ``"X" in source`` matches the COMMENT that
    explains why X matters, so the mutation that deletes X survives. Every
    absence-assertion below runs on this, never on the raw text.
    """
    out = []
    for tok in tokenize.generate_tokens(io.StringIO(path.read_text()).readline):
        if tok.type in (tokenize.COMMENT, tokenize.STRING):
            continue
        out.append(tok.string)
    return " ".join(out)


# ---------------------------------------------------------------------------
# app/runtime.py — the declaration
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _clean_runtime_env(monkeypatch):
    monkeypatch.delenv("SATOM_RUNTIME", raising=False)


def _runtime():
    from app import runtime
    return runtime


def test_default_runtime_is_host():
    assert _runtime().runtime() == "host"
    assert _runtime().is_container_runtime() is False


@pytest.mark.parametrize("value", ["container", "CONTAINER", " container ", "Container"])
def test_exact_value_selects_container(monkeypatch, value):
    monkeypatch.setenv("SATOM_RUNTIME", value)
    assert _runtime().is_container_runtime() is True


@pytest.mark.parametrize("value", ["", "1", "true", "yes", "docker", "contaner", "host"])
def test_anything_else_is_host(monkeypatch, value):
    """A typo must not disable self-update on a real node.

    The failure this prevents is asymmetric: reading a stray value as
    "container" silently removes the updater from an appliance, and the
    operator finds out the next time they need it.
    """
    monkeypatch.setenv("SATOM_RUNTIME", value)
    assert _runtime().is_container_runtime() is False


def test_container_runtime_denies_every_host_only_capability(monkeypatch):
    monkeypatch.setenv("SATOM_RUNTIME", "container")
    rt = _runtime()
    for name in rt.HOST_ONLY_CAPABILITIES:
        assert rt.capability(name) is False, name
        assert rt.unavailable_reason(name), f"{name} has no operator-facing reason"
        with pytest.raises(rt.CapabilityUnavailable):
            rt.require(name)


def test_host_runtime_allows_every_capability():
    rt = _runtime()
    for name in rt.HOST_ONLY_CAPABILITIES:
        assert rt.capability(name) is True, name
        assert rt.unavailable_reason(name) == ""
        rt.require(name)  # must not raise


def test_unknown_capability_is_allowed(monkeypatch):
    """This gate subtracts, it does not allowlist.

    If an unknown name were denied, adding a feature without registering it
    here would disable it everywhere — and the symptom would be a refusal
    message naming a capability nobody has heard of.
    """
    monkeypatch.setenv("SATOM_RUNTIME", "container")
    assert _runtime().capability("something_new") is True


def test_runtime_does_not_infer_from_proc():
    """The discriminator is a declaration, never autodetection.

    ``system_health.is_container()`` already returns **True on satom-node-1 and
    satom-node-2**: they are LXC containers. Keying these capabilities off it
    would disable self-update, certificate activation and service control on
    the two production nodes — the exact inverse of the intent.

    Asserted against ``code_of``: runtime.py's own docstring says the words
    ``is_container`` and ``/proc``, so a raw-text search would pass on a
    module that had been rewritten to autodetect.
    """
    src = ROOT / "app" / "runtime.py"
    code = code_of(src)
    assert "is_container(" not in code
    assert "system_health" not in code
    assert "/proc" not in code
    # The POSITIVE half runs on the raw text, not on ``code_of``: the variable
    # name only ever appears inside a string literal (``os.environ.get(...)``),
    # which ``code_of`` strips by design. Asserting it against the stripped
    # source failed on a correct module — the same comment/code confusion this
    # helper exists for, arriving from the other direction.
    assert "SATOM_RUNTIME" in src.read_text()


def test_every_declared_capability_has_a_call_site():
    """A capability that nothing consults is decoration.

    Searches the application EXCLUDING runtime.py, which is where the names are
    declared: including it would let every name satisfy this test by existing.
    """
    rt = _runtime()
    haystack = []
    for p in (ROOT / "app").rglob("*.py"):
        if p.name == "runtime.py" or "__pycache__" in p.parts:
            continue
        haystack.append(p.read_text())
    blob = "\n".join(haystack)
    for name in rt.HOST_ONLY_CAPABILITIES:
        assert (f'require("{name}")' in blob or f'capability("{name}")' in blob), (
            f"capability {name!r} is declared but never consulted"
        )


# ---------------------------------------------------------------------------
# Dockerfile
# ---------------------------------------------------------------------------

def test_dockerfile_declares_the_container_runtime():
    assert re.search(r"^\s*ENV\s+SATOM_RUNTIME=container", DOCKERFILE.read_text(),
                     re.M), "the image must declare its runtime"


def test_dockerfile_does_not_copy_the_whole_context():
    """`COPY . .` on this repo copies a live appliance: ~1.4 GB of data/
    (device vault, system backups, SoT blobs), the 380 MB venv, and .env."""
    for line in DOCKERFILE.read_text().splitlines():
        s = line.strip()
        if s.startswith("COPY") and "--from=" not in s:
            assert not re.match(r"COPY\s+\.\s+\.?/?\s*$", s), s


def test_dockerfile_copies_the_deploy_tree():
    """The application does not start without it.

    ``app/services/update_package_service.py`` loads ``deploy/update_package.py``
    BY PATH at module import time, and ``app/views/self_update.py`` imports that
    module — so an image carrying only ``deploy/docker/`` boot-loops gunicorn on
    a FileNotFoundError. That is exactly how this was found: by running the
    stack, after the build succeeded and the tests passed.
    """
    text = DOCKERFILE.read_text()
    assert re.search(r"^\s*COPY\s+deploy/\s+\./deploy/\s*$", text, re.M), (
        "the image must carry the whole deploy/ tree"
    )


def test_the_import_time_deploy_dependency_still_exists():
    """Pins the REASON for the test above.

    If update_package_service stops loading by path, the rule above becomes
    cargo cult — a copy nobody can justify, which is how a Dockerfile
    accumulates lines that outlive their reason.
    """
    svc = (ROOT / "app" / "services" / "update_package_service.py").read_text()
    assert '"deploy" / "update_package.py"' in svc


def test_dockerfile_runs_as_a_non_root_user():
    assert re.search(r"^\s*USER\s+satom\s*$", DOCKERFILE.read_text(), re.M)


def test_dockerfile_python_minor_matches_the_appliance():
    """The HA nodes run 3.11 (verified 3.11.2 on satom-node-1). A container
    that passes on a different minor tells you nothing about the appliance."""
    for m in re.finditer(r"^FROM\s+(\S+)", DOCKERFILE.read_text(), re.M):
        if m.group(1).startswith("python:"):
            assert m.group(1).startswith("python:3.11"), m.group(1)


# ---------------------------------------------------------------------------
# .dockerignore
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("pattern", ["data/", "venv/", ".env", "*.db", ".git", "pki/"])
def test_dockerignore_excludes_state_and_secrets(pattern):
    lines = {l.strip() for l in DOCKERIGNORE.read_text().splitlines()}
    assert pattern in lines, f"{pattern} must not enter the build context"


# ---------------------------------------------------------------------------
# compose
# ---------------------------------------------------------------------------

def _yaml(path: Path) -> dict:
    yaml = pytest.importorskip("yaml")
    return yaml.safe_load(path.read_text())


def test_metrics_store_is_not_published():
    """VictoriaMetrics HAS NO AUTHENTICATION.

    On a host install the 127.0.0.1 bind is the only thing protecting the
    fleet's metrics. Here that role is played by the absence of a published
    port, so the absence is load-bearing and is asserted.
    """
    svc = _yaml(COMPOSE)["services"]["victoria-metrics"]
    assert "ports" not in svc, "publishing the metrics store exposes the fleet"


def test_base_stack_publishes_only_the_proxy_service():
    """It used to be `web`. That INVERTED when the stack grew its own TLS
    terminator: publishing gunicorn beside the proxy re-opens the plain-HTTP
    door, and FLASK_ENV=production makes that door one where no password works
    -- so the application container must publish nothing at all."""
    services = _yaml(COMPOSE)["services"]
    published = {n for n, s in services.items() if s.get("ports")}
    assert published == {"proxy"}, published


def test_metrics_image_matches_the_host_install_version():
    """A container node and a host node answering different MetricsQL is a
    difference that only shows up as an empty dashboard panel."""
    env = (ROOT / "deploy" / "metrics-store.env").read_text()
    want = re.search(r'VM_VERSION="([^"]+)"', env).group(1)
    image = _yaml(COMPOSE)["services"]["victoria-metrics"]["image"]
    assert image.endswith(f":v{want}"), f"{image} != v{want} (deploy/metrics-store.env)"


def test_every_app_service_gets_the_shared_environment():
    """A service-level ``environment:`` REPLACES the mapping inherited through
    ``<<:`` — it does not merge into it. Written the obvious way, giving
    ``scheduler`` its SATOM_ROLE drops the database URI from that container,
    which then falls back to whatever .env carries (127.0.0.1 on a node copied
    from a host install) and logs normally while connecting to nothing.
    """
    services = _yaml(COMPOSE)["services"]
    for name in ("web", "scheduler", "cron"):
        env = services[name]["environment"]
        assert "SQLALCHEMY_DATABASE_URI" in env, name
        assert "@postgres:5432/" in env["SQLALCHEMY_DATABASE_URI"], name
        assert "RATELIMIT_STORAGE_URI" in env, name
        assert "SATOM_METRICS_URL" in env, name
    assert services["scheduler"]["environment"]["SATOM_ROLE"] == "scheduler"
    assert services["cron"]["environment"]["SATOM_ROLE"] == "cron"


def test_production_overlay_refuses_a_mutable_image_tag():
    """``:local`` can be rebuilt in place, which makes "which build is running?"
    unanswerable — the first question asked during an incident."""
    text = COMPOSE_PROD.read_text()
    assert re.search(r"SATOM_IMAGE:\?", text), "SATOM_IMAGE must be required"
    # Comments stripped first. The file's own header explains that production
    # never uses ``:local``, so a raw search matches the sentence that states
    # the rule and fails against a correct file.
    directives = "\n".join(l for l in text.splitlines()
                           if not l.lstrip().startswith("#"))
    assert ":local" not in directives


def test_production_postgres_bind_is_explicit():
    """0.0.0.0 vs an explicit address is the whole difference between "the peer
    can reach it" and "everyone can"."""
    text = COMPOSE_PROD.read_text()
    assert "SATOM_PG_BIND:?" in text
    assert "0.0.0.0:5432" not in text


def test_standby_overlay_does_not_publish_postgres():
    """Without an explicit reset the standby INHERITS the primary's port list
    and publishes 5432 on the DMZ."""
    text = COMPOSE_STANDBY.read_text()
    assert "!reset" in text and "ports" in text


def test_standby_overlay_is_never_the_only_overlay():
    """It rebuilds PGDATA from a peer. Applied to a primary that is a wipe."""
    wrapper = WRAPPER.read_text()
    i_prod = wrapper.index("compose.prod.yaml")
    i_standby = wrapper.index("compose.standby.yaml")
    assert i_prod < i_standby, "prod overlay must be layered before standby"
    assert 'SATOM_NODE_ROLE:-primary}" = "standby"' in wrapper


def test_env_example_defines_every_required_variable():
    """A ``${VAR:?}`` that env.example does not mention is a stack that cannot
    start and an error message that names a variable found nowhere."""
    required = set()
    for f in (COMPOSE, COMPOSE_PROD, COMPOSE_STANDBY):
        required |= set(re.findall(r"\$\{([A-Z_][A-Z0-9_]*):\?", f.read_text()))
    declared = set(re.findall(r"^([A-Z_][A-Z0-9_]*)=", ENV_EXAMPLE.read_text(), re.M))
    assert required, "no required variables found — the regex drifted"
    assert required <= declared, f"undocumented: {sorted(required - declared)}"


# ---------------------------------------------------------------------------
# entrypoint / wrapper
# ---------------------------------------------------------------------------

def test_entrypoint_rejects_placeholder_secrets():
    """A published example file reaching production means every session cookie
    is forgeable and every stored device credential is decryptable."""
    text = ENTRYPOINT.read_text()
    assert "CHANGE_ME" in text
    assert "SECRET_KEY FERNET_KEY" in text or "FERNET_KEY" in text


def test_entrypoint_refuses_an_unknown_role():
    """Falling through to `web` gives two containers binding 8000 and a
    silently missing scheduler."""
    text = ENTRYPOINT.read_text()
    assert "unknown SATOM_ROLE" in text


def test_scheduler_role_is_primary_only():
    """Two nodes both firing a firmware-upgrade action means a double flash."""
    text = ENTRYPOINT.read_text()
    assert "node-role.sh" in text
    assert "app.scheduler_runtime" in text


@pytest.mark.parametrize("script", [
    "entrypoint.sh", "cron-runner.sh", "node-role.sh", "satom-docker.sh",
    "pg-standby-entrypoint.sh", "initdb.d/10-replication.sh",
])
def test_shipped_scripts_are_executable_with_a_shebang(script):
    p = DOCKER_DIR / script
    assert p.exists(), p
    assert p.read_text().startswith("#!"), f"{script} has no shebang"
    assert os.access(p, os.X_OK), f"{script} is not executable"


# ---------------------------------------------------------------------------
# Found by RUNNING the stack. Each of these passed every earlier check.
# ---------------------------------------------------------------------------

def test_only_the_listening_role_is_health_checked():
    """`scheduler` and `cron` do not listen; the image HEALTHCHECK curls :8000.

    Without an explicit disable they inherit it, sit at "starting", and settle
    on "unhealthy" forever. A health signal that is always red for a working
    container is worse than none — it teaches the operator to ignore the
    column meant to carry the alarm.
    """
    services = _yaml(COMPOSE)["services"]
    for name in ("scheduler", "cron"):
        hc = services[name].get("healthcheck")
        assert hc and hc.get("disable") is True, (
            f"{name} inherits the web healthcheck it can never pass"
        )
    assert "healthcheck" not in services["web"], (
        "web must keep the image healthcheck"
    )


def test_metrics_url_env_applies_without_an_app_context():
    """The scheduler sidecar imports vm_store with NO application context.

    The settings lookup raises there, and if the fallback lived only on the
    success path the sidecar would write every metric to a loopback store that
    does not exist in a container. Measured in the running dev stack: it
    returned http://127.0.0.1:8428 while SATOM_METRICS_URL was set correctly.
    """
    src = (ROOT / "app" / "services" / "vm_store.py").read_text()
    # The except branch must consult the environment, not return the constant.
    i = src.index("outside app context")
    tail = src[i:i + 700]
    assert "_env_url() or DEFAULT_URL" in tail, (
        "the no-app-context branch must still honour SATOM_METRICS_URL"
    )


def test_cron_runner_reports_a_real_exit_code():
    """`if ! cmd; then log "$?"` captures the status of the TEST, not the
    command — it printed "responder-tick FAILED (rc=0)" for a real failure,
    which invites the reader to dismiss the message as spurious."""
    text = (ROOT / "deploy" / "docker" / "cron-runner.sh").read_text()
    body = "\n".join(l for l in text.splitlines()
                     if not l.lstrip().startswith("#"))
    assert 'if ! python -m app.cli_sentinel responder-tick' not in body
    assert 'responder-tick || log' in body

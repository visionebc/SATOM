"""Which runtime this install is, and what it is therefore allowed to do.

SATOM has always been an appliance that administers its own host: it installs
unit files, reloads the host nginx, starts and stops node services and reads
``systemctl`` to describe its own health. A container image controls none of
those things. Packaging the app without saying so produces the worst possible
outcome -- an image that boots, answers ``/healthz`` 200, and has four menu
entries that fail (or, worse, *appear* to succeed) the first time an operator
needs them.

So the container variant RENOUNCES those capabilities explicitly, and every
surface that offers them asks here first.

Why an environment variable and not autodetection
-------------------------------------------------
``app.services.system_health.is_container()`` already exists and already
returns **True on the production HA nodes**: satom-node-1 and satom-node-2 are
LXC containers, and that helper answers the question it was written for --
"are /proc/loadavg and /proc/uptime describing someone else?". Keying these
capabilities off it would disable self-update, certificate activation and
service control on the two nodes that need them most, which is the exact
inverse of the intent. Measured on 2026-08-31: ``/run/systemd/container``
exists on both a1 and a2.

The runtime is therefore a DECLARATION, made by whoever built the image
(``ENV SATOM_RUNTIME=container`` in the Dockerfile), not an inference. A host
install never sets it and is unaffected -- the default is ``host``.

The operations agent: renounced by default, delegated when present
------------------------------------------------------------------
A container stack MAY run the optional operations agent
(``deploy/docker/compose.agent.yaml``): one container that holds the Docker
socket, reads requests the web drops into a volume, and re-validates each one
against a closed list before acting. With it, the capabilities in
:data:`AGENT_DELEGABLE` stop being denied and become DELEGATED -- the
enforcement point enqueues for the agent instead of refusing.

Delegation needs two things, and neither alone is enough:

* **a declaration** -- ``SATOM_AGENT=docker``, set by the overlay on the app
  services, for the same reason ``SATOM_RUNTIME`` is a declaration; and
* **a fresh heartbeat** -- the agent rewrites ``update-status/agent.heartbeat``
  every 15 s. A declared agent that stopped reporting is treated as absent:
  accepting a request nobody will ever execute is the exact failure this
  module was written to prevent ("queued" forever, an action the operator
  watched succeed that never happened).

``ha_promote`` is host-only and never delegable: promotion is a database role
change, and on a container node it stays a manual PostgreSQL procedure.

Adding a capability
-------------------
Add the name to :data:`HOST_ONLY_CAPABILITIES` *and* call :func:`require` (or
check :func:`capability`) at the point where the privileged work actually
happens. A capability that is declared but never consulted is decoration:
``tests/test_container_runtime.py`` fails if a name here has no call site.
Adding it to :data:`AGENT_DELEGABLE` as well is a privilege decision: the
enforcement point must then have an agent branch, and the agent must accept a
request kind for it.
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

CONTAINER = "container"
HOST = "host"
AGENT_DOCKER = "docker"

#: Capabilities that only a host install has. Each one is denied in the
#: container runtime because the work it performs reaches outside the process
#: tree the image controls.
HOST_ONLY_CAPABILITIES: tuple[str, ...] = (
    # satom-updater.service installs unit files and restarts services as root.
    # In a container the correct update is "replace the image", so offering the
    # in-place updater would be offering a broken second way to do it.
    "self_update",
    # systemctl start/stop/restart of the node's own units.
    "service_control",
    # Writes the node PKI and reloads the HOST nginx. The container stack DOES
    # serve TLS -- the `proxy` service terminates it with a certificate the
    # install issues for itself -- but that nginx lives in a sibling container
    # this process cannot reload, so activation from the UI stays denied and
    # the certificate is replaced through deploy/tls-bootstrap.sh instead.
    "cert_activation",
    # `systemctl is-active` over satom-*.service: there is no systemd here.
    "unit_health",
    # HA failover enqueues satom-promote.sh for the host runner. No container
    # process executes it, so accepting the request would report a failover
    # that never happens -- on the node the operator is trying to save.
    "ha_promote",
)

#: The subset the operations agent performs on the container's behalf.
AGENT_DELEGABLE: tuple[str, ...] = (
    "self_update", "service_control", "cert_activation", "unit_health")

#: Where the agent's heartbeat lands (the ``satom-agent-status`` volume is
#: mounted over ``data/update-status`` in the app containers).
AGENT_HEARTBEAT = (Path(__file__).resolve().parents[1]
                   / "data" / "update-status" / "agent.heartbeat")
#: Four missed beats. Long enough to survive a busy engine, short enough that a
#: dead agent is noticed before an operator queues something behind it.
AGENT_MAX_SILENCE = 60.0

#: Where the console offers the delegated operations.
CONTAINER_OPS_PAGE = "Global → Administrator → Container operations"

_WITHOUT_AGENT = (" The optional operations agent (deploy/docker/"
                  "compose.agent.yaml) performs it from the console.")

#: Operator-facing reason per capability. One author for the sentence: the UI,
#: the API error and the CLI all render THIS string, so they cannot drift.
_REASONS: dict[str, str] = {
    "self_update": (
        "In-place self-update is not available in the container runtime. "
        "Update by deploying a new image tag and recreating the stack."
        + _WITHOUT_AGENT
    ),
    "service_control": (
        "Service control is not available in the container runtime. "
        "Use the container engine (docker compose restart <service>) instead."
        + _WITHOUT_AGENT
    ),
    "cert_activation": (
        "Certificate activation is not available in the container runtime. "
        "This stack already serves TLS from its own proxy container; replace "
        "the certificate with 'deploy/tls-bootstrap.sh import-cert' and "
        "restart the proxy service." + _WITHOUT_AGENT
    ),
    "unit_health": (
        "systemd unit health is not available in the container runtime. "
        "Container health is reported by the container engine."
        + _WITHOUT_AGENT
    ),
    "ha_promote": (
        "Promotion is not available in the container runtime: no process in "
        "the stack executes it. Fail over by hand (docs/docker-compose.md "
        "§10.6)."
    ),
}

#: A git revision means nothing to a container, whose code is its image. With
#: the agent present the git updater still refuses -- and says where the
#: image update lives instead.
CONTAINER_UPDATE_REDIRECT = (
    "In the container runtime the code is the image: the git and library "
    "updaters do not apply. Switch the stack to another release from "
    + CONTAINER_OPS_PAGE + ".")


def runtime() -> str:
    """``"container"`` or ``"host"``.

    Only the exact value ``container`` (case-insensitive, whitespace stripped)
    selects the container runtime. Anything else -- unset, empty, a typo, a
    stray ``true`` -- means host, because a typo must not silently disable
    self-update on a real node.
    """
    return (CONTAINER
            if os.environ.get("SATOM_RUNTIME", "").strip().lower() == CONTAINER
            else HOST)


def is_container_runtime() -> bool:
    return runtime() == CONTAINER


def agent_declared() -> bool:
    """The stack says it runs the operations agent (container runtime only:
    a host install has its own root runner and never consults this)."""
    return (is_container_runtime()
            and os.environ.get("SATOM_AGENT", "").strip().lower() == AGENT_DOCKER)


def agent_state() -> dict:
    """The agent as the web sees it: declared, live, and its last heartbeat.

    Never raises. A heartbeat that is missing, unreadable or stale is reported
    as such -- the caller renders the reason, it does not guess.
    """
    out = {"declared": agent_declared(), "live": False, "age": None,
           "heartbeat": {}, "problem": ""}
    if not out["declared"]:
        return out
    try:
        doc = json.loads(AGENT_HEARTBEAT.read_text())
        ts = float(doc.get("ts"))
    except FileNotFoundError:
        out["problem"] = "the agent has never reported (no heartbeat file)"
        return out
    except Exception as exc:  # noqa: BLE001
        out["problem"] = "unreadable heartbeat: %s" % str(exc)[:120]
        return out
    age = time.time() - ts
    out["age"] = round(age, 1)
    out["heartbeat"] = doc if isinstance(doc, dict) else {}
    if age > AGENT_MAX_SILENCE:
        out["problem"] = "last heartbeat %d s ago" % age
    elif age < -AGENT_MAX_SILENCE:
        # A heartbeat from the future is a clock problem, not proof of life.
        out["problem"] = "heartbeat timestamp is %d s in the future" % -age
    else:
        out["live"] = True
    return out


def agent_live() -> bool:
    return agent_state()["live"]


def delegated(name: str) -> bool:
    """True when *name* is performed by the operations agent right now."""
    return (is_container_runtime() and name in AGENT_DELEGABLE
            and agent_live())


def capability(name: str) -> bool:
    """True when *name* is available in the current runtime.

    An unknown name is available: this gate exists to subtract capabilities in
    the container, not to become a second allowlist that silently swallows a
    feature nobody remembered to register.
    """
    if name not in HOST_ONLY_CAPABILITIES:
        return True
    if not is_container_runtime():
        return True
    return delegated(name)


def unavailable_reason(name: str) -> str:
    """The sentence shown to the operator, or '' when *name* is available."""
    if capability(name):
        return ""
    if name in AGENT_DELEGABLE and agent_declared():
        st = agent_state()
        return ("The operations agent is enabled but not answering (%s), so "
                "'%s' is unavailable until it is back. Check it with "
                "'satom-docker ps agent' and 'satom-docker logs agent'."
                % (st["problem"] or "no heartbeat", name))
    return _REASONS.get(
        name, f"'{name}' is not available in the container runtime.")


class CapabilityUnavailable(RuntimeError):
    """Raised by :func:`require`. Carries the operator-facing reason."""

    def __init__(self, name: str, reason: str):
        super().__init__(reason)
        self.capability = name
        self.reason = reason


def require(name: str) -> None:
    """Raise :class:`CapabilityUnavailable` when *name* is denied here.

    Callers that can render a message should prefer :func:`capability` and say
    so in the UI; this is for the paths where refusing loudly is the only
    correct answer.
    """
    if not capability(name):
        raise CapabilityUnavailable(name, unavailable_reason(name))


def summary() -> dict:
    """Machine-readable runtime description.

    Consumed by ``deploy/docker/satom-docker.sh health``. Kept separate from
    the capability accessors so a caller that wants to RENDER the state does
    not have to know the capability names."""
    st = agent_state()
    return {
        "runtime": runtime(),
        "capabilities": {n: capability(n) for n in HOST_ONLY_CAPABILITIES},
        "delegated": {n: delegated(n) for n in AGENT_DELEGABLE},
        "reasons": {n: unavailable_reason(n)
                    for n in HOST_ONLY_CAPABILITIES
                    if not capability(n)},
        "agent": {"declared": st["declared"], "live": st["live"],
                  "age": st["age"], "problem": st["problem"],
                  "version": st["heartbeat"].get("agent_version", "")},
    }

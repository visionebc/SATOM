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

Adding a capability
-------------------
Add the name to :data:`HOST_ONLY_CAPABILITIES` *and* call :func:`require` (or
check :func:`capability`) at the point where the privileged work actually
happens. A capability that is declared but never consulted is decoration:
``tests/test_container_runtime.py`` fails if a name here has no call site.
"""
from __future__ import annotations

import os

CONTAINER = "container"
HOST = "host"

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
    # Writes the node PKI and reloads the HOST nginx. In the container variant
    # TLS is terminated by the reverse proxy in front of the stack.
    "cert_activation",
    # `systemctl is-active` over satom-*.service: there is no systemd here.
    "unit_health",
)

#: Operator-facing reason per capability. One author for the sentence: the UI,
#: the API error and the CLI all render THIS string, so they cannot drift.
_REASONS: dict[str, str] = {
    "self_update": (
        "In-place self-update is not available in the container runtime. "
        "Update by deploying a new image tag and recreating the stack."
    ),
    "service_control": (
        "Service control is not available in the container runtime. "
        "Use the container engine (docker compose restart <service>) instead."
    ),
    "cert_activation": (
        "Certificate activation is not available in the container runtime. "
        "TLS is terminated by the reverse proxy in front of this stack; "
        "install the certificate there."
    ),
    "unit_health": (
        "systemd unit health is not available in the container runtime. "
        "Container health is reported by the container engine."
    ),
}


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


def capability(name: str) -> bool:
    """True when *name* is available in the current runtime.

    An unknown name is available: this gate exists to subtract capabilities in
    the container, not to become a second allowlist that silently swallows a
    feature nobody remembered to register.
    """
    if name not in HOST_ONLY_CAPABILITIES:
        return True
    return not is_container_runtime()


def unavailable_reason(name: str) -> str:
    """The sentence shown to the operator, or '' when *name* is available."""
    if capability(name):
        return ""
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
    return {
        "runtime": runtime(),
        "capabilities": {n: capability(n) for n in HOST_ONLY_CAPABILITIES},
        "reasons": {n: unavailable_reason(n)
                    for n in HOST_ONLY_CAPABILITIES
                    if not capability(n)},
    }

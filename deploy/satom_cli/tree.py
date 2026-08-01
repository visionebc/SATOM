"""The command registry.

THIS FILE IS THE EXTENSION POINT. Adding a command is one ``Node`` entry — the
parser, the ``?`` help, tab completion, the privilege gate and the JSON output
all read this structure and none of them need to change. The same contract the
rest of the product already uses for ``registry_endpoints``, ``adoms`` and
``acme_dns_providers``: behaviour is DATA.

``tests/test_cli.py`` walks this tree and fails the suite if any node lacks
help text or a declared privilege level. A command that forgets to say it needs
root would otherwise fail with a traceback for an unprivileged operator — the
one moment a traceback is least useful.
"""
from . import cmd_diagnose as d
from . import cmd_execute as e
from . import cmd_get as g
from . import cmd_show as s


class Node:
    __slots__ = ("name", "help", "run", "needs_root", "children", "usage", "danger")

    def __init__(self, name, help, run=None, needs_root=False, children=None,
                 usage="", danger=False):
        self.name = name
        self.help = help
        self.run = run
        self.needs_root = needs_root
        self.children = children or {}
        self.usage = usage
        self.danger = danger


def _n(name, help, **kw):
    return name, Node(name, help, **kw)


def _group(name, help, *kids):
    return name, Node(name, help, children=dict(kids))


ROOT = Node("satom", "SATOM operator CLI", children=dict([
    _group("get", "Read state. Works as any user.",
        _group("system", "This node.",
            _n("status", "Identity, version, HA role and your privilege level.", run=g.system_status),
            _n("health", "One-shot roll-up: units, /healthz, disk. Start here.", run=g.system_health),
            _n("performance", "CPU, memory and filesystem usage.", run=g.system_performance),
            _n("interface", "IP addresses and the ports SATOM cares about.", run=g.system_interface),
        ),
        _group("service", "systemd units.",
            _n("status", "State of one unit, or all of them.", run=g.service_status,
               usage="get service status [<service>]"),
        ),
        _group("node", "High availability.",
            _n("status", "Role, peer list and peer reachability over :8443.", run=g.node_status),
        ),
        _group("database", "PostgreSQL.",
            _n("status", "Connection, size, replication.", run=g.database_status),
        ),
        _group("certificate", "TLS.",
            _n("status", "Served certificate, expiry and the renewal journal.",
               run=g.certificate_status),
        ),
        _n("log", "Tail a unit's journal.", run=g.log_show,
           usage="get log <service> [lines]"),
    ),

    _group("show", "Dump configuration and the privilege model. Any user.",
        _n("config", "The .env, with secrets redacted.", run=s.config),
        _n("units", "Alias -> systemd unit map, with install state.", run=s.units),
        _n("privilege", "How privilege is split here, and why. Read this first.",
           run=s.privilege),
        _n("sudoers", "Print the sudoers rule to request for an operator account.",
           run=s.sudoers, usage="show sudoers [<account>]"),
        _n("version", "Versions of the app, the CLI and Python.", run=s.version),
    ),

    _group("diagnose", "Active probes that answer 'why is it broken'. Any user.",
        _n("all", "Every check, folded into one exit code.", run=d.all_checks),
        _n("service", "One unit: state, definition, drop-ins, journal.",
           run=d.service, usage="diagnose service <service>"),
        _n("database", "Connect, replication role, TLS, lock waits.", run=d.database),
        _n("python", "venv integrity, compileall, and the LAZY-import smoke test.",
           run=d.python),
        _n("network", "Listening ports, nginx -t, local HTTPS probe.", run=d.network),
        _n("certificate", "Expiry, live handshake, renewal timer result.", run=d.certificate),
        _n("peer", "Peer reachability, datasync key and timer.", run=d.peer),
        _n("privilege", "Integrity of the CLI install and the sudo boundary.",
           run=d.privilege),
    ),

    _group("execute", "Change state. Requires root.",
        _n("restart", "Restart a service and VERIFY it actually came back.",
           run=e.restart, needs_root=True, usage="execute restart <service>"),
        _n("start", "Start a service.", run=e.start, needs_root=True,
           usage="execute start <service>"),
        _n("stop", "Stop a service.", run=e.stop, needs_root=True,
           usage="execute stop <service>"),
        _group("reload", "Reload without dropping state.",
            _n("nginx", "Validate the config, then reload nginx.",
               run=e.reload_nginx, needs_root=True),
        ),
        _group("update", "Code and dependency updates (via the privileged queue).",
            _n("code", "Queue a git update for the privileged runner.",
               run=e.update_code, needs_root=True, usage="execute update code [<target>]"),
            _n("pip", "Queue a curated-allowlist package change. Node-local.",
               run=e.update_pip, needs_root=True,
               usage="execute update pip <package> <version>"),
            _n("status", "Show the latest (or a specific) update record.",
               run=e.update_status, usage="execute update status [<id>]"),
        ),
        _group("reinstall", "Rebuild a piece of the installation in place.",
            _n("venv", "Recreate venv/ from requirements.txt, keeping a freeze to roll back to.",
               run=e.reinstall_venv, needs_root=True, danger=True),
            _n("units", "Re-copy the systemd units AND re-pin User= via drop-in.",
               run=e.reinstall_units, needs_root=True),
            _n("cli", "Refresh the root-owned copy of this CLI from the repo.",
               run=e.reinstall_cli, needs_root=True),
        ),
        _group("repair", "Fix state that drifted.",
            _n("permissions", "Give root-owned files in the app tree back to the service account.",
               run=e.repair_permissions, needs_root=True),
        ),
        _group("cert", "Certificate operations.",
            _n("renew", "Run the renewal pass now instead of waiting for 03:30.",
               run=e.cert_renew, needs_root=True),
        ),
        _group("alerts", "Alert engine.",
            _n("run", "Evaluate the health checks now.", run=e.alerts_run,
               needs_root=True, usage="execute alerts run [--dry-run]"),
        ),
        _group("backup", "Backups.",
            _n("db", "pg_dump the application database into data/system_backups/.",
               run=e.backup_db, needs_root=True),
        ),
        _n("preflight", "Capture a health baseline BEFORE a risky change.",
           run=e.preflight, needs_root=True, usage="execute preflight [<label>]"),
        _n("postflight", "Diff the current health against the last preflight.",
           run=e.postflight, needs_root=True),
        _n("promote", "Promote this standby to primary. Requires --yes.",
           run=e.promote, needs_root=True, danger=True),
    ),
]))


def walk(node=ROOT, path=()):
    """Yield (path_tuple, node) for every node. Used by the tests and by help."""
    yield path, node
    for name, child in node.children.items():
        for item in walk(child, path + (name,)):
            yield item

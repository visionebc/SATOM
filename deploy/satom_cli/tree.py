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
from . import cmd_checks as k
from . import cmd_diagnose as d
from . import cmd_docs as b
from . import cmd_execute as e
from . import cmd_fix as f
from . import cmd_get as g
from . import cmd_ops as o
from . import cmd_show as s
from . import cmd_tree as t


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
            _n("disk", "Space, inodes, and the directories that actually grow.", run=o.system_disk),
            _n("time", "Clock and NTP. Skew breaks TLS, ACME and every 'age' here.",
               run=o.system_time),
        ),
        _group("service", "systemd units.",
            _n("status", "State of one unit, or all of them.", run=g.service_status,
               usage="get service status [<service>]"),
        ),
        _group("timer", "Timers and .path units — the automation that has no UI.",
            _n("status", "Enabled, last fire, next fire, last result.", run=o.timer_status),
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
            _n("list", "Every certificate this node holds, not just the served one.",
               run=o.certificate_list),
        ),
        _group("backup", "The four copies.",
            _n("status", "All four, side by side, with their real ages.", run=o.backup_status),
            _n("list", "Database bundles you can hand to 'execute restore db'.",
               run=o.backup_list),
        ),
        _group("scheduler", "Scheduled actions.",
            _n("status", "What exists, when it last ran, what is overdue.",
               run=o.scheduler_status),
        ),
        _group("device", "Managed appliances.",
            _n("status", "Sync state, maintenance flag, last contact.", run=o.device_status),
        ),
        _group("monitor", "Probes.",
            _n("status", "Probe states, and how much coverage is disabled.",
               run=o.monitor_status),
        ),
        _group("job", "Background jobs.",
            _n("list", "The ledger, including ghosts that keep the dock's toast open.",
               run=o.job_list),
        ),
        _group("update", "Self-update records.",
            _n("history", "Recent updates and whether the runner ever picked them up.",
               run=o.update_history),
        ),
        _group("git", "The repository on this node.",
            _n("status", "Branch, drift, unpushed age, parked safety refs.",
               run=o.git_status),
        ),
        _group("user", "Accounts.",
            _n("list", "Who can log in — and whether anyone still can.", run=o.user_list),
        ),
        _group("alerts", "Alerting.",
            _n("status", "Whether anyone is actually told when something breaks.",
               run=o.alerts_status),
        ),
        _n("log", "Tail a unit's journal.", run=g.log_show,
           usage="get log <service> [lines]"),
    ),

    _group("show", "Configuration and reference. Any user, no probing.",
        _n("config", "The .env, with secrets redacted.", run=s.config),
        _n("units", "Alias -> systemd unit map, with install state.", run=s.units),
        _n("services", "What each unit is FOR, and which ones are off limits.",
           run=b.services),
        _n("paths", "Canonical filesystem layout: what is replicated, what is not.",
           run=b.paths),
        _n("ports", "Which port belongs to which listener, and why.", run=b.ports),
        _n("schedule", "What SHOULD run and how often.", run=b.schedule),
        _n("runbook", "Offline recovery procedures. 'show runbook' lists them.",
           run=b.runbook, usage="show runbook [<topic>]"),
        _n("privilege", "How privilege is split here, and why. Read this first.",
           run=s.privilege),
        _n("sudoers", "Print the sudoers rule to request for an operator account.",
           run=s.sudoers, usage="show sudoers [<account>]"),
        _n("changelog", "The most recent release notes from the tree.", run=b.changelog),
        _n("version", "Versions of the app, the CLI and Python.", run=s.version),
        _n("tree", "The WHOLE command tree in one view. Filters: --commands/--depth/--root.",
           run=t.tree,
           usage="show tree [<prefix>...] [--commands] [--depth N] [--root] [--danger]"),
    ),

    _group("diagnose", "Active probes that answer 'why is it broken'. Any user.",
        _n("all", "Every check, folded into one exit code.", run=d.all_checks),
        _n("service", "One unit: state, definition, drop-ins, journal.",
           run=d.service, usage="diagnose service <service>"),
        _n("install", "Is this node ARMED, or merely installed? Run on day one.",
           run=k.install),
        _n("code", "Is each process running the code that is on disk?", run=k.code),
        _n("scheduler", "Is anything automated actually firing here?", run=k.scheduler),
        _n("units", "Unit inventory and whether the privilege model survived.",
           run=k.units),
        _n("config", "The .env: present, correctly owned, internally consistent.",
           run=k.config),
        _n("database", "Connect, replication role, TLS, lock waits.", run=d.database),
        _n("python", "venv integrity, compileall, and the LAZY-import smoke test.",
           run=d.python),
        _n("network", "Listening ports, nginx -t, local HTTPS probe.", run=d.network),
        _n("nginx", "Syntax, which vhost wins :443, and the ACME redirect trap.",
           run=k.nginx),
        _n("certificate", "Expiry, live handshake, renewal timer result.", run=d.certificate),
        _n("acme", "Client, account key, webroot, provider credentials.", run=k.acme),
        _n("peer", "Peer reachability, datasync key and timer.", run=d.peer),
        _n("git", "Repository integrity, including the root-owned-files trap.",
           run=k.git),
        _n("privilege", "Integrity of the CLI install and the sudo boundary.",
           run=d.privilege),
    ),

    _group("execute", "Change state. Requires root.",
        _n("restart", "Restart a service and VERIFY it actually came back.",
           run=e.restart, needs_root=True, usage="execute restart <service>"),
        _n("restart-all", "Restart the whole stack in order, then verify /healthz.",
           run=f.restart_all, needs_root=True),
        _n("start", "Start a service.", run=e.start, needs_root=True,
           usage="execute start <service>"),
        _n("stop", "Stop a service.", run=e.stop, needs_root=True,
           usage="execute stop <service>"),
        _n("enable", "Enable a timer or .path unit (--now).", run=f.enable,
           needs_root=True, usage="execute enable <unit>"),
        _n("disable", "Disable a timer. Refuses the privileged runner.",
           run=f.disable, needs_root=True, usage="execute disable <unit>"),
        _group("reload", "Reload without dropping state.",
            _n("nginx", "Validate the config, then reload nginx.",
               run=e.reload_nginx, needs_root=True),
        ),
        _group("seed", "Create state a fresh install does NOT create for you.",
            _n("actions", "The minimum scheduled actions. Shows the plan; --yes applies.",
               run=f.seed_actions, needs_root=True, usage="execute seed actions [--yes]"),
        ),
        _group("update", "Code and dependency updates (via the privileged queue).",
            _n("code", "Queue a git update — or a rollback, by passing a commit.",
               run=e.update_code, needs_root=True, usage="execute update code [<target>]"),
            _n("pip", "Queue a curated-allowlist package change. Node-local.",
               run=e.update_pip, needs_root=True,
               usage="execute update pip <package> <version>"),
            _n("status", "Show the latest (or a specific) update record.",
               run=e.update_status, usage="execute update status [<id>]"),
        ),
        _group("reinstall", "Rebuild a piece of the installation in place.",
            _n("venv", "Recreate venv/ from requirements.txt. Needs --yes; keeps a freeze to roll back to.",
               run=e.reinstall_venv, needs_root=True, danger=True),
            _n("units", "Re-copy the systemd units AND re-pin User= via drop-in.",
               run=e.reinstall_units, needs_root=True),
            _n("cli", "Refresh the root-owned copy of this CLI from the repo.",
               run=e.reinstall_cli, needs_root=True),
        ),
        _group("repair", "Fix state that drifted.",
            _n("permissions", "Give root-owned files in the app tree back to the service account.",
               run=e.repair_permissions, needs_root=True),
            _n("jobs", "Sweep ghost jobs and prune the terminated ledger.",
               run=f.repair_jobs, needs_root=True,
               usage="execute repair jobs [--older-than N] [--yes]", danger=True),
            _n("tmp", "Delete aged scratch under data/tmp. Nothing else prunes it.",
               run=f.repair_tmp, needs_root=True,
               usage="execute repair tmp [--older-than N] [--yes]", danger=True),
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
            _n("git", "git bundle --all, including the parked safety refs.",
               run=f.backup_git, needs_root=True),
        ),
        _group("restore", "Put a backup back.",
            _n("db", "Replace the database from a bundle. Dumps the current one first.",
               run=f.restore_db, needs_root=True, danger=True,
               usage="execute restore db <file> --yes"),
        ),
        _group("admin", "Accounts, for when nobody can log in.",
            _n("reset-password", "Set a password (asked interactively, never in argv).",
               run=f.admin_reset_password, needs_root=True,
               usage="execute admin reset-password <username>"),
            _n("unlock", "Clear a lockout without touching the password.",
               run=f.admin_unlock, needs_root=True,
               usage="execute admin unlock <username>"),
        ),
        _group("scheduler", "Scheduled actions.",
            _n("run", "Fire one action NOW as a manual run.", run=f.scheduler_run,
               needs_root=True, usage="execute scheduler run <action-id>"),
            _n("enable", "Enable one action.", run=f.scheduler_enable,
               needs_root=True, usage="execute scheduler enable <action-id>"),
            _n("disable", "Disable one action.", run=f.scheduler_disable,
               needs_root=True, usage="execute scheduler disable <action-id>"),
        ),
        _group("support", "Hand-off.",
            _n("bundle", "Collect every diagnostic and journal into one 0600 file.",
               run=f.support_bundle, needs_root=True),
        ),
        _n("maintenance", "Park or un-park an appliance.", run=f.maintenance,
           needs_root=True, usage="execute maintenance <device> <on|off>"),
        _n("preflight", "Capture a health baseline BEFORE a risky change.",
           run=e.preflight, needs_root=True, usage="execute preflight [<label>]"),
        _n("postflight", "Diff the current health against the last preflight.",
           run=e.postflight, needs_root=True),
        _n("promote", "Promote this standby to primary. Requires --yes.",
           run=e.promote, needs_root=True, danger=True),
    ),
    _n("tree", "The whole command tree. Alias for 'show tree'.",
       run=t.tree,
       usage="tree [<prefix>...] [--commands] [--depth N] [--root] [--danger]"),
]))


def walk(node=ROOT, path=()):
    """Yield (path_tuple, node) for every node. Used by the tests and by help."""
    yield path, node
    for name, child in node.children.items():
        for item in walk(child, path + (name,)):
            yield item

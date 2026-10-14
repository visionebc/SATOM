"""Which ``diagnose`` commands SATOM may send — one classifier, three callers.

``diagnose`` is not a read verb. Measured in the lab on 2026-10-14, the
``diagnose`` trees of fgt02 (FortiGate 8.0.1, 3,199 commands) and faz02
(FortiAnalyzer 7.6.7, 545) carry ``diagnose debug kernel sysrq command crash``,
``diagnose ha failover device-id``, ``diagnose dvm device delete adom device``,
``diagnose debug crashlog clear`` and ``diagnose sniffer packet`` (which never
returns). Until this module, :func:`app.services.ssh_ops.assert_readonly`
accepted every one of them from the console and the custom-command box.

Two strengths, one rule set:

* :func:`blocked_reason` (``strict=False``) — the console, the custom box and
  every internal caller. Refuses a command that names a state-changing verb
  (kill, clear, reset, delete, failover, crash, format, reboot, set, enable…).
* ``strict=True`` — a diagnostic BATTERY, which runs unattended on many devices
  in one go. Adds the commands that never return (top, sniffer, debug flow…),
  the ones that send traffic (ping, traceroute) and ``diagnose test``.
* :func:`blocked_by_description` — the discovery walk also has the help text
  the device prints next to each entry ("Kill a process.", "Reset HA up time.",
  "Generate one system info log file every 2 minutes."), which catches state
  changes whose NAME says nothing (``sysinfo-log``, ``dump-conserve-info``).

Abbreviations. FortiOS runs ``diag sys kil 11 1`` as ``diagnose sys kill``: the
CLI completes any unique prefix. A token is therefore refused when it is a
blocked word OR a prefix of one, unless it is a full word the products really
use (``ha`` is a prefix of ``halt``; ``sys`` of ``sysrq``). Hyphenated names are
split, so ``reset-uptime`` and ``sync-stats-reset`` read as ``reset``.

Pure and network-free; ``tests/test_diag_policy.py`` pins it.
"""
from __future__ import annotations

import re

# Verbs that change the device (or its debug state) when they appear anywhere
# in a ``diagnose`` command. Matched per token, abbreviations included.
STATE_WORDS: frozenset[str] = frozenset({
    "kill", "killall", "pkill", "clear", "reset", "delete", "del", "remove",
    "rm", "rmmod", "insmod", "modprobe", "flush", "purge", "erase", "wipe",
    "format", "formatlogdisk", "fsck", "repair", "restart", "reboot",
    "shutdown", "halt", "poweroff", "crash", "panic", "sysrq", "failover",
    "takeover", "force", "set", "unset", "enable", "disable", "start", "stop",
    "upload", "download", "export", "import", "backup", "restore", "install",
    "uninstall", "unload", "rebuild", "reindex", "recalculate",
    "reload", "trigger", "generate", "rotate", "truncate", "write", "init",
    "reinit", "cleanup", "clean", "deregister", "register",
    "unregister", "authorize", "deauthorize", "unauthorize", "approve",
    "reject", "filter", "update-now", "upgrade", "downgrade",
    "shut", "renew", "revoke", "block", "unblock", "quarantine", "add",
    "drop-cache", "fips",
    # FortiAuthenticator lists debug LEVELS as children of each daemon under
    # ``diagnose debug application <daemon>``: debugall/traceall set them.
    "debugall",
})

# Only refused in a battery: harmless one at a time at a console, but in an
# unattended multi-device run they never return, flood the session or send
# traffic out of the device.
BATTERY_WORDS: frozenset[str] = frozenset({
    "top", "top-all", "iotop", "perftop", "mpstat", "sniffer", "tcpdump",
    "capture", "trace", "flow", "ping", "ping6", "traceroute", "tracert",
    "test", "krb_test", "follow", "tail", "realtime",
    "real-time", "console",
})

# Full words the five products use that happen to be prefixes of a word above
# (derived from the fgt02 8.0.1 and faz02 7.6.7 ``diagnose`` trees and the
# FortiWeb/FortiADC/FortiAuthenticator help captured on 2026-10-14). Without
# this list the abbreviation rule would refuse ``diagnose sys ha status``
# (``ha`` -> ``halt``, ``sys`` -> ``sysrq``). Words that are ALSO a plausible
# abbreviation of something dangerous (``sn`` -> sniffer, ``exp`` -> export,
# ``reg`` -> register, ``im``/``in`` -> import/install, ``to`` -> top) stay
# out: spelling the full word is the price of not running the other one.
# Where each one is a real word: ``ha`` and ``sys`` (fgt02 ``diagnose sys ha
# status``), ``perf`` (FortiWeb ``diagnose system perf``), ``tcp`` (FortiWeb
# ``diagnose network tcp``), ``update`` (FortiWeb ``diagnose system update
# info``), ``auth`` (fgt02 ``diagnose firewall auth list``). ``app`` was listed
# too, but neither tree nor any help capture has it as a word; it only ever
# stood for ``application`` — or for ``approve``.
SAFE_WORDS: frozenset[str] = frozenset({
    "ha", "sys", "perf", "tcp", "auth", "update",
    # ``debug`` is the branch every product has; it is a prefix of
    # ``debugall`` (a FortiAuthenticator debug level) only by accident.
    "debug",
})

# Help-text openings that mean "this changes something". Matched against the
# description the device prints in ``?`` output, case-insensitively.
_DESC_RE = re.compile(
    # A verb opening the description, as a whole word: "load-balance.virtual-
    # server" (FortiADC) is not "load", hence the (?![-.]\w) after the group.
    # "switch", "update" and a bare "dump … to" are not here: FortiGate says
    # "Switch information.", "Update object versions." and "Dump Global CA used
    # to build cert chain." about read-only commands (2026-10-14 walks).
    r"^\s*(kill|killall|reset|clear|delete|remove|restart|reboot|shut ?down|"
    r"set(?!/get)|unset|enable|disable|start|stop|force|format|erase|flush|"
    r"purge|generate|backup|upload|export|import|repair|check and repair|"
    r"recalculate|rebuild|reload|trigger|install|uninstall|load|unload|"
    r"crash(?!\s*log)|"
    r"failover|take ?over|sync now|renew|revoke|block|unblock|"
    r"deregister|register|unregister|authori[sz]e|approve|reject|add|"
    r"capture|sniff|trace|ping|traceroute|run|execute|exec|test|simulate|"
    r"inject|send|wipe|truncate|rotate|write|break|drop|insert|"
    r"activate|deactivate|toggle)\b(?![-.]\w)"
    r"|replacing|every \d+ (?:second|minute|hour)s?"
    r"|\bto (?:disk|file|ftp|tftp|usb)\b"
    r"|set/get|set or get|get/set",
    re.I)

_SPLIT = re.compile(r"[-_.]")
_VERB_RE = re.compile(r"^(diagnose|diag)$", re.I)


def _tokens(command: str) -> list[str]:
    return [t for t in (command or "").strip().lower().split() if t]


# A hyphenated name that opens with a read verb, or closes with a read noun
# while its verb sits in the middle, reports on the thing it names:
# ``hcache-auto-rebuild-status`` and ``show-dev-upgrade-path`` (faz02 7.6.7)
# are reads. A name that OPENS with a state verb is always judged a write,
# whatever it ends with: ``reset-health-status`` is FortiGate's "Reset HA
# health". That keeps ``rebuild-status`` refused too -- the price of not
# guessing which of the two a name is.
_READ_HEADS = frozenset({"show", "get", "list", "display", "print"})
# Refused when spelled, never the target of an abbreviation: every prefix of
# ``debugall`` is also a prefix of ``debug``, the branch all five products have.
_NO_ABBREV = frozenset({"debugall"})
_READ_TAILS = frozenset({"status", "info", "list", "stats", "stat", "show"})


def _word_hit(tok: str, words: frozenset[str]) -> tuple[str, str] | None:
    """``(word, how)`` when ``tok`` spells a blocked word, else None.

    ``how``: ``exact``; ``part`` (a hyphenated part, or the verb with "all"
    glued on: ``reset-uptime``, ``traceall`` -- fac01 lists ``diagnose debug
    application <daemon> traceall``); ``abbrev`` (the CLI completes a unique
    prefix: ``kil`` runs ``kill``).
    """
    if tok in words:
        return tok, "exact"
    if tok.endswith("all") and tok[:-3] in words:
        return tok[:-3], "part"
    parts = [p for p in _SPLIT.split(tok) if p]
    if len(parts) > 1 and (parts[0] in words or (
            parts[0] not in _READ_HEADS and parts[-1] not in _READ_TAILS)):
        for p in parts:
            if p in words:
                return p, "part"
            if p.endswith("all") and p[:-3] in words:
                return p[:-3], "part"
    if tok in SAFE_WORDS or tok.isdigit() or len(tok) < 2:
        return None
    for w in sorted(words, key=lambda x: (len(x), x)):
        if w in _NO_ABBREV:
            continue
        if w.startswith(tok) and w != tok:
            return w, "abbrev"
    return None


def blocked_reason(command: str, *, strict: bool = False) -> str | None:
    """Why ``command`` may not be sent, or None when it may.

    Only ``diagnose``/``diag`` statements are judged here; the verb gate itself
    (``get``/``show``/``diagnose`` only) stays in ``ssh_ops.assert_readonly``.
    The first token is the verb and is skipped; argument tokens are judged like
    any other, because FortiOS does not distinguish keyword from argument
    until it parses the line.
    """
    toks = _tokens(command)
    if not toks or not _VERB_RE.match(toks[0]):
        return None
    for tok in toks[1:]:
        hit = _word_hit(tok, STATE_WORDS)
        if hit:
            word, how = hit
            if how == "exact":
                return f"'{tok}' changes the device state"
            if how == "part":
                return f"'{tok}' contains '{word}', which changes the device state"
            return f"'{tok}' reads as '{word}', which changes the device state"
        if strict:
            hit = _word_hit(tok, BATTERY_WORDS)
            if hit:
                return (f"'{tok}' runs until interrupted, floods the session or "
                        f"sends traffic, so it cannot run in an unattended battery")
    return None


def blocked_by_description(description: str) -> str | None:
    """Why the help text marks a command as state-changing, or None."""
    d = (description or "").strip()
    if not d:
        return None
    m = _DESC_RE.search(d)
    if not m:
        return None
    return f"the device describes it as “{d[:80]}”"


def battery_reason(command: str, description: str = "") -> str | None:
    """The full battery verdict: name (strict) first, then help text.

    A description that only repeats a SAFE word's own name (FortiWeb lists
    ``update    update``) says nothing the name rule has not already judged, so
    it is not read as a verb: without this, FortiWeb's ``diagnose system
    update`` — parent of the battery's ``diagnose system update info`` — was
    refused because the shell echoed its name. Any other echoed name is still
    read (a node called ``send`` described as "send" stays refused).
    """
    why = blocked_reason(command, strict=True)
    if why:
        return why
    toks = _tokens(command)
    if (toks and toks[-1] in SAFE_WORDS
            and (description or "").strip().rstrip(".").strip().lower() == toks[-1]):
        return None
    return blocked_by_description(description)


__all__ = ["STATE_WORDS", "BATTERY_WORDS", "SAFE_WORDS", "blocked_reason",
           "blocked_by_description", "battery_reason"]

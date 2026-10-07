"""FortiAuthenticator: CLI help walk + ``show full-configuration`` + Tastypie schema.

Measured on fac01 (FACVMKVM v8.0.3 build0099, 2026-10-07):

* **No ``tree``.** ``tree`` answers ``No such command.``. FAC's CLI is a
  BOOTSTRAP CLI: ``config ?`` offers ``router`` and ``system``, and below them
  five objects (``router static``, ``system dns|global|ha|interface``). The
  schema of each object is what ``set ?`` prints inside it: one line per field,
  ``name  <type or a|b|c options>`` plus indented help lines. That walk IS the
  CLI schema of the build, and it is stored as ``cli_tree`` evidence with
  ``summary.format = "fac_help"``.
* **``show full-configuration`` == ``show``**: the five bootstrap blocks, values
  included (names only are kept, as for every product).
* **REST is a different world.** The Tastypie directory ``/api/v1/`` lists 58
  resources (users, groups, tokens, RADIUS/TACACS+ clients, policies, a few
  system settings such as SNMP and syslog). None of them is one of the five
  CLI objects. The directory is complete by construction (Tastypie publishes
  every registered resource), so ``apilib_fac`` marks its evidence
  ``summary.directory_complete`` and ``api_library.channels_at`` then reads a
  CLI object that the directory does not list as REST "no" -> ``cli_only``.

So on FAC the CLI-only set is SMALL and exact (the bootstrap fields), and the
REST-only set is everything else: the GUI/REST holds the product's
configuration, the CLI only what is needed to put the box on the network.

The walk is read-only by construction (:func:`assert_help_step`): it enters
``config <object>`` (and ``edit <row>`` for a row the box itself listed), asks
``?`` / ``set ?``, clears the line with Ctrl-U, and DROPS THE SESSION. It never
sends ``set <field> <value>``, ``next``, ``end`` or ``abort``; an object's
pending edit buffer dies with the session, so nothing can be committed.

SSH credential: SATOM's FortiAuthenticator appliance secret is the REST API key
(web-service access), which does not log into the CLI. The CLI channel
therefore runs only when the caller hands an SSH secret for this one harvest
(never stored) or injects readers; otherwise it is reported as skipped, by name.
"""
from __future__ import annotations

import logging
import re
from datetime import datetime

from . import Adapter, Capabilities, Verification, register

_log = logging.getLogger(__name__)

PRODUCT = "fortiauthenticator"
FORMAT = "fac_help"
#: FAC prints five bootstrap objects; a walk that found fewer than this read
#: nothing useful (wrong prompt, refused session).
MIN_OBJECTS = 3
#: How deep ``config a b c d`` may go while discovering objects.
MAX_DEPTH = 4
#: Ctrl-U: clears the typed line after a ``?`` so nothing is ever executed.
KILL_LINE = "\x15"

_ANSI = re.compile(r"\x1b\[[0-9;?]*[a-zA-Z]")
_WORD = r"[a-z0-9][a-z0-9-]*"
_ASK_RE = re.compile(r"^(?:\?|set \?|edit \?|config(?: %s){0,%d} \?)$" % (_WORD, MAX_DEPTH))
_ENTER_CONFIG_RE = re.compile(r"^config(?: %s){1,%d}$" % (_WORD, MAX_DEPTH))
_ROW_RE = re.compile(r"^[A-Za-z0-9_.:/-]{1,64}$")
# ``  router              config router information.``
_LISTING_RE = re.compile(r"^ {1,4}(%s)\s{2,}\S" % _WORD)
# ``  \tprimary          <IP of Primary DNS>`` / ``hb-lost-threshold <threshold_integer>``
# / ``  \tdevice           interface name`` (no angle brackets): the name
# starts right after the tab; a help line has more blanks after it.
_FIELD_RE = re.compile(r"^ {0,4}\t?(?P<name>[a-z][a-z0-9_-]*) +(?P<spec><[^<>]*>|\S[^<>]*?)\s*$")
_HELP_RE = re.compile(r"^ {0,4}\t {2,}(?P<text>\S.*?)\s*$")
_HELP_RANGE = re.compile(r"\((-?\d+)\s*-\s*(-?\d+)\s*[,)]")
_OPTION_TOKEN = re.compile(r"^[a-z0-9][a-z0-9_-]*$")
# ``> `` at the root, ``(dns): `` inside an object.
_PROMPT_TAIL = re.compile(r"(?:^|\n)\s*(?:>|\([^()\s]+\):) ?$")


class HelpWalkViolation(Exception):
    """A help-walk step that is not on the allow-list was refused before sending."""


def assert_help_step(cmd: str, rows=()) -> str:
    """Return ``cmd`` if it is a permitted help-walk step, else raise.

    Allowed, whole-line: ``?``, ``set ?``, ``edit ?``, ``config [words] ?``,
    ``config <words>`` (enter an object) and ``edit <row>`` for a row the box
    listed under ``edit ?`` (an existing row: entering a NEW id would create it
    on ``next``/``end``, which the walk never sends anyway). Everything else --
    ``set x y``, ``unset``, ``next``, ``end``, ``abort``, ``execute`` -- is refused.
    """
    c = (cmd or "").strip()
    if "\n" in c or "\r" in c or ";" in c:
        raise HelpWalkViolation("refused %r: one step per line" % (cmd or "")[:80])
    if _ASK_RE.match(c) or _ENTER_CONFIG_RE.match(c):
        return c
    if c.startswith("edit "):
        row = c[5:].strip()
        if row in set(rows or ()) and _ROW_RE.match(row):
            return c
    raise HelpWalkViolation("refused %r: not a help-walk step" % (cmd or "")[:80])


# --------------------------------------------------------------------------- #
#  Pure parsers                                                                #
# --------------------------------------------------------------------------- #
def _clean(text: str) -> str:
    return _ANSI.sub("", text or "").replace("\r", "")


def parse_listing(text: str) -> tuple[list, bool]:
    """``config <prefix> ?`` -> ``(child words, is_object)``.

    ``is_object`` = the help offered ``<Enter>``: ``config <prefix>`` is
    complete, i.e. an object.
    """
    words, enter = [], False
    for line in _clean(text).split("\n"):
        if line.strip() == "<Enter>":
            enter = True
            continue
        m = _LISTING_RE.match(line)
        if m and m.group(1) not in words:
            words.append(m.group(1))
    return words, enter


def parse_commands(text: str) -> list:
    """``?`` inside ``config X`` -> the command words (``set``, ``edit``, ...)."""
    return parse_listing(text)[0]


def parse_rows(text: str) -> tuple:
    """``edit ?`` -> ``(mkey, rows)``: the existing rows the box lists (used to
    ENTER one, never stored).

    A table with a named key prints the key name first, then a description
    line (``seq-num`` / ``0 for new route`` on ``router static``); a table
    without prints the rows only (``port1`` on ``system interface``).
    """
    lines = [ln.strip().strip("\x00") for ln in _clean(text).split("\n")[1:]]
    lines = [ln for ln in lines if ln]
    mkey, rows = None, []
    for i, tok in enumerate(lines):
        if "(" in tok or tok.endswith(":") or tok == "edit" or re.search(r"[>:] ?edit ?$", tok):
            continue
        if " " in tok:
            continue                               # a description line
        nxt = lines[i + 1] if i + 1 < len(lines) else ""
        if not rows and mkey is None and " " in nxt and "(" not in nxt:
            mkey = tok                             # header: key name + description
            continue
        if _ROW_RE.match(tok) and tok not in rows:
            rows.append(tok)
    return mkey, rows


def _type_of(spec: str, options) -> str | None:
    if options:
        return "option"
    s = spec.lower()
    if "domain" in s or "," in s:
        return "string"                 # ``<ip address, domain name>``: free text
    if "ip/netmask" in s:
        return "ipmask"
    if re.search(r"\bip\b", s):
        return "ip"
    if "password" in s:
        return "password"
    if re.search(r"integer|\bmtu\b|\blevel\b|_index\b|\bindex\b", s):
        return "integer"
    if "name" in s or "domain" in s or "address" in s:
        return "string"
    return "string"


def _options_of(spec: str):
    for sep in ("|", "/"):
        if sep in spec:
            toks = [t.strip() for t in spec.split(sep)]
            if len(toks) >= 2 and all(_OPTION_TOKEN.match(t) for t in toks):
                return toks
    return None


def parse_set_help(text: str) -> dict:
    """``set ?`` inside an object -> ``{field: {"type", "options", "attrs"}}``.

    ``attrs.cli_type`` keeps the raw ``<...>`` text; ``attrs.help`` the
    indented description lines, EXCEPT ``e.g.`` example lines (a vendor
    example is not a default, and it may carry addresses); ``attrs.range``
    when the help states one (``time between heartbeats (1-20, x100ms)``).
    """
    fields: dict = {}
    current = None
    for line in _clean(text).replace("\x00", "").split("\n"):
        h = _HELP_RE.match(line)
        if h and current:
            t = h.group("text")
            if not t.startswith("e.g."):
                attrs = fields[current]["attrs"]
                attrs["help"] = (attrs["help"] + " " + t) if attrs.get("help") else t
                rng = _HELP_RANGE.search(t)
                if rng and "range" not in attrs:
                    attrs["range"] = [int(rng.group(1)), int(rng.group(2))]
            continue
        m = _FIELD_RE.match(line) if "\t" in line[:6] or line[:1] != " " else None
        if m and m.group("name") not in ("set", "unset"):
            name, spec = m.group("name"), m.group("spec").strip()
            inner = spec[1:-1].strip() if spec.startswith("<") else spec
            opts = _options_of(inner)
            fields.setdefault(name, {"type": _type_of(inner, opts), "options": opts,
                                     "attrs": {"cli_type": spec if spec.startswith("<")
                                               else "<%s>" % spec}})
            current = name
            continue
        current = None
    return fields


def parse_walk(walk: dict) -> dict:
    """A recorded help walk -> the :func:`cli_schema.parse_tree` result shape.

    ``walk = {"objects": {cli_path: {"kind", "set_help", "read", "reason"}}, ...}``.
    An object whose fields could not be read (an empty table: no row to enter)
    is kept with no fields and listed in ``unread``.
    """
    objects, unread = {}, []
    for path in sorted((walk or {}).get("objects") or {}):
        rec = walk["objects"][path]
        words = path.split()
        kind = rec.get("kind") or "singleton"
        fields = parse_set_help(rec.get("set_help") or "") if rec.get("read") else {}
        if not rec.get("read"):
            unread.append(path)
        objects[path] = {"cli_path": path, "kind": kind,
                         "kind_chain": ["namespace"] * (len(words) - 1) + [kind],
                         "mkey": rec.get("mkey") or None, "cli_id": None, "parent": "",
                         "fields": fields}
    nfields = sum(len(o["fields"]) for o in objects.values())
    return {"format": FORMAT, "objects": objects, "unread": unread, "counts": {
        "objects": len(objects),
        "tables": sum(1 for o in objects.values() if o["kind"] == "table"),
        "singletons": sum(1 for o in objects.values() if o["kind"] == "singleton"),
        "fields": nfields,
        "enum_fields": sum(1 for o in objects.values() for s in o["fields"].values()
                           if s.get("options")),
        "datasource_fields": 0,
    }}


# --------------------------------------------------------------------------- #
#  Evidence                                                                    #
# --------------------------------------------------------------------------- #
def evidence_from_walk(walk: dict, version: str, build: str, device: dict | None,
                       origin_ref: str, *, captured_at: str = "") -> dict:
    """Help walk -> ``cli_tree`` evidence (``summary.format = "fac_help"``)."""
    from .. import cli_schema
    parsed = parse_walk(walk)
    doc = cli_schema.evidence_from_cli_tree(
        PRODUCT, version, build, "", device, origin_ref, captured_at=captured_at,
        truncated=not (walk or {}).get("complete", False), parsed=parsed,
        min_objects=MIN_OBJECTS)
    doc["summary"]["format"] = FORMAT
    doc["summary"]["unread"] = parsed["unread"]
    doc["summary"]["source_command"] = "config <object> + set ? (FAC has no tree)"
    if doc["skip_reason"].startswith("the tree output was cut short"):
        doc["skip_reason"] = "the CLI help walk did not complete: %s" % (
            (walk or {}).get("error") or "a step got no answer")
    return doc


def evidence_from_full(full_text: str, version: str, build: str, device: dict | None,
                       origin_ref: str, *, walk: dict | None = None,
                       captured_at: str = "", lab: bool = False) -> dict:
    """``show full-configuration`` -> ``cli_full`` evidence (names only)."""
    from .. import cli_schema
    tree = parse_walk(walk) if walk and walk.get("complete") else None
    doc = cli_schema.evidence_from_cli_full(
        PRODUCT, version, build, full_text, device, origin_ref, captured_at=captured_at,
        tree=tree, lab=lab, min_objects=MIN_OBJECTS)
    if lab:
        doc["summary"]["lab"] = True
    return doc


# --------------------------------------------------------------------------- #
#  Live walk                                                                   #
# --------------------------------------------------------------------------- #
def _session_class():
    from .. import ssh_ops

    class _HelpSSH(ssh_ops.FortiWebReadonlySSH):
        """FAC CLI session for the help walk: no pager change, no ``exit``."""

        rows: tuple = ()

        def _disable_pager(self) -> None:   # FAC has no ``config system console``
            return None

        def close(self) -> None:
            # Drop the transport. Never ``end``/``exit``: an object entered for
            # its help is left, uncommitted, with the session.
            try:
                if self._client:
                    self._client.close()
            finally:
                self._client = self._shell = None

        def _read_tail(self, done, maxt: float) -> str:
            """Read until the cleaned buffer's tail matches ``done`` (the box
            re-printed its prompt), bounded by ``maxt``. Quiet is not an end:
            fac01 pauses over a second before some help answers."""
            import time
            buf, start = "", time.time()
            while time.time() - start < maxt:
                if self._shell.recv_ready():
                    buf += self._shell.recv(16384).decode("utf-8", "replace")
                    if done.search(_clean(buf)):
                        time.sleep(0.2)
                        while self._shell.recv_ready():
                            buf += self._shell.recv(16384).decode("utf-8", "replace")
                        break
                else:
                    time.sleep(0.1)
            return buf

        def ask(self, cmd: str, maxt: float = 20.0) -> str:
            c = assert_help_step(cmd)
            if not c.endswith("?"):
                raise HelpWalkViolation("ask() takes a '?' step, got %r" % c)
            # After the help the box re-prints the prompt and the typed text
            # (without the ``?``): that is the end of the answer. The text and
            # the ``?`` go in two writes: fac01 sometimes ignores a ``?`` that
            # arrives in the same packet as the words before it.
            typed = re.escape(c[:-1].rstrip())
            done = re.compile(r"\n[^\n]*[>:] ?%s ?$" % typed)
            out = ""
            for _attempt in range(2):
                self._shell.send(c[:-1])
                self._read(quiet=0.3, maxt=2)
                self._shell.send("?")
                out = self._read_tail(done, maxt / 2)
                self._shell.send(KILL_LINE)
                self._read(quiet=0.5, maxt=3)
                if done.search(_clean(out)):
                    break
            return out

        def enter(self, cmd: str, rows=(), maxt: float = 20.0) -> str:
            c = assert_help_step(cmd, rows)
            if c.endswith("?"):
                raise HelpWalkViolation("enter() takes an object step, got %r" % c)
            self._shell.send(c + "\n")
            return self._read_tail(_PROMPT_TAIL, maxt)

    return _HelpSSH


def walk_cli(appliance, secret: str, *, session_factory=None, timeout: float = 15.0) -> dict:
    """Walk FAC's CLI help, read-only. Returns the walk record (never values).

    One session discovers the objects (``config ... ?``); then one FRESH session
    per object enters it, asks ``?`` (table or singleton), for a table enters
    the first row the box lists, asks ``set ?`` and is dropped.
    """
    factory = session_factory or (lambda: _session_class()(appliance, secret,
                                                           timeout=timeout).connect())
    out = {"objects": {}, "complete": False, "error": "", "skipped": []}
    try:
        s = factory()
        try:
            found, todo = [], [""]
            while todo:
                prefix = todo.pop(0)
                if len(prefix.split()) >= MAX_DEPTH:
                    continue
                words, is_obj = parse_listing(s.ask(("config %s ?" % prefix).replace("  ", " ")))
                # No answer at all is a CANDIDATE too: fac01 sometimes ignores a
                # second ``?`` on a path it already completed (measured on
                # ``config system ha ?``). Entering it decides below.
                if prefix and (is_obj or not words):
                    found.append(prefix)
                todo += [("%s %s" % (prefix, w)).strip() for w in words]
        finally:
            s.close()
        for path in found:
            s = factory()
            try:
                entered = _clean(s.enter("config " + path))
                if not re.search(r"\(%s\): ?$" % re.escape(path.split()[-1]), entered):
                    out["skipped"].append(path)       # not an object after all
                    continue
                cmds = parse_commands(s.ask("?"))
                rec = {"kind": "table" if "edit" in cmds else "singleton",
                       "read": False, "reason": "", "set_help": ""}
                if rec["kind"] == "table":
                    mkey, rows = parse_rows(s.ask("edit ?"))
                    rec["mkey"] = mkey
                    inside = False
                    for row in rows[:3]:
                        ans = _clean(s.enter("edit " + row, rows=rows))
                        if re.search(r"\(%s\): ?$" % re.escape(row), ans):
                            inside = True
                            break
                    if not inside:
                        rec["reason"] = "empty table: no row to enter for its fields"
                        out["objects"][path] = rec
                        continue
                help_text = s.ask("set ?")
                rec["set_help"] = _clean(help_text)
                rec["read"] = bool(parse_set_help(help_text))
                if not rec["read"]:
                    rec["reason"] = "set ? listed no field"
                out["objects"][path] = rec
            finally:
                s.close()
        out["complete"] = bool(out["objects"])
        if not out["objects"]:
            out["error"] = "config ? listed no object"
    except Exception as exc:  # noqa: BLE001 — recorded as an incomplete walk
        out["error"] = ("%s: %s" % (type(exc).__name__, exc))[:300]
    return out


def show_full(appliance, secret: str, *, timeout: float = 15.0, maxt: float = 120.0) -> str:
    """``show full-configuration`` over the same read-only session class, read
    until FAC's prompt comes back (``> ``), echo and prompt stripped."""
    from .. import ssh_ops
    cmd = ssh_ops.assert_readonly("show full-configuration")
    s = _session_class()(appliance, secret, timeout=timeout).connect()
    try:
        s._shell.send(cmd + "\n")
        raw = s._read_tail(_PROMPT_TAIL, maxt)
    finally:
        s.close()
    return strip_session(raw, cmd)


def strip_session(raw: str, cmd: str) -> str:
    """Drop the echoed command and FAC's prompt lines (``>``, ``(x):``)."""
    lines = _clean(raw).replace("\x00", "").split("\n")
    if lines and lines[0].strip() == cmd:
        lines = lines[1:]
    return "\n".join(ln for ln in lines if not _PROMPT_TAIL.match(ln.strip())).strip() + "\n"


# --------------------------------------------------------------------------- #
#  Harvest                                                                     #
# --------------------------------------------------------------------------- #
def harvest(appliance, *, ssh_secret: str | None = None, walk_reader=None, full_reader=None,
            rest: bool = True, rest_client=None, lab: bool = False,
            now: datetime | None = None, **_ignored) -> dict:
    """FAC through both channels. NEVER raises.

    ``ok`` = the CLI schema of the build is stored healthy; when no SSH secret
    and no reader is available the CLI channel is SKIPPED (named in ``msg``) and
    ``ok`` reflects the REST schema alone.
    """
    from .. import api_library as lib
    from .. import apilib_fac
    from .. import firmware_versions as fv
    now = now or datetime.utcnow()
    name = getattr(appliance, "name", "") or "?"
    out = {"ok": False, "appliance": name, "product": PRODUCT, "version": "",
           "tree": None, "full": None, "rest": None, "channels": None}
    try:
        raw_fw = getattr(appliance, "fw_version", "") or getattr(appliance, "firmware", "") or ""
        version = fv.normalize(raw_fw)
        if not version or fv.is_line_only(version):
            return dict(out, reason="firmware_unknown",
                        msg="the running build of %s is unknown" % name)
        out["version"] = version
        build = apilib_fac.parse_build(getattr(appliance, "firmware", "") or raw_fw)
        device = apilib_fac.device_block(appliance)
        captured = now.isoformat(timespec="seconds")
        origin = "schema_adapter:%s@%s" % (getattr(appliance, "id", ""), version)

        if rest:
            raw: dict = {}
            doc = apilib_fac.harvest(appliance, client=rest_client, raw=raw)
            res = lib.ingest(doc, raw=raw or None)
            out["rest"] = {"evidence_id": res["evidence_id"], "healthy": doc["healthy"],
                           "skip_reason": doc["skip_reason"],
                           "resources": len(doc.get("endpoints") or {})}

        can_cli = bool(ssh_secret) or walk_reader is not None
        if can_cli:
            walk = (walk_reader(appliance) if walk_reader is not None
                    else walk_cli(appliance, ssh_secret))
            tdoc = evidence_from_walk(walk, version, build, device, origin + ":tree",
                                      captured_at=captured)
            # The walk record holds help text only (no rows, no values).
            tres = lib.ingest(tdoc, raw={"doc": tdoc, "walk": walk})
            out["tree"] = {"evidence_id": tres["evidence_id"], "healthy": tdoc["healthy"],
                           "skip_reason": tdoc["skip_reason"],
                           "counts": tdoc["summary"].get("counts") or {},
                           "unread": tdoc["summary"].get("unread") or []}
            try:
                full_text = (full_reader(appliance) if full_reader is not None
                             else show_full(appliance, ssh_secret))
                ferr = ""
            except Exception as exc:  # noqa: BLE001
                full_text, ferr = "", "%s: %s" % (type(exc).__name__, exc)
            fdoc = evidence_from_full(full_text, version, build, device, origin + ":full",
                                      walk=walk if tdoc["healthy"] else None,
                                      captured_at=captured, lab=lab)
            if ferr:
                fdoc.update(healthy=False, endpoints={},
                            skip_reason=("show full-configuration failed: %s" % ferr)[:500])
            fres = lib.ingest(fdoc, raw=None)
            out["full"] = {"evidence_id": fres["evidence_id"], "healthy": fdoc["healthy"],
                           "skip_reason": fdoc["skip_reason"],
                           "counts": fdoc["summary"].get("counts") or {}}
        out["channels"] = lib.channels_at(PRODUCT, version)["summary"]
    except Exception as exc:  # noqa: BLE001 — a harvest never raises
        try:
            from ...extensions import db
            db.session.rollback()
        except Exception:  # noqa: BLE001
            pass
        _log.warning("FAC schema harvest of %s failed: %s", name, exc, exc_info=True)
        return dict(out, reason="error", msg=("%s: %s" % (type(exc).__name__, exc))[:300])
    ch = out["channels"] or {}
    tree = out["tree"]
    if tree is None:
        rest_ok = bool((out["rest"] or {}).get("healthy"))
        return dict(out, ok=rest_ok, reason="" if rest_ok else "unhealthy", cli_skipped=True,
                    msg="FAC %s: REST schema %s; CLI channel skipped (SATOM stores the "
                        "REST API key for FortiAuthenticator, not a CLI login: pass an SSH "
                        "secret for this harvest)" % (version, "stored" if rest_ok
                                                      else "NOT healthy"))
    if not tree["healthy"]:
        return dict(out, reason="unhealthy",
                    msg="CLI help walk of %s stored as unhealthy: %s" % (name, tree["skip_reason"]))
    return dict(out, ok=True, msg=(
        "FAC schema harvest of %s (%s): %d CLI objects, %d CLI fields; channels "
        "both=%d cli_only=%d hidden=%d rest_only=%d unknown=%d"
        % (name, version, (tree.get("counts") or {}).get("objects", 0),
           (tree.get("counts") or {}).get("fields", 0), ch.get("both", 0),
           ch.get("cli_only", 0), ch.get("hidden", 0), ch.get("rest_only", 0),
           ch.get("unknown", 0))))


ADAPTER = register(Adapter(
    product=PRODUCT, label="FortiAuthenticator",
    capabilities=Capabilities(tree=True, show_full=True, rest_schema=True, rest_probe=False),
    verified_on=(Verification("2026-10-07", "fac01 (lab)", "8.0.3 build0099",
                              "help walk + show full-configuration + Tastypie schema"),),
    live=True,
    notes="No `tree`: the CLI schema is the `set ?` help of the five bootstrap "
          "objects. The Tastypie directory is complete, so CLI objects it does not "
          "list are cli_only. The CLI channel needs an SSH secret per harvest "
          "(SATOM stores the REST API key)."),
    harvest)


__all__ = ["PRODUCT", "FORMAT", "HelpWalkViolation", "assert_help_step", "parse_listing",
           "parse_commands", "parse_rows", "parse_set_help", "parse_walk", "evidence_from_walk",
           "evidence_from_full", "walk_cli", "show_full", "harvest", "ADAPTER"]

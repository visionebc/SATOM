"""Plugin Studio > Apps -- the SATOM steps: DDI, capacity, certificates, FortiWeb.

The generic steps (``studio_flow``) call APIs, query data stores and walk
Processes. The steps here act on things SATOM itself owns -- the fleet, its
capacity limits, the Certificate Manager -- and on the DDI API (FA-0007), so
an administrator can draw the whole "new server policy" chain as ONE diagram
and decide, arrow by arrow, what happens when a step fails.

WHAT EACH STEP OWNS -- AND WHAT IT DOES NOT
-------------------------------------------
Every step is an adapter over the module that already answers its question:

* ``fortiweb_pick``   -- :func:`capacity.headroom` decides whether a device has
  room; this step only walks the fleet in list order and takes the first.
* ``certificate``     -- :func:`cert_manager.create_certificate` issues (with the
  provider the user picked); an existing certificate is deployed by
  :func:`cert_manager.deploy_existing`. Neither is ever revoked by a diagram.
* ``fortiweb_spo``    -- the same create endpoints and the same writer
  (:class:`fortiweb_ops.FortiWebOps`) as the SPO wizard, so ChangeHistory, the
  audit log and the device cache follow every object.
* ``ddi_reserve`` / ``ddi_release`` -- the DDI API over a Studio HTTP
  connection (its URL, user, password or token are the connection's).

THE ROLLBACK RULE
-----------------
A step that writes returns what it CREATED, and only that is ever undone:
``ddi_release`` deletes a record only when ``created`` is true (a record the
DDI already held is reused and never deleted), ``fortiweb_spo_remove``
deletes only the objects its ``fortiweb_spo`` step wrote. ``fortiweb_spo``
also cleans up after ITSELF when one of its objects fails, so a half-built
policy never stays on the device. Where a rollback goes is the diagram's
``error`` arrows -- the administrator's decision, not this module's.

DEVICE WRITES NEED config_write
-------------------------------
An app is visible to the people the administrator ticked, who need not hold
``config_write``. A step here that writes to a DEVICE is refused for a user
without it (the ``process`` step's rule), and a rehearsal describes it
instead of sending it.
"""
from __future__ import annotations

import ipaddress
import re

from . import studio_flow as F

GROUP = "satom"

#: Steps that change something outside the run (rehearsal describes them).
WRITE_KINDS = ("ddi_reserve", "ddi_reserve_set", "ddi_release", "certificate",
               "fortiweb_spo", "fortiweb_spo_remove")
#: Of those, the ones that write to an appliance (need config_write).
DEVICE_KINDS = ("certificate", "fortiweb_spo", "fortiweb_spo_remove")

#: ``satom_select`` form-field sources: what a list field may offer.
SOURCES = (
    ("fortiweb", "FortiWeb appliances"),
    ("fortiweb_pools", "FortiWeb server pools (local cache)"),
    ("fortiweb_interfaces", "FortiWeb interfaces (local cache)"),
    ("fortiweb_certificates", "FortiWeb local certificates (local cache)"),
    ("wpp_templates", "Approved Web Protection Profile templates"),
    ("certificates", "Certificate Manager certificates (usable)"),
    ("cert_providers", "Certificate providers"),
    ("zones", "Classification: zones"),
    ("lines", "Classification: lines"),
    ("departments", "Classification: departments"),
    ("segments", "Network segments"),
)
SOURCE_KEYS = tuple(k for k, _ in SOURCES)
KIND_KEYS = ("render_names", "ddi_reserve", "ddi_reserve_set", "ddi_release",
             "fortiweb_pick", "certificate", "fortiweb_spo", "fortiweb_spo_remove")

_SPO_ORDER = ("vserver", "vip", "pool", "pserver", "policy")


# --------------------------------------------------------------------------- #
#  the step kinds                                                              #
# --------------------------------------------------------------------------- #
def kinds(ch: dict | None = None) -> list:
    ch = ch or {}
    P, K = F.Param, F.Kind
    conn = lambda: P("connection", "DDI connection", "select", True,  # noqa: E731
                     tuple(ch.get("http", ())), help="A Studio HTTP connection to the DDI API.")
    return [
        K("render_names", "Render names", GROUP,
          "Build object names from patterns -- {extra}, {service}, {port}, {dns}, {spo} or any "
          "value you pass. An empty value takes its dash with it (spo-{extra}-x with no extra "
          "is spo-x), and a name FortiWeb would refuse is an error.",
          [P("patterns", "Patterns", required=True,
             help='{{ name_rules }} (rows with object + pattern) or JSON '
                  '{"server_policy": "spo-{extra}-{service}-{port}"}'),
           P("values", "Values (JSON)", "json", True,
             help='{"extra": "{{ form.extra }}", "service": "{{ form.dns | replace(\'.\', \'_\') }}"}'),
           F._save_as("names")]),
        K("ddi_reserve_set", "DDI: reserve by rules", GROUP,
          "Reserve one record per rule, in the rules' order (the master unit first). A rule "
          "takes a free address from its subnets, or the address another unit of this step "
          "already got (ip_from). If one rule fails, the records this step created are "
          "deleted again and the step ends in error.",
          [conn(),
           P("rules", "Rules", required=True,
             help="{{ ddi_rules }} -- rows with unit, name (pattern), subnets, ip_from, role"),
           P("values", "Values for the name patterns (JSON)", "json", True,
             help='{"dns": "{{ form.dns }}", "extra": "{{ form.extra }}"}'),
           P("ttl", "TTL (s)"), P("device_class", "Device class", default="server"),
           P("description", "Description"), P("change_log", "Change log message"),
           P("mode", "Addresses", default="reserve",
             help="reserve = free addresses from the DDI; given = the addresses below, and "
                  "the DDI is not called at all -- or {{ form.address_mode }}."),
           P("given", "Given addresses (JSON)", "json",
             help='Mode given: {"internal": "{{ form.internal_ip }}", "external": '
                  '"{{ form.external_ip }}"} -- keys are units or roles; each rule takes its '
                  "unit's or role's address (or ip_from's)."),
           F._save_as("ddi")], writes=True),
        K("ddi_reserve", "DDI: reserve an address", GROUP,
          "Reserve an A record (IPAM) in one DDI unit: reuse the name if the unit "
          "already holds it, else take the next free address of the first subnet "
          "that has one -- or register a given address (the same IP in another unit).",
          [conn(),
           P("unit", "DDI unit", required=True, help="e.g. bn, or {{ form.unit }}"),
           P("name", "Record name", required=True, help="e.g. use-{{ form.dns }}.used"),
           P("subnets", "Subnets (one per line, in order)", "textarea",
             help="Where a free address is searched. Empty when an address is given."),
           P("ip", "Use this address", help="e.g. {{ ddi_bn.ip }}: register it instead of "
                                            "searching (the same IP in another unit)."),
           P("ttl", "TTL (s)"), P("device_class", "Device class", default="server"),
           P("description", "Description"), P("change_log", "Change log message"),
           F._save_as("ddi")], writes=True),
        K("ddi_release", "DDI: release reservations", GROUP,
          "Delete the records that ddi_reserve steps CREATED in this run (a reused "
          "record is never deleted). For the error branch of a diagram.",
          [conn(),
           P("reservations", "Reservations", required=True,
             help="e.g. {{ [ddi_bn, ddi_inet] }} -- results of ddi_reserve steps; "
                  "a missing one is skipped."),
           P("change_log", "Change log message"), F._save_as("released")], writes=True),
        K("fortiweb_pick", "Pick a FortiWeb by capacity", GROUP,
          "The FIRST FortiWeb in the fleet list (by name) whose classification matches "
          "and whose capacity limit (Capacity page) has room for the new objects.",
          [P("zone", "Zone", help="e.g. Internal, or {{ form.zone }}; empty = any"),
           P("line", "Line"), P("department", "Department"),
           P("object", "Counted object", "select",
             choices=("server_policy", "certificate", "web_protection_profile"),
             default="server_policy"),
           P("needed", "Objects to create", default="1"),
           P("exclude", "Exclude appliance (id or name)",
             help="e.g. {{ fwb_internal.id }} -- for a second, different device."),
           P("requires", "Objects the device must have (JSON)", "json",
             help='JSON object; a device without one of them is skipped, an empty value '
                  'is ignored. Keys: certificate, server_pool, interface, '
                  'web_protection_profile (a template id or a name), e.g. '
                  '{"certificate": "{{ form.device_cert }}", '
                  '"server_pool": "{{ form.existing_pool }}"}'),
           F._save_as("fortiweb")]),
        K("certificate", "Certificate (issue or reuse)", GROUP,
          "Issue a certificate with the chosen provider and deploy it to the "
          "appliance, deploy one that already exists in the Certificate Manager, "
          "or use one that is already on the appliance (device: nothing is written).",
          [P("mode", "Mode", default="issue",
             help="issue, existing or device -- or {{ form.cert_mode }}"),
           P("provider", "Provider",
             help="Issue only: a provider key (Certificate Manager › Providers), e.g. "
                  "{{ form.cert_provider }}. Empty = the first provider."),
           P("cert_class", "Certificate class", "select",
             choices=("server", "clientserver", "client"), default="server"),
           P("common_name", "Common name", help="Issue only, e.g. {{ form.dns }}"),
           P("sans", "Extra SANs", help="Comma separated."),
           P("existing", "Existing certificate (id or name)",
             help="existing: a Certificate Manager id or name; device: the name of a local "
                  "certificate on the appliance, e.g. {{ form.certificate }}"),
           P("appliance", "Appliance (id or name)", required=True,
             help="e.g. {{ fortiweb.id }}"),
           P("zone", "Zone of the policy", help="A provider marked internal-only "
                                                "refuses any zone but Internal."),
           F._save_as("certificate")], writes=True),
        K("fortiweb_spo", "FortiWeb: create the server policy", GROUP,
          "Virtual server, VIP, server pool and members (or an existing pool), the "
          "service of the port when it is not the predefined one, then the server "
          "policy -- in that order. If one object fails, the ones this step wrote are "
          "deleted again and the step ends in error.",
          [P("appliance", "Appliance (id or name)", required=True, help="{{ fortiweb.id }}"),
           P("names", "Names (JSON)", "json", True,
             help='{"server_policy": "{{ spo }}", "virtual_server": "vs-{{ spo }}", '
                  '"vip": "vip-{{ spo }}", "server_pool": "pool-{{ spo }}"} -- optional '
                  '"service": the custom service of a non-standard port.'),
           P("vip", "VIP address", required=True, help="e.g. {{ ddi_bn.ip }}/32"),
           P("interface", "Interface", required=True, help="e.g. port1"),
           P("port", "Port the policy listens on",
             help="e.g. {{ form.port }}. 443 with a certificate / 80 without = the predefined "
                  "service; another port = a custom service (reused when the device has it). "
                  "Empty = the predefined one."),
           P("pool_mode", "Server pool", default="new",
             help="new = create the pool and its members; existing = bind a pool the device "
                  "already has (it is never changed or removed) -- or {{ form.pool_mode }}."),
           P("existing_pool", "Existing server pool", help="e.g. {{ form.existing_pool }}"),
           P("members", "Pool members (JSON)", "json",
             help='[{"ip": "{{ form.backend }}", "port": "{{ form.backend_port }}"}]'),
           P("wpp", "Web Protection Profile", help="Template id or profile name, "
                                                   "e.g. {{ form.wpp }}; empty = none."),
           P("certificate", "Certificate on the device", help="e.g. {{ certificate.name }}; "
                                                              "empty = HTTP only."),
           P("extra", "Extra policy fields (JSON)", "json",
             help='e.g. {"comments": "{{ form.comment }}"}'),
           F._save_as("spo")], writes=True),
        K("fortiweb_spo_remove", "FortiWeb: remove a created policy", GROUP,
          "Delete what a fortiweb_spo step of this run created, newest first. "
          "For the error branch of a diagram.",
          [P("spo", "Created policy", required=True, help="e.g. {{ spo_internal }}"),
           F._save_as("removed")], writes=True),
    ]


def choices() -> dict:
    """Picker values for the editor: provider keys."""
    try:
        from . import cert_providers as CP
        return {"cert_providers": [p["key"] for p in CP.providers()]}
    except Exception:  # noqa: BLE001 -- the editor must open without settings
        return {"cert_providers": []}


def writes(kind: str) -> bool:
    return kind in WRITE_KINDS


# --------------------------------------------------------------------------- #
#  DDI -- database-free, ``call(method, path, query, body) -> (status, data)``  #
# --------------------------------------------------------------------------- #
class DdiError(F.FlowError):
    pass


def ddi_rows(data) -> list[dict]:
    """A list answer, or one wrapped in a common envelope."""
    if isinstance(data, list):
        return [r for r in data if isinstance(r, dict)]
    if isinstance(data, dict):
        for k in ("items", "data", "results", "records", "rows", "result"):
            if isinstance(data.get(k), list):
                return [r for r in data[k] if isinstance(r, dict)]
        if data.get("rrOwner") or data.get("uid"):
            return [data]
    return []


def said(data) -> str:
    if isinstance(data, dict):
        d = data.get("detail")
        if isinstance(d, list):
            return "; ".join(str((x or {}).get("msg", x)) for x in d[:3])
        for k in ("detail", "message"):
            if data.get(k):
                return str(data[k])[:300]
    return (str(data)[:300] if data not in (None, "") else "")


def _same_name(a, b) -> bool:
    return str(a or "").rstrip(".").lower() == str(b or "").rstrip(".").lower()


def ddi_record(call, name: str, unit: str) -> dict:
    """The IPAM A record ``unit`` holds under ``name``, or ``{}``."""
    st, data = call("GET", "/api/dnsrr", {"ddiUnit": unit, "rrOwner": name,
                                          "rrType": "A", "category": "ipam"}, None)
    if not 200 <= st < 300:
        raise DdiError("DDI lookup of %s in %s answered HTTP %d %s" % (name, unit, st, said(data)))
    for r in ddi_rows(data):
        if _same_name(r.get("rrOwner"), name) and (r.get("rrData") or r.get("ip")):
            return r
    return {}


def _check_ip(ip: str, subnet: str = "") -> str:
    try:
        addr = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        raise DdiError("the DDI returned %r, which is not an IP address" % ip) from None
    if subnet and "/" in subnet:
        try:
            net = ipaddress.ip_network(subnet.strip(), strict=False)
        except ValueError:
            return str(addr)
        if addr not in net:
            raise DdiError("the DDI returned %s, outside the subnet %s" % (addr, subnet))
    return str(addr)


def _result(rec: dict, *, unit, name, created, subnet="", tried=None) -> dict:
    return {"unit": unit, "name": name, "ip": str(rec.get("rrData") or rec.get("ip") or ""),
            "uid": str(rec.get("uid") or ""), "created": bool(created), "manual": False,
            "subnet": subnet, "tried": tried or []}


def ddi_reserve(call, *, unit: str, name: str, subnets=(), ip: str = "", ttl=None,
                device_class: str = "", description: str = "", change_log: str = "") -> dict:
    """Reserve ``name`` in ``unit``. Order, each part paid for in Policy Clone:

    1. **The name first.** A record the unit already holds IS the reservation:
       reused, ``created: false`` -- so a rollback never deletes it, and a
       second press never burns a second address.
    2. **A given address** (the same IP in another unit) is registered with
       ``POST /api/dnsrr`` (category ipam).
    3. **Else each subnet in order** with ``POST /api/dnsrr/allocate``, which
       finds AND assigns in one call (the API has no dry run).
    4. **The record decides, not the answer's words** (Policy Clone 1.58.0):
       after every 2xx the name is looked up again; a record there is the
       reservation whatever ``status_code`` said. A lookup that fails after an
       accepted allocate stops everything -- whether the address was taken
       cannot be known, so no other subnet is asked.
    """
    unit, name = str(unit or "").strip(), str(name or "").strip()
    if not unit:
        raise DdiError("no DDI unit was given")
    if not name:
        raise DdiError("no record name was given")
    have = ddi_record(call, name, unit)
    if have:
        got = _check_ip(have.get("rrData") or have.get("ip") or "")
        if ip and got != str(ip).strip():
            raise DdiError("%s already exists in %s with %s, not %s -- it was not changed"
                           % (name, unit, got, ip))
        return _result(have, unit=unit, name=name, created=False)
    common = {"rrOwner": name, "ddiUnit": unit, "description": description or "",
              "changeLogMsg": change_log or ""}
    if device_class:
        common["deviceClass"] = device_class
    if ttl not in (None, ""):
        try:
            common["rrTtl"] = int(ttl)
        except (TypeError, ValueError):
            raise DdiError("the TTL %r is not a number of seconds" % ttl) from None
    if ip:
        want = _check_ip(ip)
        body = dict(common, rrType="A", rrData=want, category="ipam")
        st, data = call("POST", "/api/dnsrr", None, body)
        if not 200 <= st < 300:
            raise DdiError("the DDI refused %s A %s in %s: HTTP %d %s"
                           % (name, want, unit, st, said(data)))
        rec = ddi_record(call, name, unit)
        if not rec:
            raise DdiError("the DDI accepted %s A %s in %s but holds no such record"
                           % (name, want, unit))
        return _result(rec, unit=unit, name=name, created=True)
    nets = [s.strip() for s in (subnets if isinstance(subnets, (list, tuple))
                                else re.split(r"[\n,]+", str(subnets or ""))) if str(s).strip()]
    if not nets:
        raise DdiError("no subnet was given to search a free address in %s" % unit)
    tried = []
    for net in nets:
        body = dict(common, subnetAddress=net)
        st, data = call("POST", "/api/dnsrr/allocate", None, body)
        if not 200 <= st < 300:
            tried.append("%s: HTTP %d %s" % (net, st, said(data)))
            continue
        try:
            rec = ddi_record(call, name, unit)
        except DdiError as exc:
            raise DdiError("the DDI accepted the allocation in %s but the record could not "
                           "be read back (%s); no other subnet was asked" % (net, exc)) from None
        if rec:
            _check_ip(rec.get("rrData") or "", net)
            return _result(rec, unit=unit, name=name, created=True, subnet=net, tried=tried)
        answered = str((data or {}).get("ip") or "") if isinstance(data, dict) else ""
        tried.append("%s: no record after the allocation (%s)" % (net, said(data) or "no answer"))
        if answered and isinstance(data, dict) and str(data.get("status_code")) in ("0", "200", "201"):
            raise DdiError("the DDI says it allocated %s in %s but holds no record %s; "
                           "nothing else was tried" % (answered, net, name))
    raise DdiError("no subnet gave %s an address in %s: %s" % (name, unit, "; ".join(tried)))


def ddi_release(call, reservations, change_log: str = "") -> dict:
    """Delete each reservation this run CREATED; the rest are kept and named."""
    items = reservations if isinstance(reservations, list) else [reservations]
    released, kept, failed = [], [], []
    for r in items:
        if isinstance(r, dict) and r.get("manual"):
            kept.append("%s (%s): given in the form, never reserved" % (r.get("ip") or "", r.get("unit")))
            continue
        if not isinstance(r, dict) or not r.get("name"):
            continue
        tag = "%s %s (%s)" % (r.get("name"), r.get("ip") or "", r.get("unit"))
        if not r.get("created"):
            kept.append(tag + ": existed before this run")
            continue
        uid = str(r.get("uid") or "")
        try:
            if not uid:
                uid = str(ddi_record(call, r["name"], r.get("unit") or "").get("uid") or "")
            if not uid:
                kept.append(tag + ": already gone")
                continue
            st, data = call("DELETE", "/api/dnsrr", {"uid": uid, "changeLogMsg": change_log or ""}, None)
        except DdiError as exc:
            failed.append("%s: %s" % (tag, exc))
            continue
        if 200 <= st < 300:
            released.append(tag)
        else:
            failed.append("%s: HTTP %d %s" % (tag, st, said(data)))
    out = {"released": released, "kept": kept, "failed": failed}
    if failed:
        raise DdiError("could not release %s" % "; ".join(failed))
    return out


def _ddi_call(node, ctx):
    """``call()`` over the step's Studio connection. A connection pinned to an
    API Catalog version reaches only that version's endpoints, as an
    ``api_call`` step does."""
    from . import studio_api_spec as SP
    from . import studio_apis as SA
    from . import studio_connections as SC
    c = F._connection(node, "http")
    cat = SA.catalog_of(c)

    def call(method, path, query, body):
        if cat is not None and SP.find(cat["operations"], method, path) is None:
            raise DdiError("%s %s is not an endpoint of API %s %s (connection %s)"
                           % (method, path, cat["api"], cat["version"], c.slug))
        try:
            r = SC.http_call(c, method, path, query=query, body=body)
        except SC.ConnectionError_ as exc:
            raise DdiError(str(exc)) from None
        return r["status"], (r.get("json") if "json" in r else r.get("text"))
    return call


_SLOT_RE = re.compile(r"\{([a-z_][a-z0-9_]*)\}")


def fill(pattern: str, values: dict) -> str:
    """``spo-{extra}-{service}-{port}`` with the values; an EMPTY value takes
    one adjoining dash with it, so a missing extra text gives
    ``spo-app1-443``, never ``spo--app1-443``. An unknown slot is an error."""
    pattern = str(pattern or "")
    missing = [m.group(1) for m in _SLOT_RE.finditer(pattern) if m.group(1) not in values]
    if missing:
        raise F.FlowError("pattern %r uses {%s}, which has no value" % (pattern, missing[0]))
    out = pattern
    for k, v in values.items():
        v = "" if v is None else str(v).strip()
        if v:
            out = out.replace("{%s}" % k, v)
        else:
            out = re.sub(r"-?\{%s\}" % re.escape(k), "", out)
            out = re.sub(r"^\{%s\}-?" % re.escape(k), "", out)
    return re.sub(r"-{2,}", "-", out).strip("-")


def render_names(patterns, values: dict) -> dict:
    from . import naming
    if isinstance(patterns, list):
        rows = {}
        for r in patterns:
            if isinstance(r, dict) and r.get("object"):
                rows[str(r["object"])] = str(r.get("pattern") or "")
        patterns = rows
    if not isinstance(patterns, dict) or not patterns:
        raise F.FlowError("no name patterns (rows with object + pattern, or an object)")
    vals = dict(values or {})
    out = {}
    # The policy name first: the other patterns may use it as {spo}.
    order = sorted(patterns, key=lambda k: (k != "server_policy", k))
    for k in order:
        out[k] = fill(patterns[k], vals)
        if k == "server_policy":
            vals.setdefault("spo", out[k])
    for k, v in out.items():
        bad = naming.unsafe_name(v)
        if bad:
            raise F.FlowError("name %s %r: %s" % (k, v, bad))
        if not v:
            raise F.FlowError("name %s is empty" % k)
    return out


def _given(raw) -> dict:
    """``{unit or role: ip}`` with the empty entries dropped."""
    if not isinstance(raw, dict):
        return {}
    return {str(k).strip(): str(v).strip() for k, v in raw.items()
            if str(k or "").strip() and str(v if v is not None else "").strip()}


def ddi_given(rules: list, given: dict) -> tuple[list, dict]:
    """The same answer as :func:`ddi_reserve_set` for addresses the user TYPED:
    nothing is asked of or written to the DDI. A rule takes the address given
    for its unit, else for its role, else (``ip_from``) the one an earlier rule
    got. Every reservation is ``created: false, manual: true`` -- a rollback
    never deletes what this step never made."""
    done, units = [], {}
    for r in rules:
        unit = str(r.get("unit") or "").strip()
        role = str(r.get("role") or "").strip()
        src = str(r.get("ip_from") or "").strip()
        ip = given.get(unit) or given.get(role) or (units[src]["ip"] if src in units else "")
        if not ip:
            raise DdiError("no address was given for %s (role %s)" % (unit or "?", role or "-"))
        try:
            ip = str(ipaddress.ip_address(ip))
        except ValueError:
            raise DdiError("the address given for %s, %r, is not an IP address" % (unit, ip)) from None
        res = {"unit": unit, "name": "", "ip": ip, "uid": "", "created": False, "manual": True,
               "subnet": "", "tried": [], "role": role}
        done.append(res)
        units[unit] = res
    return done, units


def ddi_reserve_set(call, rules, values: dict, *, ttl=None, device_class="",
                    description="", change_log="", given=None) -> dict:
    """One reservation per rule, in ``order``. ``ip_from`` = a unit an earlier
    rule of THIS step reserved: register that same address. On a failure the
    records this step created are deleted again, newest first.

    ``given`` (``{unit or role: ip}``, any non-empty) = the user typed the
    addresses: the DDI is not called at all (:func:`ddi_given`)."""
    rows = [r for r in (rules if isinstance(rules, list) else []) if isinstance(r, dict)]
    if not rows:
        raise DdiError("no DDI rule for this request (the rules data store has none that match)")

    def num(r):
        try:
            return float(r.get("order") or 0)
        except (TypeError, ValueError):
            return 0.0
    rows.sort(key=num)
    given = _given(given)
    if given:
        done, units = ddi_given(rows, given)
        first = lambda role: next((d["ip"] for d in done if d.get("role") == role), "")  # noqa: E731
        return {"reservations": done, "units": units, "manual": True,
                "internal_ip": first("internal"), "external_ip": first("external")}
    done, units = [], {}
    try:
        for r in rows:
            unit = str(r.get("unit") or "").strip()
            name = fill(r.get("name") or "{dns}", values)
            src = str(r.get("ip_from") or "").strip()
            ip = ""
            if src:
                if src not in units:
                    raise DdiError("rule %s takes the address of %s, which no earlier rule "
                                   "reserved" % (unit, src))
                ip = units[src]["ip"]
            res = ddi_reserve(call, unit=unit, name=name, subnets=r.get("subnets") or "",
                              ip=ip, ttl=ttl, device_class=device_class,
                              description=description, change_log=change_log)
            res["role"] = str(r.get("role") or "")
            done.append(res)
            units[unit] = res
    except DdiError as exc:
        try:
            back = ddi_release(call, done, change_log=change_log)
            note = "released again: %s" % (", ".join(back["released"]) or "nothing had been created")
        except DdiError as exc2:
            note = "NOT all released: %s" % exc2
        raise DdiError("%s -- %s" % (exc, note)) from None
    first = lambda role: next((d["ip"] for d in done if d.get("role") == role), "")  # noqa: E731
    return {"reservations": done, "units": units, "manual": False,
            "internal_ip": first("internal"), "external_ip": first("external")}


# --------------------------------------------------------------------------- #
#  appliances                                                                  #
# --------------------------------------------------------------------------- #
def appliance_of(raw, kind: str = "fortiweb"):
    from ..models import Appliance, db
    raw = str(raw or "").strip()
    if not raw:
        raise F.FlowError("no appliance was given")
    a = (db.session.get(Appliance, int(raw)) if raw.isdigit()
         else Appliance.query.filter_by(name=raw).first())
    if a is None or (kind and (a.kind or "fortiweb") != kind):
        raise F.FlowError("no %s appliance %r" % (kind or "", raw))
    return a


def fleet_order(kind: str = "fortiweb") -> list:
    """The fleet list order: by name, case-insensitive."""
    from ..models import Appliance
    rows = Appliance.query.filter_by(kind=kind).all()
    return sorted(rows, key=lambda a: (a.name or "").lower())


def pick_fortiweb(*, zone="", line="", department="", obj="server_policy", needed=1,
                  exclude="", requires=None, headroom=None, has=None,
                  appliances=None) -> tuple[dict, list]:
    """``(choice, skipped)``: the first matching appliance with room that also
    holds every object in ``requires`` (``{kind: name}``, see REQUIRE_KINDS;
    an empty name is ignored). Capacity is checked first: it is a database
    count, the objects are read on the device."""
    from . import capacity
    hr = headroom or capacity.headroom
    holds = has or device_has
    need = clean_requires(requires)
    if "web_protection_profile" in need:  # a template id -> the profile name it deploys
        need["web_protection_profile"] = _wpp_name(need["web_protection_profile"])
    rows = appliances if appliances is not None else fleet_order("fortiweb")
    ex = str(exclude or "").strip()
    skipped = []

    def match(val, want):
        return not want or (val or "").strip().lower() == str(want).strip().lower()
    for a in rows:
        if ex and ex in (str(a.id), a.name):
            continue
        if not (match(a.zone, zone) and match(a.line, line) and match(a.department, department)):
            continue
        h = hr(a, obj, want=int(needed or 1))
        if not h.ok:
            skipped.append("%s: %d used of %s" % (a.name, h.used, h.effective_cap))
            continue
        missing = []
        for kind, name in need.items():
            ok, src = holds(a, kind, name)
            if not ok:
                missing.append("no %s %s (%s)" % (kind.replace("_", " "), name, src))
        if missing:
            skipped.append("%s: %s" % (a.name, ", ".join(missing)))
            continue
        return ({"id": a.id, "name": a.name, "zone": a.zone or "", "line": a.line or "",
                 "department": a.department or "", "used": h.used,
                 "cap": h.effective_cap, "free": h.free, "limit_known": h.known,
                 "requires": need}, skipped)
    want = ", ".join("%s=%s" % (k, v) for k, v in (("zone", zone), ("line", line),
                                                   ("department", department)) if v) or "any"
    also = (" holding " + ", ".join("%s %s" % (k.replace("_", " "), v) for k, v in need.items())
            if need else "")
    raise F.FlowError("no FortiWeb (%s) has room for %s more %s%s%s"
                      % (want, needed, obj, also, (" -- " + "; ".join(skipped)) if skipped else ""))


#: What ``fortiweb_pick`` can require on a device (the collection it reads).
REQUIRE_KINDS = ("certificate", "server_pool", "interface", "web_protection_profile")
EP_WPP = "/api/v2.0/cmdb/waf/web-protection-profile.inline-protection"
EP_INTERFACE = "/api/v2.0/cmdb/system/interface"


def clean_requires(raw) -> dict:
    """``{kind: name}`` without empty names; an unknown kind or a non-object
    is an ERROR (a typo must not silently stop constraining the pick)."""
    if raw in (None, "", {}):
        return {}
    if not isinstance(raw, dict):
        raise F.FlowError("requires is a JSON object, e.g. {\"certificate\": \"...\"}")
    out = {}
    for k, v in raw.items():
        k = str(k).strip()
        if k not in REQUIRE_KINDS:
            raise F.FlowError("requires: unknown kind %r (one of %s)" % (k, ", ".join(REQUIRE_KINDS)))
        v = "" if v is None else str(v).strip()
        if v:
            out[k] = v
    return out


def device_has(appliance, kind: str, name: str) -> tuple[bool, str]:
    """``(present, where from)``: read on the device when it answers, else the
    local cache (``device_names``; interfaces: also the interface cache)."""
    if kind == "web_protection_profile":
        name = _wpp_name(name)
    ep = {"certificate": EP_CERT_LOCAL, "server_pool": EP_POOL, "interface": EP_INTERFACE,
          "web_protection_profile": EP_WPP}[kind]
    names, src = device_names(appliance, ep)
    if kind == "interface" and name not in names and src != "read on the device":
        from .interface_inventory import cached_interfaces
        names = [str(i.get("name") or "") for i in cached_interfaces(appliance)]
        src = "interface cache: the device did not answer"
    return name in names, src


def _may_write_device(ctx) -> None:
    u = ctx.user_obj
    if not (u is not None and getattr(u, "can", None) and u.can("config_write")):
        raise F.FlowError("this step writes to an appliance: the user running the app "
                          "needs the config_write permission")


# --------------------------------------------------------------------------- #
#  FortiWeb objects                                                            #
# --------------------------------------------------------------------------- #
EP_SERVICE = "/api/v2.0/cmdb/server-policy/service.custom"
EP_POOL = "/api/v2.0/cmdb/server-policy/server-pool"
#: What a server policy's ``certificate`` refers to.
EP_CERT_LOCAL = "/api/v2.0/cmdb/system/certificate.local"
CERT_MODES = ("issue", "existing", "device")


def device_names(appliance, endpoint: str, *, client=None) -> tuple[list, str]:
    """``(names, where from)`` of one cmdb collection: the DEVICE when it
    answers (authoritative, an empty list included), else the local cache --
    said so, because a cached name may be gone on the device (the write then
    fails and the step removes what it wrote)."""
    from .read_layer import cached_ref_names
    err = ""
    try:
        if client is None:
            from ..clients import client_for
            client = client_for(appliance)
        names, status, err = client.cmdb_names_checked(endpoint)
        if status == "ok":
            return list(names or []), "read on the device"
    except Exception as exc:  # noqa: BLE001 -- the cache answers instead
        err = "%s: %s" % (type(exc).__name__, exc)
    return cached_ref_names(appliance.id, endpoint), \
        "from the local cache: the device did not answer (%s)" % (str(err or "no answer")[:120])


def _given_of(node, ctx) -> dict:
    """The typed addresses of a ``ddi_reserve_set`` in mode ``given``; ``{}``
    in mode ``reserve``. Mode given with nothing typed is an ERROR, never a
    quiet fall-back to reserving in the DDI the user said not to touch."""
    mode = (_s(node, ctx, "mode", "reserve") or "reserve").lower()
    if mode not in ("reserve", "given"):
        raise DdiError("addresses mode %r: reserve or given" % mode)
    if mode == "reserve":
        return {}
    given = _given(F._json(node, ctx, "given", "Given addresses"))
    if not given:
        raise DdiError("addresses = given, but no address was typed")
    return given


def _pool_of(node, ctx) -> str:
    """The existing pool to bind, ``""`` for a new one."""
    mode = (_s(node, ctx, "pool_mode", "new") or "new").lower()
    if mode not in ("new", "existing"):
        raise F.FlowError("server pool mode %r: new or existing" % mode)
    pool = _s(node, ctx, "existing_pool")
    if mode == "existing" and not pool:
        raise F.FlowError("server pool = existing, but no existing pool was picked")
    return pool if mode == "existing" else ""
#: The predefined FortiWeb services: a policy on these ports needs no object.
_PREDEFINED = {(True, 443): "HTTPS", (False, 80): "HTTP"}


def service_for(port, https: bool, name: str = "") -> tuple[str, bool]:
    """``(service name, needs a custom service)`` for the port a policy
    listens on. No port = the predefined one (HTTPS with a certificate, the
    device's default HTTP without), which is what every policy got before the
    port was applied. ``name`` = the custom service's name (``spo-naming``
    object ``service``); empty = ``HTTPS-<port>`` / ``HTTP-<port>``."""
    raw = str(port if port is not None else "").strip()
    if not raw:
        return ("HTTPS" if https else ""), False
    try:
        p = int(float(raw))
    except ValueError:
        raise F.FlowError("port %r is not a number" % raw) from None
    if not 1 <= p <= 65535:
        raise F.FlowError("port %d is outside 1-65535" % p)
    if (https, p) in _PREDEFINED:
        return _PREDEFINED[(https, p)], False
    return (str(name or "").strip() or "%s-%d" % ("HTTPS" if https else "HTTP", p)), True


def spo_steps(names: dict, *, vip: str, interface: str, members=None, wpp: str = "",
              certificate: str = "", extra: dict | None = None, port=None,
              existing_pool: str = "", service_exists: bool = False) -> list[tuple]:
    """``[(kind, label, endpoint, body, parent)]`` in dependency order -- the
    SPO wizard's endpoints (``views.workspace._CREATE_EPS``), not a copy.

    ``existing_pool`` = bind that pool (already on the device) and create no
    pool and no member. ``port`` = what the policy listens on: a port that is
    not the predefined one gets a custom service, created here unless
    ``service_exists`` (it is then bound, and never removed)."""
    from ..views.workspace import _CREATE_EPS
    existing_pool = str(existing_pool or "").strip()
    for k in ("server_policy", "virtual_server", "vip") + (() if existing_pool else ("server_pool",)):
        if not str(names.get(k) or "").strip():
            raise F.FlowError("names: %s is required" % k)
    if not str(interface or "").strip():
        raise F.FlowError("no VIP interface was given (form, or the FortiWeb rule)")
    vs, pool = names["virtual_server"], existing_pool or names["server_pool"]
    steps = [("vserver", "Virtual Server " + vs, _CREATE_EPS["vserver"], {"name": vs}, None),
             ("vip", "VIP " + names["vip"], _CREATE_EPS["vip"],
              {"name": names["vip"], "vip": vip, "interface": interface}, vs)]
    if existing_pool:
        if members:
            raise F.FlowError("an existing server pool (%s) keeps its own members: leave the "
                              "real servers empty" % existing_pool)
    else:
        if not members:
            raise F.FlowError("a new server pool needs at least one real server")
        steps.append(("pool", "Server Pool " + pool, _CREATE_EPS["pool"], {"name": pool}, None))
    for i, m in enumerate(members or [], 1):
        if isinstance(m, str):
            host, _, mport = m.strip().partition(":")
            m = {"ip": host, "port": mport or "80"}
        if not isinstance(m, dict) or not str(m.get("ip") or "").strip():
            raise F.FlowError("pool member %d needs an ip" % i)
        steps.append(("pserver", "Pool member %d" % i, _CREATE_EPS["pserver"],
                      {"ip": str(m["ip"]).strip(), "port": str(m.get("port") or "80")}, pool))
    service, custom = service_for(port, bool(certificate), names.get("service") or "")
    if custom and not service_exists:
        steps.append(("service", "Service %s (port %s)" % (service, int(float(str(port)))),
                      EP_SERVICE, {"name": service, "port": str(int(float(str(port)))),
                                   "protocol": "TCP"}, None))
    policy = {"name": names["server_policy"], "vserver": vs, "server-pool": pool}
    if wpp:
        policy["web-protection-profile"] = wpp
    if certificate:
        policy["https-service"] = service
        policy["certificate"] = certificate
    elif service:
        policy["service"] = service
    for k, v in (extra or {}).items():
        if k not in policy:
            policy[str(k)] = v
    steps.append(("policy", "Server Policy " + names["server_policy"], _CREATE_EPS["policy"],
                  policy, None))
    return steps


def _wpp_name(raw: str) -> str:
    """A template id becomes the profile name it deploys; a name stays."""
    raw = str(raw or "").strip()
    if not raw.isdigit():
        return raw
    from ..models import Template, db
    t = db.session.get(Template, int(raw))
    if t is None:
        raise F.FlowError("Web Protection Profile template #%s does not exist" % raw)
    if t.status != Template.STATUS_APPROVED:
        raise F.FlowError("template %r is %s: only an approved template may be used"
                          % (t.name, t.status))
    return t.name


def create_spo(appliance, steps, *, ops=None) -> dict:
    """Write the objects; on a failure delete what was written, newest first."""
    from urllib.parse import quote
    from .fortiweb_ops import FortiWebOps
    ops = ops or FortiWebOps(appliance)
    made = []
    for kind, label, ep, body, parent in steps:
        full = ep if not parent else "%s%smkey=%s" % (ep, "&" if "?" in ep else "?",
                                                       quote(parent, safe=""))
        res = ops.create(full, {"data": body}, dry_run=False)
        if not res.ok:
            undone = remove_spo(appliance, {"appliance_id": appliance.id, "created": made},
                                ops=ops, quiet=True)
            back = ", ".join(undone["removed"]) or "nothing had been created"
            if undone["failed"]:
                back += "; NOT removed: " + "; ".join(undone["failed"])
            raise F.FlowError("%s failed: %s -- removed again: %s"
                              % (label, res.get("error") or "refused", back))
        if kind in ("vserver", "pool", "service", "policy"):
            made.append({"kind": kind, "endpoint": ep, "mkey": body["name"], "label": label})
        else:
            made.append({"kind": kind, "endpoint": ep, "parent": parent, "label": label})
    return {"appliance_id": appliance.id, "appliance": appliance.name, "created": made,
            "server_policy": next((m["mkey"] for m in made if m["kind"] == "policy"), "")}


def remove_spo(appliance, spo: dict, *, ops=None, quiet=False) -> dict:
    """Delete the TOP objects ``create_spo`` wrote, newest first. A child (VIP,
    pool member) goes with its parent; deleting it alone first is a second
    call that can fail for nothing."""
    from .fortiweb_ops import FortiWebOps
    ops = ops or FortiWebOps(appliance)
    removed, failed = [], []
    for m in reversed(list((spo or {}).get("created") or [])):
        if not m.get("mkey"):
            continue
        res = ops.delete(m["endpoint"], m["mkey"], dry_run=False, check_refs=False)
        (removed if res.ok else failed).append(
            m["label"] if res.ok else "%s: %s" % (m["label"], res.get("error") or "refused"))
    if failed and not quiet:
        raise F.FlowError("could not remove %s" % "; ".join(failed))
    return {"removed": removed, "failed": failed}


# --------------------------------------------------------------------------- #
#  rehearsal -- the same shape as a real result, nothing sent                  #
# --------------------------------------------------------------------------- #
PENDING_IP = "0.0.0.0"


def rehearse(node: dict, ctx) -> tuple:
    """A writing step in a rehearsal: describe it, and return a value with the
    SHAPE of the real result, so the steps after it (``{{ ddi_bn.ip }}``,
    ``{{ certificate.name }}``) render instead of failing on a key that only
    a real run would have produced. The placeholders say what they stand for."""
    kind = node.get("kind")
    if kind == "ddi_reserve":
        ip = _s(node, ctx, "ip") or PENDING_IP
        v = {"unit": _s(node, ctx, "unit"), "name": _s(node, ctx, "name"), "ip": ip,
             "uid": "", "created": False, "subnet": "", "tried": [], "rehearsal": True}
        what = ("would register %s A %s in %s" % (v["name"], ip, v["unit"]) if _s(node, ctx, "ip")
                else "would reserve %s in %s from %s" % (
                    v["name"], v["unit"], ", ".join(
                        x.strip() for x in re.split(r"[\n,]+", str(_r(node, ctx, "subnets") or ""))
                        if x.strip()) or "no subnet"))
        return "ok", v, "rehearsal: " + what
    if kind == "ddi_reserve_set":
        vals = F._json(node, ctx, "values", "Values") or {}
        rows = _r(node, ctx, "rules")
        rows = sorted([r for r in rows if isinstance(r, dict)] if isinstance(rows, list) else [],
                      key=lambda r: float(r.get("order") or 0) if str(r.get("order") or "0")
                      .replace(".", "", 1).isdigit() else 0.0)
        given = _given_of(node, ctx)
        if given:
            done, units = ddi_given(rows, given)
            first = lambda role: next((d["ip"] for d in done if d["role"] == role), "")  # noqa: E731
            return "ok", {"reservations": done, "units": units, "manual": True,
                          "internal_ip": first("internal"), "external_ip": first("external"),
                          "rehearsal": True}, \
                "rehearsal: addresses given, the DDI is not called: " + "; ".join(
                    "%s %s" % (d["unit"], d["ip"]) for d in done)
        done, units = [], {}
        for r in rows:
            unit = str(r.get("unit") or "")
            ip = units[r["ip_from"]]["ip"] if r.get("ip_from") in units else PENDING_IP
            name = fill(r.get("name") or "{dns}", vals if isinstance(vals, dict) else {})
            d = {"unit": unit, "name": name, "ip": ip, "uid": "", "created": False, "manual": False,
                 "subnet": "", "tried": [], "role": str(r.get("role") or ""), "rehearsal": True}
            done.append(d)
            units[unit] = d
        first = lambda role: next((d["ip"] for d in done if d["role"] == role), "")  # noqa: E731
        return "ok", {"reservations": done, "units": units, "internal_ip": first("internal"),
                      "external_ip": first("external"), "manual": False, "rehearsal": True}, \
            "rehearsal: would reserve " + "; ".join("%s in %s%s" % (
                d["name"], d["unit"], " (same address as %s)" % r.get("ip_from") if r.get("ip_from") else "")
                for d, r in zip(done, rows))
    if kind == "certificate":
        mode = _s(node, ctx, "mode", "issue") or "issue"
        if mode not in CERT_MODES:
            raise F.FlowError("certificate mode %r: %s" % (mode, ", ".join(CERT_MODES)))
        v = {"id": None, "name": _s(node, ctx, "existing") if mode != "issue" else
             "<issued at run time>", "created": mode == "issue",
             "provider": _s(node, ctx, "provider"), "rehearsal": True}
        if mode == "device":
            if not v["name"]:
                raise F.FlowError("certificate = device, but no certificate was picked")
            v["on_device"] = True
            return "ok", v, "rehearsal: would use %s, already on %s (checked on the device " \
                "at run time; nothing is written)" % (v["name"] or "?", _s(node, ctx, "appliance"))
        prob = ""
        try:
            from . import cert_providers as CP
            prob = CP.zone_problem(_s(node, ctx, "provider") if mode == "issue" else "",
                                   _s(node, ctx, "zone")) if mode == "issue" else ""
        except Exception:  # noqa: BLE001
            prob = ""
        if prob:
            raise F.FlowError(prob)
        return "ok", v, "rehearsal: would %s a certificate (%s) for %s" % (
            "issue" if mode == "issue" else "deploy", _s(node, ctx, "provider") or "default",
            _s(node, ctx, "common_name") or _s(node, ctx, "existing"))
    if kind == "fortiweb_spo":
        names = F._json(node, ctx, "names", "Names") or {}
        members = F._json(node, ctx, "members", "Pool members") or []
        names = names if isinstance(names, dict) else {}
        pool, cert = _pool_of(node, ctx), _s(node, ctx, "certificate")
        steps = spo_steps(names, vip=_s(node, ctx, "vip"),
                          interface=_s(node, ctx, "interface"),
                          members=members if isinstance(members, list) else [],
                          wpp=_s(node, ctx, "wpp"), certificate=cert,
                          port=_s(node, ctx, "port"), existing_pool=pool)
        service, _custom = service_for(_s(node, ctx, "port"), bool(cert), names.get("service") or "")
        v = {"appliance_id": _s(node, ctx, "appliance"), "created": [],
             "server_policy": names.get("server_policy", ""), "rehearsal": True,
             "pool": pool or names.get("server_pool", ""), "pool_existing": bool(pool),
             "service": service, "interface": _s(node, ctx, "interface")}
        return "ok", v, "rehearsal: would create on %s: %s" % (
            v["appliance_id"], ", ".join(x[1] for x in steps))
    if kind in ("ddi_release", "fortiweb_spo_remove"):
        return "ok", {"released": [], "kept": [], "failed": [], "removed": [], "rehearsal": True}, \
            "rehearsal: would undo what this run created"
    plan = {k: v for k, v in (node.get("params") or {}).items() if k != "save_as"}
    return "ok", {"rehearsal": True, "would": F.render(plan, ctx.scope())}, "rehearsal: not executed"


# --------------------------------------------------------------------------- #
#  the runner                                                                  #
# --------------------------------------------------------------------------- #
def _r(node, ctx, name, default=""):
    return F.render(F._p(node, name, default), ctx.scope())


def _s(node, ctx, name, default="") -> str:
    v = _r(node, ctx, name, default)
    return "" if v is None else str(v).strip()


def run(node: dict, ctx) -> tuple:
    kind = node.get("kind")
    if kind == "fortiweb_pick":
        choice, skipped = pick_fortiweb(
            zone=_s(node, ctx, "zone"), line=_s(node, ctx, "line"),
            department=_s(node, ctx, "department"),
            obj=F._p(node, "object", "server_policy") or "server_policy",
            needed=int(_s(node, ctx, "needed", "1") or 1), exclude=_s(node, ctx, "exclude"),
            requires=F._json(node, ctx, "requires", "Objects the device must have"))
        return "ok", choice, "%s (%s used of %s)%s" % (
            choice["name"], choice["used"], choice["cap"] if choice["cap"] is not None else "no limit",
            (" -- skipped " + "; ".join(skipped)) if skipped else "")
    if kind == "render_names":
        vals = F._json(node, ctx, "values", "Values") or {}
        if not isinstance(vals, dict):
            raise F.FlowError("values is an object")
        names = render_names(_r(node, ctx, "patterns"), vals)
        return "ok", names, ", ".join("%s=%s" % kv for kv in names.items())
    if kind == "ddi_reserve_set":
        vals = F._json(node, ctx, "values", "Values") or {}
        given = _given_of(node, ctx)
        res = ddi_reserve_set(None if given else _ddi_call(node, ctx), _r(node, ctx, "rules"),
                              vals if isinstance(vals, dict) else {},
                              ttl=_s(node, ctx, "ttl"), device_class=_s(node, ctx, "device_class"),
                              description=_s(node, ctx, "description"),
                              change_log=_s(node, ctx, "change_log"), given=given)
        if res.get("manual"):
            return "ok", res, "addresses given in the form, nothing reserved in the DDI: " + "; ".join(
                "%s %s" % (d["unit"], d["ip"]) for d in res["reservations"])
        return "ok", res, "; ".join("%s %s %s in %s" % (
            "reserved" if d["created"] else "reused", d["name"], d["ip"], d["unit"])
            for d in res["reservations"])
    if kind == "ddi_reserve":
        res = ddi_reserve(_ddi_call(node, ctx), unit=_s(node, ctx, "unit"),
                          name=_s(node, ctx, "name"), subnets=_r(node, ctx, "subnets"),
                          ip=_s(node, ctx, "ip"), ttl=_s(node, ctx, "ttl"),
                          device_class=_s(node, ctx, "device_class"),
                          description=_s(node, ctx, "description"),
                          change_log=_s(node, ctx, "change_log"))
        return "ok", res, "%s %s %s in %s" % ("reserved" if res["created"] else "reused",
                                              res["name"], res["ip"], res["unit"])
    if kind == "ddi_release":
        res = ddi_release(_ddi_call(node, ctx), _r(node, ctx, "reservations"),
                          change_log=_s(node, ctx, "change_log"))
        return "ok", res, "released %d, kept %d" % (len(res["released"]), len(res["kept"]))
    if kind == "certificate":
        _may_write_device(ctx)
        return _run_certificate(node, ctx)
    if kind == "fortiweb_spo":
        _may_write_device(ctx)
        a = appliance_of(_s(node, ctx, "appliance"))
        names = F._json(node, ctx, "names", "Names") or {}
        members = F._json(node, ctx, "members", "Pool members") or []
        extra = F._json(node, ctx, "extra", "Extra policy fields") or {}
        if not isinstance(names, dict) or not isinstance(members, list) or not isinstance(extra, dict):
            raise F.FlowError("names and extra are objects, members a list")
        pool, port, cert = _pool_of(node, ctx), _s(node, ctx, "port"), _s(node, ctx, "certificate")
        service, custom = service_for(port, bool(cert), names.get("service") or "")
        notes = []
        if pool:
            have, src = device_names(a, EP_POOL)
            if pool not in have:
                raise F.FlowError("no server pool %r on %s (%s) -- a server pool is a per-device "
                                  "object; nothing was written" % (pool, a.name, src))
            notes.append("pool %s bound (%s)" % (pool, src))
        exists = False
        if custom:
            have, src = device_names(a, EP_SERVICE)
            exists = service in have
            if exists:
                notes.append("service %s reused (%s)" % (service, src))
        steps = spo_steps(names, vip=_s(node, ctx, "vip"), interface=_s(node, ctx, "interface"),
                          members=members, wpp=_wpp_name(_s(node, ctx, "wpp")),
                          certificate=cert, extra=extra, port=port, existing_pool=pool,
                          service_exists=exists)
        res = create_spo(a, steps)
        res.update(pool=pool or names.get("server_pool", ""), pool_existing=bool(pool),
                   service=service, interface=_s(node, ctx, "interface"))
        return "ok", res, "created on %s: %s%s" % (
            a.name, ", ".join(m["label"] for m in res["created"]),
            (" -- " + "; ".join(notes)) if notes else "")
    if kind == "fortiweb_spo_remove":
        _may_write_device(ctx)
        spo = _r(node, ctx, "spo")
        if not isinstance(spo, dict) or not spo.get("appliance_id"):
            return "ok", {"removed": [], "failed": []}, "nothing to remove"
        a = appliance_of(spo["appliance_id"])
        res = remove_spo(a, spo)
        return "ok", res, "removed from %s: %s" % (a.name, ", ".join(res["removed"]) or "nothing")
    raise F.FlowError("unknown step kind %r" % kind)


def _device_certificate(a, name: str, zone: str):
    """Mode ``device``: a local certificate that is ALREADY on the appliance.
    Nothing is written; the name is checked ON the device (the cache only
    when the device does not answer, said so). A certificate the Certificate
    Manager also knows keeps its provider's zone rule; one it does not know
    has no provider to check, and the step says so."""
    from ..models import ManagedCertificate
    from . import cert_providers as CP
    if not name:
        raise F.FlowError("certificate = device, but no certificate was picked")
    have, src = device_names(a, EP_CERT_LOCAL)
    if name not in have:
        raise F.FlowError("no local certificate %r on %s (%s) -- a certificate is a "
                          "per-device object; nothing was written" % (name, a.name, src))
    row = ManagedCertificate.query.filter_by(name=name).first()
    if row is not None:
        prob = CP.zone_problem(row.provider, zone)
        if prob:
            raise F.FlowError(prob)
        note = "provider %s" % (row.provider or "default")
    else:
        note = "not in the Certificate Manager: no provider zone rule to check"
    return "ok", {"id": row.id if row is not None else None, "name": name, "created": False,
                  "provider": (row.provider or "") if row is not None else "",
                  "on_device": True}, "uses %s, already on %s (%s; %s)" % (name, a.name, src, note)


def _run_certificate(node, ctx):
    from ..models import ManagedCertificate, db
    from . import cert_manager as CM
    from . import cert_providers as CP
    a = appliance_of(_s(node, ctx, "appliance"))
    mode = _s(node, ctx, "mode", "issue") or "issue"
    if mode not in CERT_MODES:
        raise F.FlowError("certificate mode %r: %s" % (mode, ", ".join(CERT_MODES)))
    zone = _s(node, ctx, "zone")
    if mode == "device":
        return _device_certificate(a, _s(node, ctx, "existing"), zone)
    if mode == "existing":
        raw = _s(node, ctx, "existing")
        row = (db.session.get(ManagedCertificate, int(raw)) if raw.isdigit()
               else ManagedCertificate.query.filter_by(name=raw).first())
        if row is None:
            raise F.FlowError("no certificate %r in the Certificate Manager" % raw)
        prob = CP.zone_problem(row.provider, zone)
        if prob:
            raise F.FlowError(prob)
        err = CM.deploy_existing(row, a, actor=ctx.user)
        if err:
            raise F.FlowError(err)
        return "ok", {"id": row.id, "name": row.name, "created": False,
                      "provider": row.provider or ""}, "deployed %s to %s" % (row.name, a.name)
    provider = _s(node, ctx, "provider")
    prob = CP.zone_problem(provider, zone)
    if prob:
        raise F.FlowError(prob)
    cn = _s(node, ctx, "common_name")
    sans = [s for s in re.split(r"[,\s]+", _s(node, ctx, "sans")) if s]
    res = CM.create_certificate(a, cn, F._p(node, "cert_class", "server") or "server",
                                extra_sans=sans or None, deploy=True, actor=ctx.user,
                                provider=provider)
    if not res.get("ok"):
        raise F.FlowError("certificate: %s" % (res.get("error") or "not issued"))
    return "ok", {"id": res.get("cert_id"), "name": res.get("name") or "", "created": True,
                  "provider": provider}, "issued %s (%s) and deployed to %s" % (
        res.get("name"), provider or "default provider", a.name)


# --------------------------------------------------------------------------- #
#  satom_select form fields                                                    #
# --------------------------------------------------------------------------- #
_FLEET_EPS = {"fortiweb_pools": EP_POOL, "fortiweb_certificates": EP_CERT_LOCAL}


def _fleet_objects(source: str) -> list[dict]:
    """Pool, local certificate or interface names over every FortiWeb, from the
    local cache (the form never waits on a device). The label says which
    devices have it: the FortiWeb is picked at run time, and the run checks
    the name ON it."""
    from .interface_inventory import cached_interfaces
    from .read_layer import cached_ref_names
    where: dict[str, list] = {}
    for a in fleet_order("fortiweb"):
        if source in _FLEET_EPS:
            names = cached_ref_names(a.id, _FLEET_EPS[source])
        else:
            names = [str(i.get("name") or "") for i in cached_interfaces(a)]
        for n in names:
            if n:
                where.setdefault(n, []).append(a.name)
    return [{"value": n, "label": "%s (%s)" % (n, ", ".join(devs))}
            for n, devs in sorted(where.items(), key=lambda kv: kv[0].lower())]


def source_options(source: str) -> tuple[list[dict], str]:
    """``([{value, label}], problem)`` for a ``satom_select`` field."""
    from . import settings_store as store
    if source == "fortiweb":
        return [{"value": str(a.id), "label": "%s (%s / %s)" % (a.name, a.zone or "-", a.line or "-")}
                for a in fleet_order("fortiweb")], ""
    if source in ("fortiweb_pools", "fortiweb_interfaces", "fortiweb_certificates"):
        return _fleet_objects(source), ""
    if source == "wpp_templates":
        from ..models import Template
        rows = (Template.query.filter_by(kind=Template.KIND_WEB_PROTECTION,
                                         status=Template.STATUS_APPROVED)
                .order_by(Template.name, Template.version.desc()).all())
        seen, out = set(), []
        for t in rows:
            if t.name in seen:
                continue
            seen.add(t.name)
            out.append({"value": str(t.id), "label": "%s v%s" % (t.name, t.version)})
        return out, ""
    if source == "certificates":
        from ..models import ManagedCertificate
        rows = (ManagedCertificate.query
                .filter(ManagedCertificate.revoked_at.is_(None),
                        ManagedCertificate.archived_at.is_(None),
                        ManagedCertificate.cert_pem != "")
                .order_by(ManagedCertificate.name).limit(500).all())
        return [{"value": str(c.id), "label": "%s%s" % (
            c.name, (" [%s]" % c.provider) if c.provider else "")} for c in rows
            if c.status not in ("revoked", "superseded", "awaiting_signature")], ""
    if source == "cert_providers":
        from . import cert_providers as CP
        return [{"value": p["key"], "label": p["name"] + (" (internal only)" if p["internal_only"] else "")}
                for p in CP.providers()], ""
    if source in ("zones", "lines", "departments"):
        return [{"value": v, "label": v} for v in store.classification(source)], ""
    if source == "segments":
        out = []
        for s in store.get_json(store.K_SEGMENTS, []) or []:
            if isinstance(s, dict) and s.get("name"):
                out.append({"value": str(s.get("cidr") or s["name"]),
                            "label": "%s (%s, %s)" % (s["name"], s.get("cidr") or "-", s.get("zone") or "-")})
        return out, ""
    return [], "unknown SATOM list %r" % source

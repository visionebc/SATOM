"""Python Studio > Examples -- working bundles an author installs with one click.

Each bundle is a set of Studio objects that belong together -- connections,
data stores, Script Library scripts and apps -- written against the real
answers of the systems they talk to (FortiOS 8.0 REST API, NetBox 4 REST
API). Installing creates what is missing and leaves alone what exists: an
object with the same id is never overwritten, so re-installing after editing
an example keeps the edits. The installed objects are TEMPLATES
(:func:`is_template`): since 2026-10-23 they are never deleted -- the bundle
has no Remove any more and every Studio delete refuses them; an app can be
disabled or reset instead (operator request).

Every id starts with ``ex-``, so an example can never collide with real work,
and every connection is created WITHOUT a secret and pointed at a placeholder
host: nothing reaches a device until the administrator has entered its
address and its token on the connection page.

What each bundle shows:

* ``fortigate-policy`` -- an APP BUILT ONLY FROM THE DIAGRAM: three API calls
  to a FortiGate (route lookup → ``policy-lookup`` → the matching rule from
  ``cmdb``), two decisions, an output, and actions on it (save to a data
  store, download, raise a change request). Plus the same lookup as a
  Script Library script.
* ``netbox-ip`` -- a SCRIPT that calls a Connection (``satom_script.
  connection``) and an app whose diagram RUNS that script.
* ``traffic-explainer`` -- one script using TWO connections (FortiGate and
  NetBox): who owns both ends of a flow and which rule decides it.
* ``site-contacts`` -- DATA STORES with no external system at all: a list
  field fed by a store, a query and an upsert. Works the moment it is
  installed, and is published so it appears under Operations > Plugins.
* ``dns-lb-lookup`` -- the DNS & LB Lookup page as THREE apps built from the
  SATOM steps of ``studio_dns``: the lookup (resolvers + the fleet's LB cache,
  Copy DNS / Copy LB, a Records button on every name and Open policy /
  Decommission on every match), DNS Records (list, then Edit / Delete on each
  row) and the decommission (plan, warnings to tick, apply). The buttons open
  the other app's form over the run page. Uses SATOM's own resolvers and DNS
  backends, so it works once installed; the page itself stays.
"""
from __future__ import annotations

import json
import textwrap

FGT_CONN = "ex-fortigate"
NB_CONN = "ex-netbox"

# --------------------------------------------------------------------------- #
#  scripts                                                                     #
# --------------------------------------------------------------------------- #
FGT_SCRIPT = textwrap.dedent('''\
    """Which FortiGate rule lets this traffic through?

    The answer comes from the FortiGate itself, never from a copy of its
    rules: the ingress interface is the one it routes the SOURCE through
    (monitor/router/lookup), the verdict is its own policy-lookup, and the
    matching rule is read back from the configuration (cmdb/firewall/policy).

    Connection ex-fortigate: https://<fortigate>/api/v2, Bearer = the token of
    a REST API administrator with a read-only profile. The token never enters
    this script: SATOM adds it to each call.
    """
    from satom_script import connection, inputs, log, result

    fgt = connection("ex-fortigate")
    PROTOCOLS = {"tcp": 6, "udp": 17, "icmp": 1}


    def get(path, **params):
        r = fgt.get(path, params=params or None)
        r.raise_for_status()            # HTTP 4xx/5xx -> the run fails, saying why
        return (r.json() or {}).get("results")


    def names(rule, key):
        return ", ".join(x.get("name", "") for x in rule.get(key) or [])


    src = inputs["source"].strip()
    dst = inputs["destination"].strip()
    proto = inputs.get("protocol") or "tcp"
    port = inputs.get("port")

    route = get("/monitor/router/lookup", destination=src) or {}
    entries = route.get("entries") or []
    if not entries:
        result({"source": src, "destination": dst, "verdict": "no route",
                "note": "the FortiGate has no route to the source address"})
        raise SystemExit(0)
    ingress = entries[0]["interface"]
    log("%s enters the FortiGate through %s" % (src, ingress))

    query = {"srcintf": ingress, "sourceip": src, "dest": dst,
             "protocol": str(PROTOCOLS[proto])}
    if proto == "icmp":
        query.update(icmptype="8", icmpcode="0")
    else:
        query["destport"] = str(int(port or 0))
    lookup = get("/monitor/firewall/policy-lookup", **query) or {}

    out = {"source": src, "destination": dst, "protocol": proto, "port": port,
           "ingress": ingress, "match": bool(lookup.get("match"))}
    if lookup.get("match"):
        pid = int(lookup["policy_id"])
        rule = (get("/cmdb/firewall/policy/%d" % pid,
                    format="policyid|name|srcintf|dstintf|srcaddr|dstaddr|service|action|status")
                or [{}])[0]
        out.update(policy_id=pid, policy_name=rule.get("name", ""),
                   action=lookup.get("policy_action") or rule.get("action", ""),
                   src_addr=names(rule, "srcaddr"), dst_addr=names(rule, "dstaddr"),
                   service=names(rule, "service"), egress=names(rule, "dstintf"))
    else:
        out.update(policy_id=None, policy_name="(no rule matches)",
                   action=lookup.get("sec_default_action") or "deny",
                   note="no rule matches: the implicit deny applies")
    log("verdict: %s" % out["action"])
    result(out)
''')

NETBOX_SCRIPT = textwrap.dedent('''\
    """Who owns this IP address? (NetBox)

    Two reads from NetBox: the IP address record (status, DNS name, tenant,
    the device and interface it is assigned to) and every prefix that
    contains it, most specific first (VLAN, role, scope, tenant).

    Connection ex-netbox: https://<netbox>/api, authentication "API key",
    header Authorization, secret "Token <key>" (a NetBox v1 token) -- or
    authentication Bearer with a v2 token (NetBox 4.5+).
    """
    import ipaddress

    from satom_script import connection, inputs, log, result

    nb = connection("ex-netbox")


    def label(obj, *keys):
        """The first present key of a nested NetBox object, as text."""
        if not isinstance(obj, dict):
            return obj or ""
        for k in keys:
            if obj.get(k) not in (None, ""):
                return obj[k]
        return ""


    ip = str(ipaddress.ip_address(inputs["ip"].strip()))   # refuses a non-address
    addrs = nb.get("/ipam/ip-addresses/", params={"address": ip}).raise_for_status().json()
    prefixes = nb.get("/ipam/prefixes/", params={"contains": ip, "limit": 50}) \\
        .raise_for_status().json()

    records = []
    for a in addrs.get("results") or []:
        obj = a.get("assigned_object") or {}
        records.append({
            "address": a.get("address"),
            "status": label(a.get("status"), "value"),
            "dns_name": a.get("dns_name") or "",
            "tenant": label(a.get("tenant"), "name"),
            "vrf": label(a.get("vrf"), "name") or "global",
            "device": label(obj.get("device") or obj.get("virtual_machine"), "name"),
            "interface": label(obj, "name"),
            "description": a.get("description") or "",
        })
    nets = sorted(prefixes.get("results") or [],
                  key=lambda p: ipaddress.ip_network(p["prefix"]).prefixlen, reverse=True)
    networks = [{
        "prefix": p.get("prefix"),
        "vlan": ("%s (%s)" % (label(p.get("vlan"), "name"), label(p.get("vlan"), "vid"))
                 if p.get("vlan") else ""),
        "role": label(p.get("role"), "name"),
        "scope": label(p.get("scope") or p.get("site"), "name", "display"),
        "tenant": label(p.get("tenant"), "name"),
        "status": label(p.get("status"), "value"),
    } for p in nets]
    log("%d address record(s), %d prefix(es)" % (len(records), len(networks)))
    result({"ip": ip, "owner": records[0] if records else None,
            "addresses": records, "prefixes": networks,
            "most_specific": networks[0]["prefix"] if networks else None})
''')

EXPLAINER_SCRIPT = textwrap.dedent('''\
    """Explain a flow: who owns both ends (NetBox) and which rule decides it
    (FortiGate). One script, two connections -- each call goes out with its
    own connection's credential, and the script holds neither.
    """
    import ipaddress

    from satom_script import connection, inputs, log, result

    fgt = connection("ex-fortigate")
    nb = connection("ex-netbox")
    PROTOCOLS = {"tcp": 6, "udp": 17}


    def fgt_get(path, **params):
        r = fgt.get(path, params=params)
        r.raise_for_status()
        return (r.json() or {}).get("results")


    def owner(ip):
        """The NetBox view of one address; None when NetBox does not know it."""
        try:
            a = nb.get("/ipam/ip-addresses/", params={"address": ip}).raise_for_status().json()
            p = nb.get("/ipam/prefixes/", params={"contains": ip}).raise_for_status().json()
        except Exception as exc:    # NetBox down: the flow is still explained
            log("NetBox: %s" % exc)
            return None
        rec = (a.get("results") or [{}])[0]
        obj = rec.get("assigned_object") or {}
        nets = sorted(p.get("results") or [],
                      key=lambda x: ipaddress.ip_network(x["prefix"]).prefixlen, reverse=True)
        return {"dns_name": rec.get("dns_name") or "",
                "device": ((obj.get("device") or {}).get("name") or ""),
                "tenant": ((rec.get("tenant") or {}).get("name") or ""),
                "prefix": nets[0]["prefix"] if nets else ""}


    src = str(ipaddress.ip_address(inputs["source"].strip()))
    dst = str(ipaddress.ip_address(inputs["destination"].strip()))
    proto = inputs.get("protocol") or "tcp"
    port = int(inputs.get("port") or 443)

    ingress = ((fgt_get("/monitor/router/lookup", destination=src) or {})
               .get("entries") or [{}])[0].get("interface")
    verdict = {"match": False, "action": "no route"}
    if ingress:
        pl = fgt_get("/monitor/firewall/policy-lookup", srcintf=ingress, sourceip=src,
                     dest=dst, protocol=str(PROTOCOLS[proto]), destport=str(port)) or {}
        verdict = {"match": bool(pl.get("match")), "policy_id": pl.get("policy_id") or None,
                   "action": pl.get("policy_action") or pl.get("sec_default_action") or "deny"}
    log("%s -> %s %s/%d: %s" % (src, dst, proto, port, verdict["action"]))
    result({"flow": "%s -> %s %s/%d" % (src, dst, proto, port), "ingress": ingress,
            **verdict, "source_owner": owner(src), "destination_owner": owner(dst)})
''')


# --------------------------------------------------------------------------- #
#  apps                                                                        #
# --------------------------------------------------------------------------- #
def _n(key, kind, label, x, y, **params):
    return {"key": key, "kind": kind, "label": label, "x": x, "y": y, "params": params}


def _e(src, dst, branch="always"):
    return {"src": src, "dst": dst, "branch": branch}


_FGT_RECORD_MATCH = (
    "{{ {'source': form.source, 'destination': form.destination, "
    "'protocol': form.protocol, 'port': form.port, 'ingress': srcintf, "
    "'policy_id': verdict.policy_id, 'policy_name': rule.name, "
    "'action': verdict.policy_action, "
    "'src_addr': rule.srcaddr | map(attribute='name') | join(', '), "
    "'dst_addr': rule.dstaddr | map(attribute='name') | join(', '), "
    "'service': rule.service | map(attribute='name') | join(', '), "
    "'checked_by': run.user} }}")
_FGT_RECORD_DENY = (
    "{{ {'source': form.source, 'destination': form.destination, "
    "'protocol': form.protocol, 'port': form.port, 'ingress': srcintf, "
    "'policy_id': none, 'policy_name': '(no rule matches)', "
    "'action': verdict.sec_default_action | default('deny'), "
    "'src_addr': '', 'dst_addr': '', 'service': '', 'checked_by': run.user} }}")

FGT_APP_GRAPH = {
    "nodes": [
        _n("start", "start", "Start", 80, 30),
        _n("route", "api_call", "Route back to the source", 80, 130,
           connection=FGT_CONN, method="GET", path="/monitor/router/lookup",
           query='{"destination": "{{ form.source }}"}',
           extract="results.entries[0].interface", save_as="srcintf"),
        _n("has_route", "decision", "Is there a route?", 80, 230,
           left="{{ srcintf | default('') }}", op="not_empty", right=""),
        _n("lookup", "api_call", "Ask the FortiGate (policy-lookup)", 80, 330,
           connection=FGT_CONN, method="GET", path="/monitor/firewall/policy-lookup",
           query='{"srcintf": "{{ srcintf }}", "sourceip": "{{ form.source }}", '
                 '"dest": "{{ form.destination }}", '
                 '"protocol": "{{ {\'tcp\': 6, \'udp\': 17}[form.protocol] }}", '
                 '"destport": "{{ form.port }}"}',
           extract="results", save_as="verdict"),
        _n("matched", "decision", "Does a rule match?", 80, 430,
           left="{{ verdict.match }}", op="true", right=""),
        _n("rule", "api_call", "Read the rule", 80, 530,
           connection=FGT_CONN, method="GET",
           path="/cmdb/firewall/policy/{{ verdict.policy_id }}",
           query='{"format": "policyid|name|srcintf|dstintf|srcaddr|dstaddr|service|action|status"}',
           extract="results[0]", save_as="rule"),
        _n("record_match", "set", "Verdict: the rule", 80, 630, name="record",
           value=_FGT_RECORD_MATCH),
        _n("record_deny", "set", "Verdict: implicit deny", 360, 530, name="record",
           value=_FGT_RECORD_DENY),
        _n("show", "output", "Show the verdict", 80, 730, value="{{ record }}",
           title="Verdict of the FortiGate", view="keyvalue"),
        _n("end", "end", "End", 80, 830),
        _n("no_route", "fail", "No route", 360, 230,
           message="The FortiGate has no route to {{ form.source }}."),
        _n("api_failed", "fail", "The FortiGate did not answer", 640, 330,
           message="The FortiGate did not answer: {{ last_error.message }}"),
    ],
    "edges": [
        _e("start", "route"), _e("route", "has_route", "ok"), _e("route", "api_failed", "error"),
        _e("has_route", "lookup", "yes"), _e("has_route", "no_route", "no"),
        _e("lookup", "matched", "ok"), _e("lookup", "api_failed", "error"),
        _e("matched", "rule", "yes"), _e("matched", "record_deny", "no"),
        _e("rule", "record_match", "ok"), _e("rule", "api_failed", "error"),
        _e("record_match", "show"), _e("record_deny", "show"), _e("show", "end"),
    ],
}

FLOW_FIELDS = [
    {"name": "source", "label": "Source IP", "type": "text", "required": True,
     "help": "The address the traffic comes from, e.g. 192.0.2.10"},
    {"name": "destination", "label": "Destination IP", "type": "text", "required": True,
     "help": "The address it goes to, e.g. 198.51.100.20"},
    {"name": "protocol", "label": "Protocol", "type": "select", "options": "tcp\nudp",
     "default": "tcp"},
    {"name": "port", "label": "Destination port", "type": "number", "required": True,
     "default": "443"},
]

SCRIPT_FLOW_FIELDS = [
    {"name": "source", "label": "Source IP", "type": "text", "required": True},
    {"name": "destination", "label": "Destination IP", "type": "text", "required": True},
    {"name": "protocol", "label": "Protocol", "type": "select", "options": ["tcp", "udp", "icmp"],
     "default": "tcp"},
    {"name": "port", "label": "Destination port", "type": "number", "default": 443,
     "help": "Ignored for icmp"},
]


def _fgt_actions(cr_key: str) -> list[dict]:
    acts = [
        {"key": "log", "label": "Save to the lookup log", "kind": "save_store",
         "params": {"store": "ex-policy-lookups", "mode": "insert", "rows": "{{ record }}"}},
        {"key": "csv", "label": "Download (CSV)", "kind": "download",
         "params": {"format": "csv", "value": "{{ [record] }}", "filename": "policy-lookup"}},
    ]
    if cr_key:
        acts.append({"key": "ask", "label": "Ask for this access (change request)",
                     "kind": "change_request", "confirm": True,
                     "params": {"action": cr_key,
                                "title": "Open {{ form.protocol }}/{{ form.port }} "
                                         "{{ form.source }} -> {{ form.destination }}",
                                "reason": "Policy lookup by {{ run.user }}: {{ record.action }} "
                                          "({{ record.policy_name }}).",
                                "devices": "", "risk": "medium"}})
    return acts


NETBOX_APP_GRAPH = {
    "nodes": [
        _n("start", "start", "Start", 80, 30),
        _n("lookup", "script", "Run the NetBox script", 80, 130, script="ex-netbox-ip-owner",
           inputs='{"ip": "{{ form.ip }}"}', save_as="nb"),
        _n("known", "decision", "Does NetBox know it?", 80, 230,
           left="{{ nb.owner }}", op="not_empty", right=""),
        _n("owner", "output", "The owner", 80, 330, value="{{ nb.owner }}",
           title="Address record", view="keyvalue"),
        _n("nets", "output", "Its networks", 80, 430, value="{{ nb.prefixes }}",
           title="Prefixes that contain it (most specific first)", view="table"),
        _n("unknown", "output", "Unknown address", 360, 330,
           value="NetBox has no IP address record for {{ form.ip }}. "
                 "Most specific prefix: {{ nb.most_specific or 'none' }}.",
           title="Not documented", view="text"),
        _n("end", "end", "End", 80, 530),
        _n("failed", "fail", "NetBox failed", 360, 130,
           message="NetBox lookup failed: {{ last_error.message }}"),
    ],
    "edges": [
        _e("start", "lookup"), _e("lookup", "known", "ok"), _e("lookup", "failed", "error"),
        _e("known", "owner", "yes"), _e("known", "unknown", "no"),
        _e("owner", "nets"), _e("nets", "end"), _e("unknown", "end"),
    ],
}

EXPLAINER_APP_GRAPH = {
    "nodes": [
        _n("start", "start", "Start", 80, 30),
        _n("explain", "script", "Explain the flow", 80, 130, script="ex-traffic-explainer",
           inputs='{"source": "{{ form.source }}", "destination": "{{ form.destination }}", '
                  '"protocol": "{{ form.protocol }}", "port": "{{ form.port }}"}',
           save_as="flow"),
        _n("show", "output", "The answer", 80, 230, value="{{ flow }}",
           title="{{ flow.flow }}", view="json"),
        _n("end", "end", "End", 80, 330),
        _n("failed", "fail", "Failed", 360, 130, message="{{ last_error.message }}"),
    ],
    "edges": [_e("start", "explain"), _e("explain", "show", "ok"),
              _e("explain", "failed", "error"), _e("show", "end")],
}

CONTACT_LOOKUP_GRAPH = {
    "nodes": [
        _n("start", "start", "Start", 80, 30),
        _n("read", "store_query", "Read the site", 80, 130, store="ex-site-contacts",
           filter='{"site": "{{ form.site }}"}', limit="1", save_as="rows"),
        _n("show", "output", "Show the contact", 80, 230, value="{{ rows[0] }}",
           title="{{ form.site }}", view="keyvalue"),
        _n("end", "end", "End", 80, 330),
    ],
    "edges": [_e("start", "read"), _e("read", "show", "ok"), _e("show", "end")],
}

CONTACT_EDIT_GRAPH = {
    "nodes": [
        _n("start", "start", "Start", 80, 30),
        _n("write", "store_write", "Insert or update the site", 80, 130,
           store="ex-site-contacts", mode="upsert", match='{"site": "{{ form.site }}"}',
           values='{"site": "{{ form.site }}", "contact": "{{ form.contact }}", '
                  '"phone": "{{ form.phone }}", "email": "{{ form.email }}"}',
           save_as="written"),
        _n("read", "store_query", "Read it back", 80, 230, store="ex-site-contacts",
           filter='{"site": "{{ form.site }}"}', limit="1", save_as="rows"),
        _n("show", "output", "Saved", 80, 330, value="{{ rows[0] }}",
           title="Saved: {{ form.site }}", view="keyvalue"),
        _n("end", "end", "End", 80, 430),
    ],
    "edges": [_e("start", "write"), _e("write", "read", "ok"), _e("read", "show", "ok"),
              _e("show", "end")],
}


# --------------------------------------------------------------------------- #
#  DNS & LB Lookup -- the page as three apps (services.studio_dns)             #
# --------------------------------------------------------------------------- #
DNS_LOOKUP_APP = "ex-dns-lb-lookup"
DNS_RECORDS_APP = "ex-dns-records"
DNS_DECOM_APP = "ex-dns-decommission"

DNS_LOOKUP_FIELDS = [
    {"name": "entries", "label": "Hostnames / IPs, one per line", "type": "textarea",
     "required": True,
     "help": "Optionally 'name TYPE', e.g. app.example.com CNAME; *.example.com and "
             "192.0.2.10 work too. At most 50."},
    {"name": "lb", "label": "Show LB matches", "type": "checkbox", "default": "true"},
    {"name": "quick", "label": "Quick LB (gateway only)", "type": "checkbox"},
    {"name": "exact", "label": "Exact match", "type": "checkbox"},
    {"name": "ttl", "label": "Show TTL", "type": "checkbox"},
]
_RECORDS_BUTTON = json.dumps([
    {"label": "Records", "app": DNS_RECORDS_APP,
     "inputs": {"operation": "list", "name": "{{ row._resolved }}"}}])
_LB_BUTTONS = json.dumps([
    {"label": "Open policy", "url": "{{ row._url }}", "when": "{{ row._url }}"},
    {"label": "Decommission", "app": DNS_DECOM_APP,
     "when": "{{ row._aid and row._policy and row._kind in ['fortiweb', 'fortiadc'] }}",
     "inputs": {"appliance": "{{ row._aid }}", "policy": "{{ row._policy }}",
                "hostname": "{{ row._hostname }}"}}])
DNS_LOOKUP_GRAPH = {
    "nodes": [
        _n("start", "start", "Start", 300, 30),
        _n("dns", "dns_lookup", "Ask the resolvers", 300, 120, entries="{{ form.entries }}",
           ttl="{{ form.ttl }}", save_as="dns"),
        _n("dns_failed", "fail", "No lookup", 560, 120, message="{{ last_error.message }}"),
        _n("want_lb", "decision", "LB wanted?", 300, 210, left="{{ form.lb or form.quick }}",
           op="true"),
        _n("lb", "lb_lookup", "Match the fleet's LB cache", 560, 210,
           entries="{{ form.entries }}", exact="{{ form.exact }}", dns="{{ dns }}",
           save_as="lb"),
        _n("lb_failed", "output", "LB matching failed", 800, 210,
           value="{{ last_error.message }}", title="LB matching failed", view="text"),
        _n("show_dns", "output", "DNS answers", 300, 300, value="{{ dns.rows }}",
           title="DNS ({{ dns.servers | join(', ') }})", view="table",
           row_actions=_RECORDS_BUTTON),
        _n("has_lb", "decision", "LB matches wanted?", 300, 390,
           left="{{ form.lb and lb is defined }}", op="true"),
        _n("show_lb", "output", "LB matches", 560, 390, value="{{ lb.rows }}",
           title="LB matches", view="table", row_actions=_LB_BUTTONS),
        _n("has_quick", "decision", "Quick LB wanted?", 300, 480,
           left="{{ form.quick and lb is defined }}", op="true"),
        _n("show_quick", "output", "Quick LB", 560, 480, value="{{ lb.gateways }}",
           title="Quick LB (gateways)", view="table"),
        _n("has_missing", "decision", "Anything found nowhere?", 300, 570,
           left="{{ lb.not_found if lb is defined else dns.unresolved }}", op="not_empty"),
        _n("show_missing", "output", "Not found", 560, 570,
           value="{{ lb.not_found if lb is defined else dns.unresolved }}",
           title="Not found in any source", view="list"),
        _n("end", "end", "End", 300, 660),
    ],
    "edges": [_e("start", "dns"), _e("dns", "want_lb", "ok"), _e("dns", "dns_failed", "error"),
              _e("want_lb", "lb", "yes"), _e("want_lb", "show_dns", "no"),
              _e("lb", "show_dns", "ok"), _e("lb", "lb_failed", "error"),
              _e("lb_failed", "show_dns"), _e("show_dns", "has_lb"),
              _e("has_lb", "show_lb", "yes"), _e("has_lb", "has_quick", "no"),
              _e("show_lb", "has_quick"), _e("has_quick", "show_quick", "yes"),
              _e("has_quick", "has_missing", "no"), _e("show_quick", "has_missing"),
              _e("has_missing", "show_missing", "yes"), _e("has_missing", "end", "no"),
              _e("show_missing", "end")],
}
DNS_LOOKUP_ACTIONS = [
    {"key": "copy-dns", "label": "Copy DNS", "kind": "copy",
     "params": {"format": "text", "value": "{{ dns.tsv }}"}},
    {"key": "copy-lb", "label": "Copy LB", "kind": "copy",
     "params": {"format": "text", "value": "{{ lb.tsv if lb is defined else '' }}"}},
    {"key": "records", "label": "DNS Records", "kind": "open_app",
     "params": {"app": DNS_RECORDS_APP, "inputs": json.dumps(
         {"operation": "list", "name": "{{ dns.rows[0]._resolved if dns.rows else '' }}"})}},
    {"key": "csv-dns", "label": "Download DNS (CSV)", "kind": "download",
     "params": {"format": "csv", "value": "{{ dns.rows }}", "filename": "dns-lookup"}},
    {"key": "csv-lb", "label": "Download LB (CSV)", "kind": "download",
     "params": {"format": "csv", "value": "{{ lb.rows if lb is defined else [] }}",
                "filename": "lb-matches"}},
]

DNS_RECORDS_FIELDS = [
    {"name": "operation", "label": "Operation", "type": "select", "required": True,
     "options": "list\ncreate\nupdate\ndelete", "default": "list",
     "help": "list shows the records of the name; update and delete need the record id "
             "(the Edit and Delete buttons of the list fill it in)."},
    {"name": "backend", "label": "DNS backend", "type": "satom_select",
     "source": "dns_backends",
     "help": "Empty: the only DNS backend there is (Settings > DNS Records)."},
    {"name": "name", "label": "Name", "type": "text", "help": "e.g. app.example.com"},
    {"name": "type", "label": "Type", "type": "select", "default": "A",
     "options": "A\nAAAA\nCNAME\nMX\nNS\nTXT\nSRV\nPTR\nCAA"},
    {"name": "value", "label": "Value", "type": "text", "help": "e.g. 192.0.2.10"},
    {"name": "ttl", "label": "TTL (s)", "type": "text"},
    {"name": "zone", "label": "Zone", "type": "text"},
    {"name": "id", "label": "Record id", "type": "text", "help": "For update and delete."},
]
_RECORD_FORM = {"backend": "{{ records.backend.id }}", "id": "{{ row.id }}",
                "name": "{{ row.name }}", "type": "{{ row.type }}", "value": "{{ row.value }}",
                "ttl": "{{ row.ttl if row.ttl is not none else '' }}", "zone": "{{ row.zone }}"}
_RECORD_BUTTONS = json.dumps([
    {"label": "Edit", "app": DNS_RECORDS_APP, "inputs": dict(_RECORD_FORM, operation="update")},
    {"label": "Delete", "app": DNS_RECORDS_APP, "inputs": dict(_RECORD_FORM, operation="delete")}])
DNS_RECORDS_GRAPH = {
    "nodes": [
        _n("start", "start", "Start", 300, 30),
        _n("is_list", "decision", "List?", 300, 120, left="{{ form.operation }}",
           op="equals", right="list"),
        _n("list", "dns_records", "Read the records", 80, 210, backend="{{ form.backend }}",
           name="{{ form.name }}", zone="{{ form.zone }}", save_as="records"),
        _n("change", "dns_record_change", "Write the record", 520, 210,
           operation="{{ form.operation }}", backend="{{ form.backend }}",
           record='{"id": "{{ form.id }}", "name": "{{ form.name }}", "type": '
                  '"{{ form.type }}", "value": "{{ form.value }}", "ttl": "{{ form.ttl }}", '
                  '"zone": "{{ form.zone }}"}',
           save_as="record"),
        _n("show_change", "output", "What was written", 520, 300, value="{{ record.record }}",
           title="{{ record.operation }}: {{ record.record.name }} in "
                 "{{ record.backend.name or 'the DNS backend' }}", view="keyvalue"),
        _n("relist", "dns_records", "Read the name again", 520, 390,
           backend="{{ record.backend.id or form.backend }}", name="{{ record.record.name }}",
           zone="{{ form.zone }}", save_as="records"),
        _n("relist_failed", "output", "Could not read it again", 760, 390,
           value="{{ last_error.message }}", title="The record was written; listing it "
                                                   "again failed", view="text"),
        _n("show_list", "output", "Records", 300, 480, value="{{ records.records }}",
           title="{{ records.name or records.zone or 'All records' }} in "
                 "{{ records.backend.name }}", view="table", row_actions=_RECORD_BUTTONS),
        _n("failed", "fail", "Refused", 80, 300, message="{{ last_error.message }}"),
        _n("end", "end", "End", 300, 570),
    ],
    "edges": [_e("start", "is_list"), _e("is_list", "list", "yes"),
              _e("is_list", "change", "no"), _e("list", "show_list", "ok"),
              _e("list", "failed", "error"), _e("change", "show_change", "ok"),
              _e("change", "failed", "error"), _e("show_change", "relist"),
              _e("relist", "show_list", "ok"), _e("relist", "relist_failed", "error"),
              _e("relist_failed", "end"), _e("show_list", "end")],
}
DNS_RECORDS_ACTIONS = [
    {"key": "new", "label": "New record", "kind": "open_app",
     "params": {"app": DNS_RECORDS_APP, "inputs": json.dumps(
         {"operation": "create", "backend": "{{ records.backend.id if records is defined "
                                            "else form.backend }}",
          "name": "{{ form.name }}", "type": "A"})}},
    {"key": "csv", "label": "Download (CSV)", "kind": "download",
     "params": {"format": "csv", "value": "{{ records.records if records is defined else [] }}",
                "filename": "dns-records"}},
]

DNS_DECOM_FIELDS = [
    {"name": "appliance", "label": "Appliance", "type": "satom_select",
     "source": "lb_appliances", "required": True, "search": True},
    {"name": "policy", "label": "Server policy / virtual server", "type": "text",
     "required": True},
    {"name": "hostname", "label": "Hostname being retired", "type": "text",
     "help": "Its DNS records are removed first."},
]
DNS_DECOM_GRAPH = {
    "nodes": [
        _n("start", "start", "Start", 300, 30),
        _n("plan", "dns_decommission_plan", "Plan (reads only)", 300, 120,
           appliance="{{ form.appliance }}", policy="{{ form.policy }}",
           hostname="{{ form.hostname }}", save_as="plan"),
        _n("no_plan", "fail", "No plan", 560, 120, message="{{ last_error.message }}"),
        _n("show_plan", "output", "The plan", 300, 210, value="{{ plan }}",
           title="Decommission plan", view="plan"),
        _n("confirm", "ask", "Confirm", 300, 300,
           prompt="Decommission {{ plan.target.policy }} on {{ plan.target.appliance }}? "
                  "Everything marked delete or unbind is removed, DNS records first.",
           pass_label="Decommission", fail_label="Cancel",
           acknowledge="{{ plan.warnings | rejectattr('blocking') | map(attribute='text') "
                       "| list }}",
           blockers="{{ plan.warnings | selectattr('blocking') | map(attribute='text') "
                    "| list }}",
           confirm_text="{{ plan.target.policy }}"),
        _n("apply", "dns_decommission_apply", "Apply the confirmed plan", 300, 390,
           appliance="{{ form.appliance }}", policy="{{ form.policy }}",
           hostname="{{ form.hostname }}", confirm="{{ plan.fingerprint }}",
           acknowledge="{{ last_answer.all_acknowledged }}", save_as="decommission"),
        _n("show_done", "output", "Done", 300, 480, value="{{ decommission.results }}",
           title="Done: {{ decommission.summary.ok }} of {{ decommission.summary.total }} "
                 "step(s)", view="table"),
        _n("show_failed", "output", "What happened", 560, 390,
           value="{{ decommission.results if decommission is defined and "
                 "decommission.results is defined else [] }}",
           title="Decommission failed: {{ last_error.message }}", view="table"),
        _n("failed", "fail", "Failed", 560, 480, message="{{ last_error.message }}"),
        _n("cancelled", "output", "Cancelled", 60, 390, value="Nothing was changed.",
           title="Cancelled", view="text"),
        _n("end", "end", "End", 300, 570),
    ],
    "edges": [_e("start", "plan"), _e("plan", "show_plan", "ok"), _e("plan", "no_plan", "error"),
              _e("show_plan", "confirm"), _e("confirm", "apply", "yes"),
              _e("confirm", "cancelled", "no"), _e("cancelled", "end"),
              _e("apply", "show_done", "ok"), _e("apply", "show_failed", "error"),
              _e("show_failed", "failed"), _e("show_done", "end")],
}


# --------------------------------------------------------------------------- #
#  the bundles                                                                 #
# --------------------------------------------------------------------------- #
FGT_CONNECTION = {
    "slug": FGT_CONN, "name": "FortiGate REST API (example)", "kind": "http",
    "form": {"base_url": "https://fortigate.example.com/api/v2", "auth": "bearer",
             "timeout": 15, "verify_tls": True,
             "description": "Example. Replace the host with your FortiGate, then paste the "
                            "token of a REST API administrator (System > Administrators > "
                            "Create New > REST API Admin) with a READ-ONLY profile and this "
                            "SATOM node as its trusted host."}}
NB_CONNECTION = {
    "slug": NB_CONN, "name": "NetBox REST API (example)", "kind": "http",
    "form": {"base_url": "https://netbox.example.com/api", "auth": "api_key",
             "header_name": "Authorization", "timeout": 15, "verify_tls": True,
             "description": "Example. Replace the host with your NetBox. Secret: "
                            "\"Token <key>\" (a v1 API token, read-only). With a v2 token "
                            "(NetBox 4.5+) choose Bearer and paste the token alone."}}

POLICY_STORE = {
    "slug": "ex-policy-lookups", "name": "Policy lookups (example)",
    "description": "Every verdict an operator chose to keep, from the FortiGate policy finder.",
    "columns": [
        {"name": "source", "type": "text", "required": True},
        {"name": "destination", "type": "text", "required": True},
        {"name": "protocol", "type": "text"}, {"name": "port", "type": "number"},
        {"name": "ingress", "type": "text"}, {"name": "policy_id", "type": "number"},
        {"name": "policy_name", "type": "text"}, {"name": "action", "type": "text"},
        {"name": "src_addr", "type": "text"}, {"name": "dst_addr", "type": "text"},
        {"name": "service", "type": "text"}, {"name": "checked_by", "type": "text"}]}

CONTACT_STORE = {
    "slug": "ex-site-contacts", "name": "Site contacts (example)",
    "description": "Who to call for each site. Read by the Site contact app, written by "
                   "the Edit site contact app.",
    "columns": [
        {"name": "site", "label": "Site", "type": "text", "required": True},
        {"name": "contact", "label": "Contact", "type": "text"},
        {"name": "phone", "label": "Phone", "type": "text"},
        {"name": "email", "label": "E-mail", "type": "text"}],
    "rows": [
        {"site": "Zurich DC", "contact": "NOC Zurich", "phone": "+41 44 000 00 00",
         "email": "noc-zrh@example.com"},
        {"site": "Mexico City DC", "contact": "NOC CDMX", "phone": "+52 55 0000 0000",
         "email": "noc-cdmx@example.com"},
        {"site": "Lab", "contact": "Lab team", "phone": "", "email": "lab@example.com"}]}

BUNDLES = [
    {"key": "fortigate-policy",
     "title": "FortiGate: which rule lets this traffic through?",
     "summary": "An app built only from the diagram: it asks the FortiGate for the route back "
                "to the source, runs the FortiGate's own policy-lookup and reads the matching "
                "rule. The operator can keep the verdict in a data store, download it, or ask "
                "for the access as a change request. The same lookup is included as a script.",
     "connections": [FGT_CONNECTION], "stores": [POLICY_STORE],
     "scripts": [{"slug": "ex-fortigate-policy-lookup",
                  "name": "FortiGate policy lookup (example)",
                  "description": "Which FortiGate rule matches a flow, asked to the FortiGate.",
                  "fields": SCRIPT_FLOW_FIELDS, "connections": [FGT_CONN], "network": "none",
                  "timeout": 60, "code": FGT_SCRIPT}],
     "apps": [{"slug": "ex-policy-finder", "name": "Policy finder (example)",
               "icon": "bi-signpost-split", "fields": FLOW_FIELDS, "graph": FGT_APP_GRAPH,
               "actions": "fortigate", "publish": False,
               "description": "Which FortiGate rule decides this flow, and act on the answer."}],
     "setup": ["Open the connection ex-fortigate: set the base URL to "
               "https://<your FortiGate>/api/v2 and paste the token of a read-only REST API "
               "administrator whose trusted host is this node.",
               "Press Test on the connection with the path /monitor/system/status.",
               "Open the app Policy finder (example), Test it (e.g. source 192.0.2.10, "
               "destination 198.51.100.20, tcp/443), choose its ADOMs and users, Publish."]},
    {"key": "netbox-ip",
     "title": "NetBox: who owns this IP address?",
     "summary": "A Script Library script that calls NetBox through a connection (it never sees "
                "the token), and an app whose diagram runs that script and shows the owner and "
                "the networks of the address.",
     "connections": [NB_CONNECTION], "stores": [],
     "scripts": [{"slug": "ex-netbox-ip-owner", "name": "NetBox IP owner (example)",
                  "description": "The NetBox record and the prefixes of one IP address.",
                  "fields": [{"name": "ip", "label": "IP address", "type": "text",
                              "required": True}],
                  "connections": [NB_CONN], "network": "none", "timeout": 60,
                  "code": NETBOX_SCRIPT}],
     "apps": [{"slug": "ex-ip-owner", "name": "IP owner (example)", "icon": "bi-diagram-3",
               "fields": [{"name": "ip", "label": "IP address", "type": "text",
                           "required": True, "help": "e.g. 192.0.2.10"}],
               "graph": NETBOX_APP_GRAPH, "actions": [
                   {"key": "json", "label": "Download (JSON)", "kind": "download",
                    "params": {"format": "json", "value": "{{ nb }}", "filename": "ip-owner"}}],
               "publish": False,
               "description": "Who owns an IP address and which networks contain it."}],
     "setup": ["Open the connection ex-netbox: set the base URL to https://<your NetBox>/api "
               "and the secret to \"Token <read-only API token>\".",
               "Press Test with the path /status/.",
               "Test the app IP owner (example), then Publish it."]},
    {"key": "traffic-explainer",
     "title": "Explain a flow (FortiGate + NetBox)",
     "summary": "One script with two connections: who owns both ends of a flow (NetBox) and "
                "which FortiGate rule decides it. Each call carries its own connection's "
                "credential; the script holds neither. Installs the two connections if they "
                "are missing.",
     "connections": [FGT_CONNECTION, NB_CONNECTION], "stores": [],
     "scripts": [{"slug": "ex-traffic-explainer", "name": "Explain a flow (example)",
                  "description": "Owners of both ends and the deciding FortiGate rule.",
                  "fields": [f for f in SCRIPT_FLOW_FIELDS if f["name"] != "protocol"] + [
                      {"name": "protocol", "label": "Protocol", "type": "select",
                       "options": ["tcp", "udp"], "default": "tcp"}],
                  "connections": [FGT_CONN, NB_CONN], "network": "none", "timeout": 90,
                  "code": EXPLAINER_SCRIPT}],
     "apps": [{"slug": "ex-traffic-explainer", "name": "Explain a flow (example)",
               "icon": "bi-arrow-left-right", "fields": FLOW_FIELDS,
               "graph": EXPLAINER_APP_GRAPH, "actions": [], "publish": False,
               "description": "Owners of both ends of a flow and the rule that decides it."}],
     "setup": ["Finish the setup of ex-fortigate and ex-netbox (see the two bundles above).",
               "Test the app Explain a flow (example), then Publish it."]},
    {"key": "site-contacts",
     "title": "Data stores: site contacts (works right away)",
     "summary": "No external system: a data store with three sample rows, an app whose list "
                "field is fed by that store and reads one row, and an app that inserts or "
                "updates a row (upsert). Both apps are published for Studio authors in every "
                "ADOM, so they appear under Operations > Plugins at once.",
     "connections": [], "stores": [CONTACT_STORE], "scripts": [],
     "apps": [{"slug": "ex-site-contact", "name": "Site contact (example)",
               "icon": "bi-telephone", "publish": True,
               "fields": [{"name": "site", "label": "Site", "type": "store_select",
                           "required": True, "store": "ex-site-contacts",
                           "value_col": "site", "label_col": "site"}],
               "graph": CONTACT_LOOKUP_GRAPH, "actions": [
                   {"key": "csv", "label": "Download (CSV)", "kind": "download",
                    "params": {"format": "csv", "value": "{{ rows }}", "filename": "contact"}}],
               "description": "Who to call for a site."},
              {"slug": "ex-site-contact-edit", "name": "Edit site contact (example)",
               "icon": "bi-pencil-square", "publish": True,
               "fields": [{"name": "site", "label": "Site", "type": "text", "required": True},
                          {"name": "contact", "label": "Contact", "type": "text"},
                          {"name": "phone", "label": "Phone", "type": "text"},
                          {"name": "email", "label": "E-mail", "type": "text"}],
               "graph": CONTACT_EDIT_GRAPH, "actions": [],
               "description": "Add a site, or change its contact (upsert on the site name)."}],
     "setup": ["Nothing to configure. Open Operations > Plugins > Site contact (example).",
               "To let other users run them, open each app > Settings and pick users or "
               "groups (Administrator > Access > Groups)."]},
    {"key": "dns-lb-lookup",
     "title": "DNS & LB Lookup (the page as three apps)",
     "summary": "The DNS & LB Lookup page rebuilt in Plugin Studio: look names up on every "
                "resolver and match them to the FortiWeb / FortiADC cache, copy the DNS or "
                "LB table, open a name's DNS records (edit or delete each one) and "
                "decommission a matched service after ticking its warnings. Each step asks "
                "the same permission as the page (network.view, user_manage for records, "
                "config_write to decommission). Published for Studio authors in every ADOM.",
     "connections": [], "stores": [], "scripts": [],
     "apps": [{"slug": DNS_LOOKUP_APP, "name": "DNS & LB Lookup", "icon": "bi-globe2",
               "publish": True, "fields": DNS_LOOKUP_FIELDS, "graph": DNS_LOOKUP_GRAPH,
               "actions": DNS_LOOKUP_ACTIONS,
               "description": "Resolve hostnames and IPs on the configured DNS servers and "
                              "match them to this ADOM's load-balancing config (device "
                              "cache)."},
              {"slug": DNS_RECORDS_APP, "name": "DNS Records", "icon": "bi-card-list",
               "publish": True, "fields": DNS_RECORDS_FIELDS, "graph": DNS_RECORDS_GRAPH,
               "actions": DNS_RECORDS_ACTIONS,
               "description": "List, create, change or delete the records of a DNS backend "
                              "(Settings > DNS Records)."},
              {"slug": DNS_DECOM_APP, "name": "Decommission a service", "icon": "bi-trash3",
               "publish": True, "fields": DNS_DECOM_FIELDS, "graph": DNS_DECOM_GRAPH,
               "actions": [],
               "description": "Retire a FortiWeb server policy or FortiADC virtual server "
                              "with what only it uses, and its DNS records: plan, confirm, "
                              "apply."}],
     "setup": ["Nothing to configure: the apps use the resolvers of Administrator > Objects "
               "> DNS Resolvers and the backends of Settings > DNS Records.",
               "Open Operations > Plugins > DNS & LB Lookup.",
               "To let other users run them, open each app > Settings and pick users or "
               "groups; each step still asks them for the page's permission."]},
]
BUNDLE_KEYS = tuple(b["key"] for b in BUNDLES)


class ExampleError(ValueError):
    pass


def bundle(key: str) -> dict:
    for b in BUNDLES:
        if b["key"] == key:
            return b
    raise ExampleError("no example %r" % key)


def _cr_key() -> str:
    """A change type that applies to FortiGates -- a policy one if there is
    one -- for the "ask for this access" action; '' = leave the action out."""
    try:
        from ..views.change_requests import cr_type_entries
        entries = [e for e in cr_type_entries() if "fortigate" in (e.get("products") or [])]
    except Exception:  # noqa: BLE001
        return ""
    pol = [e for e in entries if "policy" in e["key"]]
    return (pol or entries or [{}])[0].get("key", "")


# --------------------------------------------------------------------------- #
#  state, install, remove                                                      #
# --------------------------------------------------------------------------- #
def _exists(kind: str, slug: str) -> bool:
    if kind == "connection":
        from . import studio_connections as SC
        return SC.get(slug) is not None
    if kind == "store":
        from . import studio_store as SS
        return SS.get(slug) is not None
    if kind == "script":
        from . import script_library as SL
        try:
            return bool(SL.get(slug))
        except SL.ScriptError:
            return False
    from . import studio_apps as SA
    return SA.get(slug) is not None


def objects(b: dict) -> list[tuple[str, str, str]]:
    """``[(kind, slug, name)]`` of a bundle, in install order."""
    out = [("connection", c["slug"], c["name"]) for c in b["connections"]]
    out += [("store", s["slug"], s["name"]) for s in b["stores"]]
    out += [("script", s["slug"], s["name"]) for s in b["scripts"]]
    out += [("app", a["slug"], a["name"]) for a in b["apps"]]
    return out


def status() -> list[dict]:
    """Every bundle with, for each object, whether it is installed."""
    out = []
    for b in BUNDLES:
        objs = [{"kind": k, "slug": s, "name": n, "installed": _exists(k, s)}
                for k, s, n in objects(b)]
        out.append({**{k: b[k] for k in ("key", "title", "summary", "setup")},
                    "objects": objs, "installed": all(o["installed"] for o in objs),
                    "partly": any(o["installed"] for o in objs),
                    "code": [{"slug": s["slug"], "code": s["code"]} for s in b["scripts"]]})
    return out


def install(key: str, by: str) -> dict:
    """Create the missing objects of bundle *key*. ``{"created": [...],
    "kept": [...]}`` -- an existing object is kept as it is."""
    from . import script_library as SL
    from . import studio_apps as SA
    from . import studio_connections as SC
    from . import studio_store as SS
    from ..extensions import db
    b = bundle(key)
    created, kept = [], []
    for c in b["connections"]:
        if SC.get(c["slug"]) is not None:
            kept.append(c["slug"])
            continue
        conn = SC.create(c["slug"], c["name"], c["kind"], by)
        SC.save(conn, dict(c["form"], name=c["name"]), by)
        created.append(c["slug"])
    for s in b["stores"]:
        if SS.get(s["slug"]) is not None:
            kept.append(s["slug"])
            continue
        st = SS.create(s["slug"], s["name"], by)
        SS.save_schema(st, s["name"], s["description"], s["columns"], by)
        for row in s.get("rows") or []:
            SS.insert(st, row, by)
        created.append(s["slug"])
    for s in b["scripts"]:
        if _exists("script", s["slug"]):
            kept.append(s["slug"])
            continue
        SL.create(s["slug"], s["name"], by)
        SL.save_draft(s["slug"], {SL.ENTRY: s["code"]},
                      {"name": s["name"], "description": s["description"],
                       "fields": s["fields"], "network": s["network"],
                       "timeout": s["timeout"], "connections": s["connections"]},
                      by, note="installed from Python Studio > Examples")
        SL.publish(s["slug"], "example, as installed", by)
        created.append(s["slug"])
    # Every new app exists before any of them is saved: an action or a row
    # button may open another app of the bundle (dns-lb-lookup), and an
    # action naming an app that does not exist yet does not validate.
    new = []
    for a in b["apps"]:
        if SA.get(a["slug"]) is not None:
            kept.append(a["slug"])
            continue
        new.append((a, SA.create(a["slug"], a["name"], by)))
    for a, app in new:
        actions = _fgt_actions(_cr_key()) if a["actions"] == "fortigate" else a["actions"]
        probs = SA.save_draft(app, fields=a["fields"], graph=a["graph"], actions=actions, by=by)
        if probs:
            db.session.rollback()
            raise ExampleError("example app %s does not validate: %s"
                               % (a["slug"], "; ".join(probs)))
        SA.save_settings(app, {"name": a["name"], "description": a["description"],
                               "icon": a["icon"], "adoms": ["*"],
                               "access": {"users": [], "groups": []}}, [], by)
        if a.get("publish"):
            SA.publish(app, "example, as installed", by)
        created.append(a["slug"])
    return {"created": created, "kept": kept}


#: (kind, slug) of every object an example installs. These are the
#: TEMPLATES: they can be edited, disabled, reset and downloaded, never
#: deleted (operator, 2026-10-23) -- the Examples pane lost its Remove button
#: and every delete route asks is_template first.
TEMPLATE_OBJECTS = frozenset((k, s) for b in BUNDLES for k, s, _n in objects(b))


def is_template(kind: str, slug: str) -> bool:
    return (kind, slug) in TEMPLATE_OBJECTS

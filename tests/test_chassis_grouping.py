"""Guards for CHASSIS grouping — several appliance rows that are one device.

Why this exists, measured live on fortiweb09 (FortiWeb-KVM 7.6.8) after
``adom-admin`` was enabled and three ADOMs were created:

  * ``server-policy/policy`` differs per ADOM — the config really is
    partitioned, so the rows are not duplicates.
  * ``system/interface`` and ``system/vip`` are IDENTICAL from all four ADOMs
    — the network and the hardware are NOT partitioned.

The authentication token carries exactly one ADOM (``Appliance.vdom``, baked
in ``clients/fortiweb._auth_token``) and there is no per-request override, so
a multi-ADOM device can only be registered as one row per ADOM. Everything
that reasoned per ROW was therefore answering a hardware question with a count
of rows: capacity got N independent budgets for one CPU, interface roles read
as undeclared on every sibling, and "migrate to another FortiWeb" would
happily migrate a policy onto the same chassis and call it a move.

The grouping is DERIVED from (kind, host, port), never stored: two rows that
dial the same address and port are the same box, and no stored group id can
be more true than that — only staler.
"""
import re
from pathlib import Path

import pytest

from app import models
from app.services import capacity, policy_ops


APP = Path(__file__).resolve().parents[1] / "app"


class _Row:
    """Duck-typed appliance row (no Flask, no DB)."""

    def __init__(self, name, host, port=443, kind="fortiweb", vdom=None,
                 is_cluster=False, id=None):
        self.name = name
        self.host = host
        self.port = port
        self.kind = kind
        self.vdom = vdom
        self.is_cluster = is_cluster
        self.id = id


# --------------------------------------------------------------------------- #
#  chassis_key                                                                  #
# --------------------------------------------------------------------------- #
def test_same_host_and_port_is_the_same_chassis():
    a = _Row("fwb09", "192.0.2.14", vdom="root")
    b = _Row("fwb09@prod", "192.0.2.14", vdom="adom_prod")
    assert models.chassis_key(a) == models.chassis_key(b)


def test_a_different_host_is_a_different_chassis():
    assert models.chassis_key(_Row("a", "192.0.2.14")) != \
        models.chassis_key(_Row("b", "192.0.2.15"))


def test_a_different_port_is_a_different_chassis():
    """Two management ports on one address are two appliances behind a NAT far
    more often than they are one box."""
    assert models.chassis_key(_Row("a", "192.0.2.14", port=443)) != \
        models.chassis_key(_Row("b", "192.0.2.14", port=8443))


def test_a_different_product_is_never_the_same_chassis():
    assert models.chassis_key(_Row("a", "192.0.2.14", kind="fortiweb")) != \
        models.chassis_key(_Row("b", "192.0.2.14", kind="fortiadc"))


def test_host_matching_is_case_insensitive_and_trimmed():
    assert models.chassis_key(_Row("a", " FWB09.example.com ")) == \
        models.chassis_key(_Row("b", "fwb09.example.com"))


def test_a_row_without_a_host_has_no_chassis():
    """An HA cluster node 0 in per-node mode has no connection of its own.
    Giving every such container the same key would merge unrelated clusters
    into one imaginary chassis."""
    assert models.chassis_key(_Row("node0", "")) is None
    assert models.chassis_key(_Row("node0", None)) is None


def test_a_cluster_container_is_never_grouped_by_its_vip():
    """A VIP-mode cluster node 0 DOES carry a host — the shared VIP — and its
    members may carry it too. Grouping them would call a two-box HA pair one
    chassis, which is the opposite of the truth."""
    assert models.chassis_key(_Row("clu", "192.0.2.50", is_cluster=True)) is None


def test_unknown_chassis_degrades_to_this_row_alone():
    """Never to 'every ungrouped row'. A widened group is a widened capacity
    count and a warning on unrelated migrations."""
    lone = _Row("node0", "")
    assert models.chassis_siblings(lone) == [lone]
    assert models.chassis_siblings(lone, include_self=False) == []


# --------------------------------------------------------------------------- #
#  The same-chassis pre-flight check                                            #
# --------------------------------------------------------------------------- #
def test_same_chassis_is_detected_between_two_adom_rows():
    assert policy_ops._same_chassis(_Row("a", "192.0.2.14", vdom="root"),
                                    _Row("b", "192.0.2.14", vdom="adom_prod"))


def test_different_devices_are_not_flagged():
    """A warning that fires on the ORDINARY case is one operators learn to
    click past, which costs more than it buys."""
    assert not policy_ops._same_chassis(_Row("a", "192.0.2.14"),
                                        _Row("b", "192.0.2.15"))


def test_unresolvable_rows_are_not_flagged_as_same_chassis():
    assert not policy_ops._same_chassis(_Row("a", ""), _Row("b", ""))
    assert not policy_ops._same_chassis(_Row("a", "", is_cluster=True),
                                        _Row("b", "", is_cluster=True))


def test_the_chassis_check_warns_and_never_blocks():
    """Moving a policy between ADOMs of one box is legitimate — it is just not
    the operation the button's name promises. Blocking it would forbid a
    supported workflow to make a point."""
    src = (APP / "services" / "policy_ops.py").read_text(encoding="utf-8")
    start = src.index('if cross_box and _same_chassis(')
    block = src[start:start + 900]
    assert 'add("chassis", "warn"' in block
    assert '"block"' not in block


def test_the_chassis_warning_names_the_shared_host():
    """'Same physical device' without the address leaves the operator to guess
    WHICH device, and the whole point is that the two names look different."""
    src = (APP / "services" / "policy_ops.py").read_text(encoding="utf-8")
    start = src.index('if cross_box and _same_chassis(')
    block = src[start:start + 900]
    assert "source_appl.host" in block


# --------------------------------------------------------------------------- #
#  Capacity is a property of the hardware                                       #
# --------------------------------------------------------------------------- #
def test_headroom_counts_the_chassis_not_the_row(monkeypatch):
    """The number that used to lie. Three ADOM rows on one box were getting
    three independent budgets against one CPU, and each one reported room."""
    rows = [_Row("fwb09", "192.0.2.14", id=1), _Row("fwb09@p", "192.0.2.14", id=2),
            _Row("fwb09@d", "192.0.2.14", id=3)]
    monkeypatch.setattr(models, "chassis_siblings", lambda a, **kw: rows)
    seen = {}

    def fake_count(appliance_id, otype):
        seen.setdefault("ids", []).append(appliance_id)
        return 7

    monkeypatch.setattr(capacity, "current_count", fake_count)
    used, n = capacity.chassis_count(rows[0], "server_policy")
    assert sorted(seen["ids"]) == [1, 2, 3]
    assert n == 3 and used == 21


def test_chassis_count_falls_back_to_the_single_row(monkeypatch):
    """A grouping that cannot be resolved must narrow, never widen."""
    def boom(a, **kw):
        raise RuntimeError("no app context")

    monkeypatch.setattr(models, "chassis_siblings", boom)
    monkeypatch.setattr(capacity, "current_count", lambda i, o: 1)
    used, n = capacity.chassis_count(_Row("solo", "192.0.2.14", id=9), "server_policy")
    assert (used, n) == (1, 1)


def test_chassis_count_survives_an_empty_sibling_list(monkeypatch):
    """chassis_siblings can legitimately come back EMPTY — an appliance row
    that is not committed yet matches nothing in the query it issues. Counting
    "no ids" would return 0 used and report a full budget on a box that is
    full, so the row itself has to be the floor."""
    monkeypatch.setattr(models, "chassis_siblings", lambda a, **kw: [])
    monkeypatch.setattr(capacity, "current_count", lambda i, o: 100)
    used, n = capacity.chassis_count(_Row("fresh", "192.0.2.14", id=5),
                                     "server_policy")
    assert (used, n) == (100, 1), "the row's own id must be the floor, not []"


def test_current_count_is_the_single_counting_seam():
    """chassis_count must SUM current_count, not issue a second widened query.
    A parallel query path moves the seam every existing caller and test
    already intercepts — which is how this change first broke
    tests/test_capacity_plan.py by reaching the database from a unit test."""
    src = (APP / "services" / "capacity.py").read_text(encoding="utf-8")
    fn = src[src.index("def chassis_count("):src.index("@dataclass")]
    body = re.sub(r'"{3}.*?"{3}', "", fn, flags=re.S)
    assert "current_count(" in body
    assert "db.session" not in body, "chassis_count must not query directly"


def test_headroom_uses_the_chassis_number():
    src = (APP / "services" / "capacity.py").read_text(encoding="utf-8")
    fn = src[src.index("def headroom("):src.index("def fleet_headroom(")]
    body = re.sub(r"#[^\n]*", "", fn)
    assert "chassis_count(" in body
    assert "current_count(" not in body, \
        "headroom must not fall back to the per-row count"


def test_the_message_says_when_it_counted_more_than_one_row(monkeypatch):
    """A used-count larger than the row holds reads as a broken counter unless
    the message names the scope it actually measured. Executed rather than
    grepped: the previous version asserted that the source mentioned ``h.rows``
    and stayed green when the row count was dropped on the way in."""
    monkeypatch.setattr(capacity, "chassis_count", lambda a, o: (5, 3))
    monkeypatch.setattr(capacity, "limit_for_appliance", lambda a, o: None)
    appl = _Row("fwb09@prod", "192.0.2.14", id=2)
    appl.model, appl.firmware, appl.id = "FortiWeb-VM04", "7.6.8", 2
    ok, msg = capacity.check_headroom(appl, "server_policy", want=1)
    assert ok is True
    assert "3 ADOM rows" in msg and "192.0.2.14" in msg, msg


def test_a_single_row_message_says_nothing_about_adoms(monkeypatch):
    """The scope note must not appear on an ordinary device — noise on the
    common case is how operators stop reading the uncommon one."""
    monkeypatch.setattr(capacity, "chassis_count", lambda a, o: (5, 1))
    monkeypatch.setattr(capacity, "limit_for_appliance", lambda a, o: None)
    appl = _Row("fwb10", "192.0.2.15", id=3)
    appl.model, appl.firmware = "FortiWeb-VM04", "7.6.8"
    _ok, msg = capacity.check_headroom(appl, "server_policy", want=1)
    assert "ADOM rows" not in msg, msg


def test_the_row_count_travels_on_the_measurement(monkeypatch):
    """headroom() must put the scope ON the Headroom it returns. Dropping it
    there silently defaults every message back to 'one row'."""
    monkeypatch.setattr(capacity, "chassis_count", lambda a, o: (5, 4))
    monkeypatch.setattr(capacity, "limit_for_appliance", lambda a, o: None)
    appl = _Row("fwb09", "192.0.2.14", id=1)
    appl.model, appl.firmware = "FortiWeb-VM04", "7.6.8"
    assert capacity.headroom(appl, "server_policy").rows == 4


# --------------------------------------------------------------------------- #
#  Interface documentation is chassis-wide                                      #
# --------------------------------------------------------------------------- #
class _Iface:
    def __init__(self, appliance_id, name, role, segment=""):
        self.appliance_id = appliance_id
        self.name = name
        self.role = role
        self.segment = segment
        self.ip_address = ""


class _FakeIfaceModel:
    """Stands in for ApplianceInterface with an in-memory .query.filter()."""

    rows: list = []

    class _Q:
        def __init__(self, rows):
            self._rows = rows

        def filter(self, criterion):
            # The production code filters on appliance_id.in_(ids); the ids are
            # recovered from the compiled criterion so the fake cannot silently
            # ignore a filter the real query would honour.
            wanted = set(criterion.right.value)
            return _FakeIfaceModel._Q([r for r in self._rows
                                       if r.appliance_id in wanted])

        def all(self):
            return list(self._rows)

    appliance_id = None  # replaced below


def _install_fake_ifaces(monkeypatch, rows, siblings):
    import sqlalchemy as sa

    class _Model:
        appliance_id = sa.column("appliance_id")
        query = _FakeIfaceModel._Q(rows)

    monkeypatch.setattr(models, "ApplianceInterface", _Model)
    monkeypatch.setattr(models, "chassis_siblings", lambda a, **kw: siblings)


def test_documented_roles_reads_the_whole_chassis(monkeypatch):
    """Ports are physical and shared across ADOMs (measured live on
    fortiweb09), while the documentation is stored per row. Reading only this
    row reports every sibling as undeclared — a warning produced by the schema,
    not by the network."""
    base = _Row("fwb09", "192.0.2.14", id=1)
    adom = _Row("fwb09@prod", "192.0.2.14", id=2, vdom="adom_prod")
    _install_fake_ifaces(monkeypatch,
                         [_Iface(1, "port2.20", "traffic_in", "VLAN20")],
                         [base, adom])
    got = policy_ops._documented_roles(adom)
    assert got["port2.20"]["role"] == "traffic_in", \
        "the ADOM row must inherit the chassis' documentation"
    assert got["port2.20"]["segment"] == "VLAN20"


def test_the_rows_own_declaration_wins_over_a_siblings(monkeypatch):
    """A per-ADOM override is a deliberate statement. If a sibling's row could
    overwrite it, declaring anything on the ADOM row would be pointless."""
    base = _Row("fwb09", "192.0.2.14", id=1)
    adom = _Row("fwb09@prod", "192.0.2.14", id=2, vdom="adom_prod")
    _install_fake_ifaces(monkeypatch,
                         [_Iface(1, "port3", "traffic_out", "chassis default"),
                          _Iface(2, "port3", "ha_sync", "adom override")],
                         [base, adom])
    assert policy_ops._documented_roles(adom)["port3"]["role"] == "ha_sync"
    # ...and symmetrically, from the base row's point of view its OWN value wins.
    assert policy_ops._documented_roles(base)["port3"]["role"] == "traffic_out"


def test_documented_roles_is_empty_when_nothing_was_declared(monkeypatch):
    row = _Row("fwb09", "192.0.2.14", id=1)
    _install_fake_ifaces(monkeypatch, [], [row])
    assert policy_ops._documented_roles(row) == {}


def test_documented_roles_ignores_unrelated_devices(monkeypatch):
    """A widened group is a role read off the wrong box."""
    mine = _Row("fwb09", "192.0.2.14", id=1)
    _install_fake_ifaces(monkeypatch,
                         [_Iface(1, "port1", "management"),
                          _Iface(99, "port1", "traffic_in")],
                         [mine])
    assert policy_ops._documented_roles(mine)["port1"]["role"] == "management"

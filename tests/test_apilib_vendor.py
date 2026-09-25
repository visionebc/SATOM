"""Vendor Ansible collection -> spans evidence (``app/services/apilib_vendor``).

The fixtures are tiny hand-written collections in ``tmp_path`` that copy the
real layouts (FortiOS ``versioned_schema`` at module level, FortiAnalyzer
``urls_list`` / ``module_arg_spec`` inside ``main()``). One test at the end
runs against the real collections on this node when they are present.
"""
from __future__ import annotations

import gzip
import json
import os
import sys
import textwrap
from datetime import datetime

import pytest

from app.services import apilib_vendor as av

REAL_ROOT = "/var/tmp/apilib-vendor"


# ---------------------------------------------------------------------------
# fixture builders
# ---------------------------------------------------------------------------

def _collection(root, namespace, name, version, modules, release_date="2026-08-17"):
    root.mkdir(parents=True, exist_ok=True)
    (root / "MANIFEST.json").write_text(json.dumps({"collection_info": {
        "namespace": namespace, "name": name, "version": version}}))
    if release_date:
        (root / "changelogs").mkdir()
        # An older release listed first: its date must not be picked up.
        (root / "changelogs" / "changelog.yaml").write_text(textwrap.dedent(f"""\
            ancestor: null
            releases:
              0.9.0:
                changes:
                  release_summary: old
                release_date: "2020-01-01"
              {version}:
                changes:
                  release_summary: current
                release_date: "{release_date}"
            """))
    mdir = root / "plugins" / "modules"
    mdir.mkdir(parents=True)
    (mdir / "__init__.py").write_text("")
    for fname, src in modules.items():
        (mdir / fname).write_text(textwrap.dedent(src))
    return str(root)


# Module-level ``raise``: if the parser ever imported or exec'd a vendor module
# the whole test would blow up instead of quietly passing.
_POISON = 'raise SystemExit("vendor module was executed")\n'


def _fos_module(path, name, schema, extra_calls=""):
    return _POISON + textwrap.dedent(f"""
        import ansible_module_that_does_not_exist

        def firewall_x(data, fos):
            mkey = fos.get_mkey("{path}", "{name}", data, vdom=None)
            current = fos.get("{path}", "{name}", vdom=None, mkey=mkey)
            {extra_calls}
            return fos.set("{path}", "{name}", data=data, vdom=None)

        def remove(data, fos):
            return fos.delete("{path}", "{name}", mkey=data["name"], vdom=None)

        versioned_schema = {schema!r}
        """)


ADDRESS6_SCHEMA = {
    "type": "list",
    "elements": "dict",
    "v_range": [["v6.0.0", ""]],
    "children": {
        "name": {"v_range": [["v6.0.0", ""]], "type": "string", "required": True},
        "type": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "ipprefix"},
                        {"value": "geography", "v_range": [["v6.4.0", ""]]}],
        },
        "macaddr": {
            "type": "list",
            "elements": "dict",
            "v_range": [["v7.0.0", ""]],
            "children": {
                "macaddr": {"v_range": [["v7.0.0", ""]], "type": "string", "required": True},
                "nested": {"type": "dict", "v_range": [["v7.0.2", ""]],
                           "children": {"deep": {"v_range": [["v7.2.1", ""]], "type": "string"}}},
            },
        },
        "legacy": {"v_range": [["v6.0.0", "v6.2.0"], ["v6.4.4", "v7.0.12"]], "type": "integer"},
        "untagged": {"type": "string"},
    },
}

SYSLOGD2_SCHEMA = {
    "type": "dict",
    "v_range": [["v6.0.0", "v7.4.3"]],
    "children": {
        "status": {"v_range": [["v6.0.0", ""]], "type": "string",
                   "options": [{"value": "enable"}, {"value": "disable"}]},
        "brand_new": {"v_range": [["v8.0.0", ""]], "type": "integer"},
    },
}

SIMPLE_SCHEMA = {"type": "dict", "v_range": [["v7.0.0", ""]],
                 "children": {"status": {"v_range": [["v7.0.0", ""]], "type": "string"}}}


@pytest.fixture
def fortios(tmp_path):
    modules = {
        "fortios_firewall_address6.py": _fos_module("firewall", "address6", ADDRESS6_SCHEMA),
        "fortios_log_syslogd2_setting.py": _fos_module("log.syslogd2", "setting", SYSLOGD2_SCHEMA),
        # Looks like a monitor module by prefix, is a real cmdb table.
        "fortios_monitoring_npu_hpe.py": _fos_module("monitoring", "npu-hpe", SIMPLE_SCHEMA),
        # Carry a schema on purpose: they must be skipped by NAME, not by luck.
        "fortios_monitor.py": _fos_module("monitor", "x", SIMPLE_SCHEMA),
        "fortios_monitor_fact.py": _fos_module("monitor", "y", SIMPLE_SCHEMA),
        "fortios_log_fact.py": _fos_module("log", "fact", SIMPLE_SCHEMA),
        "fortios_json_generic.py": _fos_module("json", "generic", SIMPLE_SCHEMA),
        "fortios_export_config_playbook.py": _POISON + "def main():\n    pass\n",
        # Two different cmdb targets: refuse to guess.
        "fortios_system_ambiguous.py": _fos_module(
            "system", "one", SIMPLE_SCHEMA,
            extra_calls='fos.set("system", "two", data=data, vdom=None)'),
        "fortios_system_badver.py": _fos_module(
            "system", "badver", {"type": "dict", "v_range": [["v7.x", ""]],
                                 "children": {"a": {"type": "string", "v_range": [["v7.x", ""]]}}}),
    }
    return _collection(tmp_path / "fortios", "fortinet", "fortios", "2.6.0", modules)


def _faz_module(key, urls, obj, task_type="full crud", urls_var="urls_list", module_level_urls=False):
    spec = {"access_token": {"type": "str", "no_log": True},
            "state": {"type": "str", "required": True, "choices": ["present", "absent"]}}
    if obj is not None:
        spec[key] = obj
    urls_src = f"{urls_var} = {urls!r}\n"
    return _POISON + (urls_src if module_level_urls else "") + textwrap.dedent(f"""
        def main():
            {"" if module_level_urls else urls_src}
            module_primary_key = 'name'
            module_arg_spec = {spec!r}
            faz = FortiAnalyzerAnsible(urls_list, module_primary_key, [], None, None,
                                       metadata=module_arg_spec, task_type={task_type!r})
            faz.process()
        """)


ADMIN_USER = {
    "type": "dict",
    "v_range": [["6.2.1", ""]],
    "options": {
        "userid": {"type": "str"},
        "profileid": {"v_range": [["6.4.1", "7.4.0"]], "type": "str",
                      "choices": ["Super_User", "Restricted_User"]},
        "dashboard": {"type": "list", "elements": "dict",
                      "options": {"moduleid": {"type": "int", "v_range": [["7.6.4", ""]]},
                                  "name": {"type": "str"}}},
        "password": {"type": "raw", "no_log": True, "required": True},
    },
}


@pytest.fixture
def fortianalyzer(tmp_path):
    simple = {"type": "dict", "v_range": [["7.0.0", ""]], "options": {"name": {"type": "str"}}}
    modules = {
        "faz_cli_system_admin_user.py": _faz_module(
            "cli_system_admin_user", ["/cli/global/system/admin/user", "/cli/global/other"], ADMIN_USER),
        "faz_report_config_chart.py": _faz_module(
            "report_config_chart", ["/report/adom/{adom}/config/chart"],
            {"type": "dict", "v_range": [["6.2.1", "7.2.10"]],
             "options": {"name": {"type": "str", "v_range": [["7.2.2", ""]]}}},
            task_type="partial crud"),
        # Older generator layout: module-level ``jrpc_urls``.
        "faz_dvmdb_folder.py": _faz_module(
            "dvmdb_folder", ["/dvmdb/adom/{adom}/folder"], simple,
            urls_var="jrpc_urls", module_level_urls=True),
        "faz_sys_reboot.py": _faz_module("sys_reboot", ["/sys/reboot"], simple, task_type="exec"),
        "faz_dvmdb_adom_objectmember.py": _faz_module(
            "dvmdb_adom_objectmember", ["/dvmdb/adom/{adom}/object member"], simple,
            task_type="object member"),
        "faz_report_run.py": _faz_module("report_run", ["/report/adom/{adom}/run"], simple,
                                         task_type="jsonrpc2_add"),
        # Named skips, even though they claim to be config objects.
        "faz_cli_exec_fgfm_reclaimdevtunnel.py": _faz_module(
            "cli_exec_fgfm_reclaimdevtunnel", ["/cli/global/exec/x"], simple),
        "faz_fact.py": _faz_module("fact", ["/x"], simple),
        "faz_generic.py": _faz_module("generic", ["/x"], simple),
        "faz_rename.py": _faz_module("rename", ["/x"], simple),
        "faz_cli_system_nospan.py": _faz_module(
            "cli_system_nospan", ["/cli/global/system/nospan"], {"type": "dict", "options": {}}),
        "faz_cli_system_nonliteral.py": _POISON + textwrap.dedent("""
            def main():
                urls_list = ['/cli/global/system/nonliteral']
                module_arg_spec = {'cli_system_nonliteral': {'type': 'dict', 'choices': list(X)}}
                FortiAnalyzerAnsible(task_type='full crud')
            """),
    }
    return _collection(tmp_path / "fortianalyzer", "fortinet", "fortianalyzer", "1.10.0",
                       modules, release_date="2025-10-22")


def _one(path):
    docs = av.evidence_from_ansible_collection(path)
    assert len(docs) == 1
    return docs[0]


# ---------------------------------------------------------------------------
# FortiOS
# ---------------------------------------------------------------------------

def test_fortios_envelope(fortios):
    doc = _one(fortios)
    assert doc["product"] == "fortigate"
    assert doc["source"] == "vendor_doc"
    assert doc["origin_ref"] == "ansible:fortinet.fortios:2.6.0"
    assert doc["device"] is None
    assert doc["healthy"] is True and doc["skip_reason"] == ""
    # The release date of THIS version, not the older entry above it.
    assert doc["captured_at"] == "2026-08-17T00:00:00"
    assert doc["scope"]["kind"] == "spans"
    json.dumps(doc)  # plain JSON, ready for the canonical hash


def test_fortios_vendor_code_is_never_imported(fortios):
    _one(fortios)
    assert not any("fortios_firewall_address6" in m for m in sys.modules)


def test_fortios_endpoint_selection(fortios):
    doc = _one(fortios)
    assert set(doc["endpoints"]) == {"firewall_address6", "log_syslogd2_setting",
                                     "monitoring_npu_hpe"}
    skipped = {s["module"]: s["reason"] for s in doc["summary"]["skipped"]}
    assert set(skipped) == {"fortios_monitor", "fortios_monitor_fact", "fortios_log_fact",
                            "fortios_json_generic", "fortios_export_config_playbook",
                            "fortios_system_ambiguous", "fortios_system_badver"}
    assert "monitor" in skipped["fortios_monitor"]
    assert "fact" in skipped["fortios_log_fact"]
    assert "versioned_schema" in skipped["fortios_export_config_playbook"]
    assert "cmdb path" in skipped["fortios_system_ambiguous"]
    assert "version" in skipped["fortios_system_badver"]
    s = doc["summary"]
    assert s["modules_total"] == 10  # __init__.py is not a module
    assert s["endpoints"] == 3 and s["skipped_count"] == 7
    assert sum(s["skipped_by_reason"].values()) == 7


def test_fortios_urn_and_section(fortios):
    eps = _one(fortios)["endpoints"]
    assert eps["firewall_address6"]["urn"] == "/api/v2/cmdb/firewall/address6"
    assert eps["firewall_address6"]["section"] == "firewall"
    assert eps["log_syslogd2_setting"]["urn"] == "/api/v2/cmdb/log.syslogd2/setting"
    assert eps["log_syslogd2_setting"]["section"] == "log"
    assert eps["monitoring_npu_hpe"]["urn"] == "/api/v2/cmdb/monitoring/npu-hpe"
    assert all("verdict" not in e for e in eps.values())  # spans evidence has no verdict


def test_fortios_fields_are_top_level_only(fortios):
    fields = _one(fortios)["endpoints"]["firewall_address6"]["fields"]
    assert set(fields) == {"name", "type", "macaddr", "legacy", "untagged"}
    assert fields["macaddr"]["children"] == ["macaddr", "nested"]
    assert fields["macaddr"]["type"] == "list"
    assert fields["type"]["options"] == ["ipprefix", "geography"]
    assert fields["name"]["required"] is True
    assert "required" not in fields["type"]
    assert "children" not in fields["name"] and "options" not in fields["name"]


def test_fortios_spans(fortios):
    eps = _one(fortios)["endpoints"]
    a6 = eps["firewall_address6"]
    assert a6["spans"] == [["6.0.0", ""]]
    assert a6["fields"]["macaddr"]["spans"] == [["7.0.0", ""]]
    assert a6["fields"]["legacy"]["spans"] == [["6.0.0", "6.2.0"], ["6.4.4", "7.0.12"]]
    # No v_range on the field: it inherits the endpoint's range.
    assert a6["fields"]["untagged"]["spans"] == [["6.0.0", ""]]
    sl = eps["log_syslogd2_setting"]
    assert sl["spans"] == [["6.0.0", "7.4.3"]]
    assert sl["fields"]["brand_new"]["spans"] == [["8.0.0", ""]]


def test_fortios_scope_versions(fortios):
    doc = _one(fortios)
    versions = doc["scope"]["versions"]
    # Numeric order (7.0.2 < 7.0.12), no "v", no open-end marker, and the
    # nested-only (7.0.2, 7.2.1) and option-only (6.4.0) builds included.
    assert versions == ["6.0.0", "6.2.0", "6.4.0", "6.4.4", "7.0.0", "7.0.2",
                        "7.0.12", "7.2.1", "7.4.3", "8.0.0"]
    assert doc["summary"]["max_version"] == "8.0.0"
    assert doc["summary"]["min_version"] == "6.0.0"
    # A skipped module's versions do not leak into the scope.
    assert "7.x" not in versions


def test_captured_at_falls_back_to_now(tmp_path):
    path = _collection(tmp_path / "c", "fortinet", "fortios", "2.6.0",
                       {"fortios_monitoring_npu_hpe.py": _fos_module("monitoring", "npu-hpe", SIMPLE_SCHEMA)},
                       release_date=None)
    stamp = datetime.fromisoformat(_one(path)["captured_at"])
    assert abs((datetime.utcnow() - stamp).total_seconds()) < 120


def test_collections_without_version_data_yield_nothing(tmp_path):
    for name in ("fortiweb", "fortiadc"):
        path = _collection(tmp_path / name, "fortinet", name, "1.0.0", {})
        assert av.evidence_from_ansible_collection(path) == []


def test_not_a_collection_is_an_error(tmp_path):
    with pytest.raises(ValueError):
        av.evidence_from_ansible_collection(str(tmp_path))


def test_normalize_version():
    assert av.normalize_version("v7.4.3") == "7.4.3"
    assert av.normalize_version("7.4.3") == "7.4.3"
    assert av.normalize_version("") == ""
    with pytest.raises(ValueError):
        av.normalize_version("v7.x")
    assert sorted(["7.0.12", "7.0.2", "6.4.15"], key=av.version_key) == ["6.4.15", "7.0.2", "7.0.12"]


# ---------------------------------------------------------------------------
# FortiAnalyzer
# ---------------------------------------------------------------------------

def test_faz_envelope_and_selection(fortianalyzer):
    doc = _one(fortianalyzer)
    assert doc["product"] == "fortianalyzer"
    assert doc["origin_ref"] == "ansible:fortinet.fortianalyzer:1.10.0"
    assert doc["captured_at"] == "2025-10-22T00:00:00"
    assert doc["device"] is None and doc["scope"]["kind"] == "spans"
    assert set(doc["endpoints"]) == {"cli_system_admin_user", "report_config_chart", "dvmdb_folder"}
    skipped = {s["module"]: s["reason"] for s in doc["summary"]["skipped"]}
    assert set(skipped) == {"faz_sys_reboot", "faz_dvmdb_adom_objectmember", "faz_report_run",
                            "faz_cli_exec_fgfm_reclaimdevtunnel", "faz_fact", "faz_generic",
                            "faz_rename", "faz_cli_system_nospan", "faz_cli_system_nonliteral"}
    assert "exec" in skipped["faz_sys_reboot"]
    assert "object member" in skipped["faz_dvmdb_adom_objectmember"]
    assert "v_range" in skipped["faz_cli_system_nospan"]


def test_faz_urn_and_section(fortianalyzer):
    eps = _one(fortianalyzer)["endpoints"]
    assert eps["cli_system_admin_user"]["urn"] == "/cli/global/system/admin/user"
    assert eps["cli_system_admin_user"]["section"] == "cli"
    assert eps["report_config_chart"]["urn"] == "/report/adom/{adom}/config/chart"
    assert eps["report_config_chart"]["section"] == "report"
    assert eps["dvmdb_folder"]["urn"] == "/dvmdb/adom/{adom}/folder"


def test_faz_fields_and_spans(fortianalyzer):
    eps = _one(fortianalyzer)["endpoints"]
    user = eps["cli_system_admin_user"]
    assert user["spans"] == [["6.2.1", ""]]
    f = user["fields"]
    assert set(f) == {"userid", "profileid", "dashboard", "password"}
    assert f["profileid"]["options"] == ["Super_User", "Restricted_User"]
    assert f["profileid"]["spans"] == [["6.4.1", "7.4.0"]]
    assert f["userid"]["spans"] == [["6.2.1", ""]]  # inherited
    assert f["dashboard"]["children"] == ["moduleid", "name"]
    assert "options" not in f["dashboard"]
    assert f["password"]["required"] is True and f["password"]["type"] == "raw"
    chart = eps["report_config_chart"]
    assert chart["spans"] == [["6.2.1", "7.2.10"]]
    assert chart["fields"]["name"]["spans"] == [["7.2.2", ""]]


def test_faz_scope_versions(fortianalyzer):
    doc = _one(fortianalyzer)
    assert doc["scope"]["versions"] == ["6.2.1", "6.4.1", "7.0.0", "7.2.2", "7.2.10",
                                        "7.4.0", "7.6.4"]
    assert doc["summary"]["max_version"] == "7.6.4"


# ---------------------------------------------------------------------------
# the real collections, when this node has them
# ---------------------------------------------------------------------------

def test_real_collections():
    fos_path = os.path.join(REAL_ROOT, "fortios")
    faz_path = os.path.join(REAL_ROOT, "fortianalyzer")
    if not (os.path.isdir(fos_path) and os.path.isdir(faz_path)):
        pytest.skip("vendor collections not extracted on this node")
    fos = _one(fos_path)
    faz = _one(faz_path)
    assert fos["summary"]["endpoints"] > 600
    assert faz["summary"]["endpoints"] > 150
    assert fos["summary"]["max_version"] == "8.0.0"
    assert fos["endpoints"]["firewall_policy"]["urn"] == "/api/v2/cmdb/firewall/policy"
    assert fos["endpoints"]["log_syslogd2_setting"]["urn"] == "/api/v2/cmdb/log.syslogd2/setting"
    assert (fos["endpoints"]["wireless_controller_hotspot20_anqp_venue_name"]["urn"]
            == "/api/v2/cmdb/wireless-controller.hotspot20/anqp-venue-name")
    assert fos["endpoints"]["system_global"]["urn"] == "/api/v2/cmdb/system/global"
    assert not any(n.startswith("monitor_") or n.endswith("_fact") for n in fos["endpoints"])
    for doc in (fos, faz):
        versions = doc["scope"]["versions"]
        assert versions == sorted(versions, key=av.version_key)
        known = set(versions)
        for ep in doc["endpoints"].values():
            spans = [ep["spans"]] + [f["spans"] for f in ep["fields"].values()]
            for group in spans:
                assert group
                for lo, hi in group:
                    av.version_key(lo)  # parses
                    assert lo in known and (hi == "" or hi in known)
                    if hi:
                        assert av.version_key(lo) <= av.version_key(hi)
        # Small enough to store as one raw_gz blob.
        assert len(gzip.compress(json.dumps(doc).encode())) < 2_000_000

from app.services import section_taxonomy as T


def test_section_for_builtin_kinds():
    assert T.section_for_kind("web-protection-profile") == "web_protection"
    assert T.section_for_kind("server-policy") == "server_policy"
    assert T.section_for_kind("system-profile") == "system"
    assert T.section_for_kind("structure") == "structure"


def test_section_for_config_kinds():
    assert T.section_for_kind("config:network") == "network"
    assert T.section_for_kind("config:server_objects") == "server_objects"


def test_section_for_future_wpp_subsection():
    assert T.section_for_kind("config:wpp.signatures") == "web_protection"


def test_section_label_known_and_config():
    assert T.section_label("web_protection") == "Web Protection"
    assert T.section_label("network") == "Network"
    assert T.section_label("structure") == "Structure"


def test_known_sections_ordered_and_complete():
    keys = [s["key"] for s in T.known_sections()]
    assert keys[0] == "web_protection"      # WPP first
    assert "server_policy" in keys
    assert "system" in keys and "network" in keys

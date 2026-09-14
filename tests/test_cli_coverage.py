"""CLI ↔ API coverage: the diff between what a device's CLI serves and what the
catalog knows.

The material this reads has been on disk since 2026-07-04 — ``show
full-configuration`` dumps in the config vault — and nothing read it. So the
risk here is not that the feature breaks loudly; it is that it produces a
plausible, precise, WRONG number. Every guard below fixes one of the ways it
could do that:

* a config table with nothing in it prints NO BLOCK, so "in the catalog, absent
  from this dump" is not absence — it is an unconfigured feature, and 94 of them
  exist in the live FortiWeb dump. Folding that bucket into "absent" would put a
  fabricated headline on the page;
* a dump belongs to ONE device on ONE date, and every dump in the vault today
  belongs to an appliance that has since been deleted — so a dump whose product
  cannot be ESTABLISHED is never diffed, because guessing would compare a
  FortiADC config against the FortiWeb catalog and invent ~300 findings;
* CLI and REST spell child tables differently (two real cases in the live dump),
  and that is neither a match nor a gap;
* the dump carries ``ENC`` credentials and PEM private keys, and this page
  renders block TEXT.

Targeted suite: nothing here needs the network.
"""
from __future__ import annotations

import io
import pathlib
import re

import pytest

from tests.conftest import admin_user_id, login, make_user, profile_id

REPO = pathlib.Path(__file__).resolve().parents[1]
PARTIAL = REPO / "app" / "templates" / "partials" / "_cli_coverage.html"
VIEW = REPO / "app" / "views" / "_clicoverage.py"
SERVICE = REPO / "app" / "services" / "cli_coverage.py"

HUB_TEMPLATES = (
    "app/templates/api_explorer/index.html",
    "app/templates/adc_api/index.html",
    "app/templates/faz_api/index.html",
    "app/templates/fac_api/index.html",
)


# --------------------------------------------------------------------------
# helpers — assertions about SOURCE must not be satisfied by prose
# --------------------------------------------------------------------------

def _py_code_only(path: pathlib.Path) -> str:
    """Python source with comments and docstrings removed.

    Every guard in this repo that asserts a string is ABSENT from a module has
    to do this, because the comment that EXPLAINS the rule quotes the strings
    the rule forbids. It has now cost a false failure ten separate times.
    """
    import ast
    import io as _io
    import tokenize

    src = path.read_text(encoding="utf-8")
    out = []
    for tok in tokenize.generate_tokens(_io.StringIO(src).readline):
        if tok.type == tokenize.COMMENT:
            continue
        out.append(tok)
    stripped = tokenize.untokenize(out)
    # docstrings survive untokenize — drop them via the AST
    tree = ast.parse(stripped)
    doc_lines: set = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef,
                            ast.ClassDef)):
            body = getattr(node, "body", None) or []
            if body and isinstance(body[0], ast.Expr) and isinstance(
                    getattr(body[0], "value", None), ast.Constant) and isinstance(
                    body[0].value.value, str):
                doc_lines.update(range(body[0].lineno, (body[0].end_lineno or
                                                        body[0].lineno) + 1))
    return "\n".join(ln for i, ln in enumerate(stripped.splitlines(), 1)
                     if i not in doc_lines)


def _section_js() -> str:
    """ONLY the <script> this partial owns, with JS comments stripped.

    Slicing matters twice over. The hub pages already carry their own handlers,
    so a substring found anywhere in the rendered page can be satisfied by code
    that has nothing to do with this section — the mutation that deletes this
    section's handler then SURVIVES. And the comments in this block name
    ``innerHTML`` in order to forbid it.
    """
    src = PARTIAL.read_text(encoding="utf-8")
    m = re.search(r"<script nonce=[^>]*>(.*?)</script>", src, re.S)
    assert m, "the partial no longer contains its own <script> block"
    js = m.group(1)
    js = re.sub(r"/\*.*?\*/", "", js, flags=re.S)
    js = re.sub(r"(?m)^\s*//.*$", "", js)
    return js


def _jinja_text_only() -> str:
    """The partial with Jinja comments ({# … #}) removed."""
    return re.sub(r"\{#.*?#\}", "", PARTIAL.read_text(encoding="utf-8"), flags=re.S)


FW_DUMP = """config global
  config system settings
    set opmode reverse-proxy
  end
  config system global
    set hostname fw-test
  end
  config system admin
    edit "admin"
      set password ENC AbCdEf0123456789==
      set forbid-password-reuse disable
      set history-password1 ENC ZZZZ
    next
  end
  config system admin-certificate local
    edit "wc"
      set certificate "-----BEGIN CERTIFICATE-----
MIIBogIBAAJBAL
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
end
-----END CERTIFICATE-----
"
      set private-key "-----BEGIN ENCRYPTED PRIVATE KEY-----
end
-----END ENCRYPTED PRIVATE KEY-----
"
      unset comment
    next
  end
  config system automation-webhook
  end
  config system fortiguard-attack-context
    set fortiguard-cert ENC NOTACREDENTIALSHAPEDNAME==
  end
  config system automation-stitch
    edit "S1"
      set status disable
      config  action_member
        edit 1
          set action-name Default_script
        next
      end
    next
  end
end
config vdom
  config server-policy policy
    edit "p1"
      set comment "hello"
    next
  end
end
"""


def _seed_dump(app, *, firmware="FortiWeb-KVM 7.6.8,build1128(GA.M),260602",
               name="fwseed", text=FW_DUMP, encrypted=False):
    """Put a dump in the vault the way a real capture does (file + row)."""
    from app.extensions import db
    from app.services import backup

    with app.app_context():
        row = backup.store_bytes(appliance_id=901, appliance_name=name,
                                 data=text.encode(), filename=f"{name}_cli.conf",
                                 source="device", created_by="tester",
                                 firmware=firmware)
        if encrypted:
            row.encrypted = True
            db.session.commit()
        return row.id


def _make_appliance(app, name="fw-cc", kind="fortiweb"):
    from app.models import Appliance, db
    with app.app_context():
        a = Appliance(name=name, kind=kind, host="192.0.2.99", port=443,
                      username="admin", verify_ssl=False)
        a.password = "secret"
        db.session.add(a)
        db.session.commit()
        return a.id


# ==========================================================================
# the parser
# ==========================================================================

def test_scope_containers_are_stripped_only_at_the_top():
    """``config global`` is a scope; ``config system global`` is a real table.

    Strip by matching the OUTERMOST block exactly, on the raw words, before any
    hyphen splitting. A rule that dropped any token named ``global`` would
    silently merge ``/api/v2.0/cmdb/system/global`` into nothing.
    """
    from app.services import cli_coverage as cc

    blocks = cc.parse_config_dump(FW_DUMP)
    assert ("system", "settings") in blocks
    assert ("system", "global") in blocks, "a nested real table lost its token"
    assert ("global",) not in blocks and ("vdom",) not in blocks
    # the vdom-scoped table is keyed as if the container were not there
    assert ("server", "policy", "policy") in blocks


def test_a_line_reading_end_inside_a_quoted_value_cannot_close_a_block():
    """The seeded PEM bodies contain a bare ``end`` on purpose.

    FortiWeb puts certificates and keys in multi-line quoted values, so a
    continuation line is arbitrary text. Treating one as syntax pops a block
    that never closed and reparents every block after it — a coverage report
    that is precise, plausible and wrong.
    """
    from app.services import cli_coverage as cc

    assert "\nend\n" in FW_DUMP, "the fixture no longer exercises this"
    blocks = cc.parse_config_dump(FW_DUMP)
    # automation-stitch comes AFTER the certificate block in the fixture; if a
    # PEM 'end' had popped the scope, it would be keyed with a 'global' prefix
    # or lost entirely.
    assert ("system", "automation", "stitch") in blocks
    assert ("system", "automation", "stitch", "action", "member") in blocks

    # Key identity CANNOT see this corruption: the fake `end` pops the `config
    # global` container, which is stripped from the key anyway, so every later
    # block lands on the same tuple either way. What changes is the NESTING and
    # the EXTENT of the block that held the PEM.
    assert blocks[("system", "automation", "stitch")].depth == 2
    assert blocks[("system", "automation", "stitch", "action", "member")].depth == 3

    cert = blocks[("system", "admin", "certificate", "local")]
    assert {"certificate", "private-key", "comment"} <= cert.sets, cert.sets
    body = cc.extract_block(FW_DUMP, "system admin-certificate local")
    assert "unset comment" in body, "the block was cut short at a PEM's bare 'end'"
    assert body.rstrip().endswith("end")
    assert cc.parse_report(FW_DUMP)["balanced"] is True


def test_the_same_table_in_two_scopes_is_counted_once():
    from app.services import cli_coverage as cc

    doubled = FW_DUMP + "config vdom\n  config server-policy policy\n" \
                        "    edit \"p2\"\n      set comment \"x\"\n    next\n  end\nend\n"
    single = cc.parse_config_dump(FW_DUMP)[("server", "policy", "policy")]
    blocks = cc.parse_config_dump(doubled)
    blk = blocks[("server", "policy", "policy")]
    # Counting dict keys proves nothing — a dict cannot hold a duplicate. The
    # second occurrence has to ACCUMULATE into the first record, keeping the
    # first sighting's line number, or the totals start depending on how many
    # VDOMs the box happens to have.
    assert blk.instances == 2, blk.instances
    assert blk.line == single.line
    assert single.instances == 1


def test_parse_report_flags_a_truncated_dump():
    """A capture cut short by a read timeout looks exactly like a small config.

    ``ssh_config_backup`` only refuses the ones that fail its header/footer
    check, so the page needs its own structural verdict to put beside the counts.
    """
    from app.services import cli_coverage as cc

    truncated = "config global\n  config system settings\n    set opmode x\n"
    rep = cc.parse_report(truncated)
    assert rep["balanced"] is False and rep["unclosed"] == 2
    assert cc.parse_report(FW_DUMP)["balanced"] is True


# ==========================================================================
# the diff — every bucket is separated by WHY
# ==========================================================================

def test_a_catalog_endpoint_with_no_block_is_no_block_never_absent(app):
    """The bucket name and the page wording both have to say it.

    An empty config table prints nothing, so this bucket cannot be read as
    absence. 94 rows land in it on the live FortiWeb dump; presenting them as
    removals would be the page's biggest number and a fabrication.
    """
    from app.services import cli_coverage as cc

    with app.app_context():
        diff = cc.compare("fortiweb", FW_DUMP, line="7.6")

    assert cc.BUCKET_NO_BLOCK == "no_block"
    assert diff["counts"]["no_block"] > 0, "the fixture must exercise this bucket"
    assert "absent" not in diff, "no bucket on this report may be called absent"
    assert not any("absent" in k for k in diff["counts"])

    page = _jinja_text_only()
    assert "no block in this dump" in page
    assert "NOT evidence the firmware lacks them" in page


def test_monitor_endpoints_are_excluded_rather_than_reported_as_gaps(app):
    """42 FortiWeb catalog entries are runtime readouts with no config table.

    They cannot match by construction, so counting them would put 42 permanent
    non-findings in the headline — which is how an operator learns to ignore a
    page.
    """
    from app.services import cli_coverage as cc

    with app.app_context():
        diff = cc.compare("fortiweb", FW_DUMP, line="7.6")

    monitor_names = {e["name"] for e in diff[cc.BUCKET_MONITOR]}
    assert monitor_names, "the catalog must still contain non-cmdb endpoints"
    reported = {r["catalog"] for r in diff[cc.BUCKET_NO_BLOCK]}
    assert not (monitor_names & reported)
    assert diff["counts"]["catalog_monitor"] == len(monitor_names)


def test_a_child_table_the_catalog_spells_differently_is_neither_bucket(app):
    """Same object, different path: not a match, not a gap.

    Two real cases in the live FortiWeb dump (``waf graphql-validation policy
    graphql-rule-list`` vs ``…/graphql-validation.policy/rule-list``). SATOM
    cannot tell from a config file which spelling the device serves, so it says
    so instead of picking one.
    """
    from app.services import cli_coverage as cc

    dump = ("config global\n"
            "  config waf xml-exempted-urls\n"
            "    config exempted-url-list\n"
            "      set x 1\n"
            "    end\n"
            "  end\n"
            "end\n")
    with app.app_context():
        diff = cc.compare("fortiweb", dump, line="7.6")

    near_paths = {r["path"] for r in diff[cc.BUCKET_NEAR]}
    assert near_paths, "the fixture no longer produces a near match"
    cli_only_paths = {r["path"] for r in diff[cc.BUCKET_CLI_ONLY]}
    both_paths = {r["path"] for r in diff[cc.BUCKET_BOTH]}
    assert not (near_paths & cli_only_paths)
    assert not (near_paths & both_paths)
    # and a near match must carry the catalog URN it is being compared against,
    # or the operator has nothing to execute in the console
    assert all(r.get("urn") for r in diff[cc.BUCKET_NEAR])


def test_a_near_match_is_not_also_counted_as_a_missing_block(app):
    """It would otherwise be reported twice, in two buckets that disagree."""
    from app.services import cli_coverage as cc

    dump = ("config global\n"
            "  config waf xml-exempted-urls\n"
            "    config exempted-url-list\n"
            "      set x 1\n"
            "    end\n"
            "  end\n"
            "end\n")
    with app.app_context():
        diff = cc.compare("fortiweb", dump, line="7.6")
    near_names = {r["catalog"] for r in diff[cc.BUCKET_NEAR]}
    no_block_names = {r["catalog"] for r in diff[cc.BUCKET_NO_BLOCK]}
    assert near_names and not (near_names & no_block_names)


def test_cli_only_separates_configured_from_empty(app):
    """A table nobody filled in is a smaller catalog gap than one with rows."""
    from app.services import cli_coverage as cc

    with app.app_context():
        diff = cc.compare("fortiweb", FW_DUMP, line="7.6")
    stitch = [r for r in diff[cc.BUCKET_CLI_ONLY]
              if r["path"] == "system automation-stitch action_member"]
    assert stitch, "the fixture's CLI-only block disappeared from the report"
    assert stitch[0]["configured"] is True

    empty = [r for r in diff[cc.BUCKET_CLI_ONLY]
             if r["path"] == "system automation-webhook"]
    assert empty, "the fixture must also carry an EMPTY cli-only block"
    assert empty[0]["configured"] is False
    # `<=` is satisfied by counting everything. The split only means something
    # if the count is STRICTLY smaller when an empty table is present.
    assert diff["counts"]["cli_only_configured"] < diff["counts"]["cli_only"]


@pytest.mark.parametrize("product", ["fortianalyzer", "fortiauthenticator"])
def test_an_unsupported_product_states_a_reason_and_diffs_nothing(app, product):
    """Stated, not rendered as an empty page.

    FortiAnalyzer's API reaches MORE than its CLI (JSON-RPC), and
    FortiAuthenticator has no config CLI at all — a diff for either would read
    backwards. Shipping a parser for them would be shipping a measurement
    nobody can check.
    """
    from app.services import cli_coverage as cc

    assert product not in cc.SUPPORTED_PRODUCTS
    with app.app_context():
        diff = cc.compare(product, FW_DUMP)
    assert diff["supported"] is False
    assert len(diff["reason"]) > 60, "the reason has to explain itself"
    assert not diff[cc.BUCKET_CLI_ONLY] and not diff[cc.BUCKET_BOTH]
    assert diff["counts"] == {}


# ==========================================================================
# evidence — a dump is one device, one date, one product
# ==========================================================================

def test_a_dump_whose_product_cannot_be_established_is_never_diffed(app):
    """Guessing would diff a FortiADC config against the FortiWeb catalog.

    Every dump in the live vault belongs to a DELETED appliance, so the row's
    recorded firmware string is the only surviving statement of what kind of box
    it came from. No string, no diff.
    """
    from app.services import cli_coverage as cc

    bid = _seed_dump(app, firmware=None, name="mystery")
    with app.app_context():
        rec = next(r for r in cc.evidence_index() if r["backup_id"] == bid)
        assert rec["product"] == ""
        assert rec["usable"] is False and "guessing" in rec["reason"]
        text, rec2 = cc.read_dump(bid)
        assert text == "", "an unlabelled dump must not be readable"


def test_an_encrypted_backup_is_refused_with_its_reason(app):
    from app.services import cli_coverage as cc

    bid = _seed_dump(app, name="locked", encrypted=True)
    with app.app_context():
        rec = next(r for r in cc.evidence_index() if r["backup_id"] == bid)
        assert rec["usable"] is False and "encrypt" in rec["reason"]
        assert cc.read_dump(bid)[0] == ""


def test_product_of_firmware_reads_the_capture_not_the_filename(app):
    from app.services import cli_coverage as cc

    assert cc.product_of_firmware("FortiWeb-KVM 7.6.8,build1128") == "fortiweb"
    assert cc.product_of_firmware("FortiADC-KVM v8.0.3 build0093") == "fortiadc"
    assert cc.product_of_firmware("") == ""
    assert cc.product_of_firmware(None) == ""


def test_report_picks_the_newest_usable_dump_and_says_which(app):
    from app.services import cli_coverage as cc

    _seed_dump(app, name="old")
    newest = _seed_dump(app, name="new")
    with app.app_context():
        rep = cc.report("fortiweb")
    assert rep["chosen"]["backup_id"] == newest
    assert rep["chosen"]["appliance"] == "new"
    assert rep["diff"]["no_evidence"] is False


def test_a_chosen_dump_that_turns_out_unreadable_is_still_no_evidence(app):
    """The other half of the flag, and the only half a mutation could reach.

    ``evidence_index`` calls a row usable from its metadata and the file's
    existence; ``read_dump`` is what actually opens it. A file that is on disk
    but is not a CLI dump therefore passes the first check and fails the second
    — and the report must come back as "no evidence", not as a diff of an empty
    string against the catalog, which would report the whole catalog missing.
    """
    from app.models_backup import ConfigBackup
    from app.services import cli_coverage as cc

    # The row's ``encrypted`` flag is computed once, AT CAPTURE
    # (``store_bytes`` → ``is_encrypted``). Overwriting the file afterwards is
    # therefore the realistic shape of this: the metadata still says plaintext
    # FortiWeb config and the bytes no longer are.
    bid = _seed_dump(app, name="notadump")
    with app.app_context():
        path = ConfigBackup.query.get(bid).stored_path
    with io.open(path, "w", encoding="utf-8") as fh:
        fh.write("this is not a configuration\n")

    with app.app_context():
        rec = next(r for r in cc.evidence_index() if r["backup_id"] == bid)
        assert rec["usable"] is True, \
            "the index reads metadata, not content — that is why read_dump checks"
        rep = cc.report("fortiweb", bid)
    assert rep["diff"]["no_evidence"] is True
    assert rep["diff"]["counts"]["cli_blocks"] == 0
    assert "not a CLI configuration dump" in rep["chosen"]["reason"]


def test_with_no_evidence_the_report_says_so_instead_of_showing_zero(app):
    """0 CLI-only findings and "nothing was ever captured" look identical on a
    counter and mean opposite things."""
    from app.services import cli_coverage as cc

    with app.app_context():
        rep = cc.report("fortiweb")
    assert rep["chosen"] is None and rep["diff"]["no_evidence"] is True
    page = _jinja_text_only()
    assert "that is a gap in evidence, not a clean result" in page


# ==========================================================================
# fields — delegated, never recomputed
# ==========================================================================

def test_field_gap_delegates_to_api_matrix(app, monkeypatch):
    """One author for "is this field known on this line?".

    ``api_matrix.preflight`` already carries the rule that comparing sweep field
    sets against harvested schema fields reports 56 removals which are nothing
    but a noise filter. A second implementation here would be a second author
    of that answer, and it would get it wrong the same way the first one did.
    """
    from app.services import api_matrix, cli_coverage as cc

    seen = {}

    def _fake(product, line, key, keys, matrix=None):
        seen.update(product=product, line=line, key=key, keys=list(keys))
        return {"status": "ok", "unknown": [], "known": list(keys)}

    monkeypatch.setattr(api_matrix, "preflight", _fake)
    with app.app_context():
        out = cc.field_gap("fortiweb", "7.6", "admin", ["hostname"])
    assert seen == {"product": "fortiweb", "line": "7.6", "key": "admin",
                    "keys": ["hostname"]}
    assert out["status"] == "ok"


def test_without_a_firmware_line_the_field_answer_is_unmeasured(app):
    """Not "ok", and not a guess against whatever line happens to have data."""
    from app.services import api_matrix, cli_coverage as cc

    out = cc.field_gap("fortiweb", "", "admin", ["hostname"])
    assert out["status"] == api_matrix.STATUS_UNMEASURED
    assert out["unknown"] == []
    # The STATUS alone cannot see this: preflight also answers `unmeasured` for
    # an unknown line, so dropping the local check changes nothing an operator
    # can act on — except the REASON, which is the whole difference between
    # "we have not measured that firmware" and "this dump never said which
    # firmware it came from". Assert the sentence, not just the verdict.
    assert "does not record which firmware line" in out["reason"]


# ==========================================================================
# the dump is a device configuration and it carries credentials
# ==========================================================================

def test_enc_values_are_redacted_and_field_names_are_kept():
    """The names are the point of the page; the values must not reach a browser."""
    from app.services import cli_coverage as cc

    out = cc.scrub_block(FW_DUMP)
    assert "AbCdEf0123456789==" not in out
    assert "ZZZZ" not in out
    assert "set password" in out, "redacting the NAME would hide the finding"
    assert cc.REDACTED in out

    # Every one of the 8 ENC-valued field names in the live fortiweb08 dump is
    # credential-SHAPED (`password`, `secret`, `client-secret`, `ftp-passwd`,
    # `smtp-password`), so the name rule alone would have covered all of them
    # and this guard would have proved nothing. The value-shaped rule is the
    # primary one precisely because it does not go stale when Fortinet adds a
    # field — so it is guarded with a name the fallback CANNOT match.
    assert "NOTACREDENTIALSHAPEDNAME" not in out
    assert "set fortiguard-cert ENC %s" % cc.REDACTED in out


def test_a_certificate_chain_is_redacted_as_one_value():
    """Several ``-----BEGIN`` blocks live inside ONE quoted value.

    Walking PEM markers instead of the quote emitted every block after the
    first as its own half-line of leaked structure, and left the closing quote
    behind on a line of its own. Measured against fortiweb08's real
    ``system admin-certificate local`` block.
    """
    from app.services import cli_coverage as cc

    out = cc.scrub_block(FW_DUMP)
    assert "BEGIN CERTIFICATE" not in out
    assert "BEGIN ENCRYPTED PRIVATE KEY" not in out
    assert "MIIBogIBAAJBAL" not in out
    assert not [ln for ln in out.splitlines() if ln.strip() == '"'], \
        "a stray closing quote survived the redaction"
    assert 'set certificate "%s"' % cc.REDACTED in out
    assert 'set private-key "%s"' % cc.REDACTED in out


def test_an_enum_valued_field_whose_name_looks_secret_is_kept():
    """``set forbid-password-reuse disable`` is configuration, not a credential.

    A name-only rule redacts it, ``force-password-change`` and
    ``key-max-length`` too — hiding real settings in the name of hiding nothing.
    """
    from app.services import cli_coverage as cc

    out = cc.scrub_block(FW_DUMP)
    assert "set forbid-password-reuse disable" in out
    kept = cc.scrub_block("    set key-max-length 1024\n")
    assert "1024" in kept


def test_a_multiline_value_that_is_not_a_secret_is_kept_verbatim():
    from app.services import cli_coverage as cc

    text = ('config waf x\n  set comment "line one\nline two"\nend\n')
    out = cc.scrub_block(text)
    assert "line one" in out and "line two" in out
    assert cc.REDACTED not in out


def test_extract_block_returns_scrubbed_text_by_default(app):
    from app.services import cli_coverage as cc

    body = cc.extract_block(FW_DUMP, "system admin-certificate local")
    assert body.startswith("  config system admin-certificate local")
    assert "BEGIN" not in body
    assert cc.extract_block(FW_DUMP, "no such table") == ""


# ==========================================================================
# the routes — the permission split is the design
# ==========================================================================

@pytest.fixture()
def operator_id(app):
    """A user who may see the API hub but has no BACKUP permission.

    Its profile is asserted below rather than assumed: without that, every 403
    guard here would be VACUOUS — passing because the user was stopped one door
    earlier.
    """
    return make_user(app, username="ccop", role="readonly",
                     profile_id=profile_id(app, "readonly"))


def test_premise_the_readonly_user_can_see_the_hub_but_not_backups(app, client,
                                                                   operator_id):
    from app.models import Permission, User

    with app.app_context():
        u = User.query.get(operator_id)
        assert not u.can(Permission.BACKUP), \
            "this fixture must NOT hold BACKUP or the 403 guards prove nothing"
    login(client, operator_id)
    r = client.get("/web/api-explorer/")
    assert r.status_code == 200, "the section's own page must still render"
    assert b'id="cliCoverage"' in r.data


def test_the_counts_render_without_backup_but_the_text_does_not(app, client,
                                                               operator_id):
    """Table NAMES are catalog metadata; block TEXT is device configuration.

    The vault is gated on BACKUP for exactly that reason (views/backups.py,
    every route), so a coverage section that served block text to anyone would
    be a way around that permission.
    """
    bid = _seed_dump(app)
    login(client, operator_id)
    page = client.get("/web/api-explorer/").get_data(as_text=True)
    assert "system automation-stitch" in page, "the finding itself stays visible"
    assert "Backup permission" in page

    r = client.get("/web/api-explorer/cli-coverage/block?dump=%d&path=system+admin" % bid)
    assert r.status_code in (302, 403), r.status_code
    assert b"config system admin" not in r.data


def test_block_text_needs_backup_and_then_works(app, client):
    bid = _seed_dump(app)
    login(client, admin_user_id(app))
    r = client.get("/web/api-explorer/cli-coverage/block?dump=%d"
                   "&path=system+automation-stitch" % bid)
    assert r.status_code == 200 and r.get_json()["ok"] is True
    assert "config system automation-stitch" in r.get_json()["text"]


def test_block_route_refuses_a_dump_from_another_product(app, client):
    """ADOM isolation: the FortiWeb hub may not render a FortiADC config.

    Enforced everywhere else in this app by ``product_scope``; a route that
    took a dump id from a query string would be the hole in it.
    """
    bid = _seed_dump(app, firmware="FortiADC-KVM v8.0.3 build0093", name="adcseed")
    login(client, admin_user_id(app))
    r = client.get("/web/api-explorer/cli-coverage/block?dump=%d&path=system+global"
                   % bid)
    assert r.status_code == 403
    assert "fortiadc evidence, not fortiweb" in r.get_json()["error"]


def test_block_route_cannot_be_pointed_at_a_block_that_does_not_exist(app, client):
    bid = _seed_dump(app)
    login(client, admin_user_id(app))
    r = client.get("/web/api-explorer/cli-coverage/block?dump=%d&path=../../etc/passwd"
                   % bid)
    assert r.status_code == 404
    assert "no such block" in r.get_json()["error"]


def test_the_live_read_is_validated_by_the_read_only_gate(app, client, monkeypatch):
    """``path`` reaches an SSH session, so the gate must re-validate it.

    ``show`` is already an allowed verb; ``set`` and ``execute`` are not, and
    the refusal happens before any connect (``run_command`` validates first).
    """
    from app.services import ssh_ops

    aid = _make_appliance(app)
    login(client, admin_user_id(app))
    called = []
    monkeypatch.setattr(ssh_ops, "run_command",
                        lambda a, cmd, timeout=None: called.append(cmd) or "ok")

    r = client.post("/web/api-explorer/cli-coverage/live",
                    data={"appliance_id": aid, "path": "system automation-stitch"})
    assert r.status_code == 200 and r.get_json()["ok"] is True
    assert called == ["show system automation-stitch"], called

    def _boom(a, cmd, timeout=None):
        return ssh_ops.assert_readonly(cmd)

    monkeypatch.setattr(ssh_ops, "run_command", _boom)
    r = client.post("/web/api-explorer/cli-coverage/live",
                    data={"appliance_id": aid,
                          "path": "system global\nset hostname pwned"})
    assert r.status_code == 400 and "refused" in r.get_json()["error"]


def test_the_live_read_output_is_scrubbed_too(app, client, monkeypatch):
    """The device answers with the same credentials the stored dump holds."""
    from app.services import cli_coverage as cc
    from app.services import ssh_ops

    aid = _make_appliance(app)
    login(client, admin_user_id(app))
    monkeypatch.setattr(ssh_ops, "run_command",
                        lambda a, cmd, timeout=None:
                        'config system admin\n  set password ENC LEAKME==\nend')
    r = client.post("/web/api-explorer/cli-coverage/live",
                    data={"appliance_id": aid, "path": "system admin"})
    body = r.get_json()["text"]
    assert "LEAKME" not in body and cc.REDACTED in body


def test_the_live_read_refuses_an_appliance_of_another_product(app, client,
                                                               monkeypatch):
    """TWO doors, and only one of them is reachable over HTTP.

    Measured, not assumed: the ``/web`` URL scope stamps ``product=fortiweb`` on
    the request regardless of what the session says, so
    ``visible_appliance_or_404`` never yields a FortiADC row here and the answer
    is 404 — confirming the row exists is the leak that scoping closes. That
    makes the route's own kind check a SECOND door with one behaviour, which is
    exactly the kind of code that rots untested: so it is exercised directly,
    with the scope lifted, and it must still refuse.
    """
    from app.views import _clicoverage

    aid = _make_appliance(app, name="adc-cc", kind="fortiadc")
    login(client, admin_user_id(app))

    r = client.post("/web/api-explorer/cli-coverage/live",
                    data={"appliance_id": aid, "path": "system global"})
    assert r.status_code == 404, "the ADOM scope must not even confirm it exists"

    # scope lifted — the route's own check is now the only thing left
    with app.app_context():
        from app.models import Appliance
        adc = Appliance.query.get(aid)
        monkeypatch.setattr(_clicoverage, "visible_appliance_or_404",
                            lambda _id: adc)
        r = client.post("/web/api-explorer/cli-coverage/live",
                        data={"appliance_id": aid, "path": "system global"})
        assert r.status_code == 403, r.status_code
        assert "not a fortiweb" in r.get_json()["error"]


def test_capture_refuses_an_appliance_of_another_product(app, client, monkeypatch):
    """Same two doors — and a capture WRITES to the vault.

    A FortiADC dump filed from the FortiWeb hub would be diffed against the
    wrong catalog by whoever opened the page next, so the refusal has to hold
    even without the scope in front of it.
    """
    from app.views import _clicoverage

    aid = _make_appliance(app, name="adc-cap", kind="fortiadc")
    login(client, admin_user_id(app))

    r = client.post("/web/api-explorer/cli-coverage/capture",
                    data={"appliance_id": aid}, follow_redirects=True)
    assert r.status_code == 404

    with app.app_context():
        from app.models import Appliance
        adc = Appliance.query.get(aid)
        monkeypatch.setattr(_clicoverage, "visible_appliance_or_404",
                            lambda _id: adc)
        r = client.post("/web/api-explorer/cli-coverage/capture",
                        data={"appliance_id": aid}, follow_redirects=True)
        assert b"is not a fortiweb" in r.data


# ==========================================================================
# one author for the section
# ==========================================================================

def test_capture_reports_the_reason_when_the_device_refuses(app, client,
                                                          monkeypatch):
    """A failed capture must name why.

    A redirect with a bare "did not complete" reads as an operational hiccup
    when it is usually the device saying something specific (`-20010` licence
    lock, `-901` backup password, SSH auth).
    """
    from app.services import backup as backup_svc

    aid = _make_appliance(app)
    login(client, admin_user_id(app))

    def _fail(appliance, created_by="", method="auto"):
        raise RuntimeError("SSH auth failed for fw-cc")

    monkeypatch.setattr(backup_svc, "fetch_device_backup_auto", _fail)
    r = client.post("/web/api-explorer/cli-coverage/capture",
                    data={"appliance_id": aid}, follow_redirects=True)
    assert r.status_code == 200
    assert b"SSH auth failed" in r.data


def test_capture_asks_for_the_ssh_transport_explicitly(app, client, monkeypatch):
    """``method="ssh"``, not ``auto``.

    ``auto`` prefers the device's REST local-backup, which yields the device's
    OWN backup file — a perfectly good vault artifact and not necessarily the
    ``show full-configuration`` text this page parses. A capture button on a
    coverage page that files something the coverage page cannot read is the
    quietest possible failure.
    """
    from app.services import backup as backup_svc

    aid = _make_appliance(app)
    login(client, admin_user_id(app))
    seen = {}

    def _spy(appliance, created_by="", method="auto"):
        seen["method"] = method
        return backup_svc.store_bytes(
            appliance_id=appliance.id, appliance_name=appliance.name,
            data=FW_DUMP.encode(), filename="x_cli.conf", source="device",
            firmware="FortiWeb-KVM 7.6.8")

    monkeypatch.setattr(backup_svc, "fetch_device_backup_auto", _spy)
    client.post("/web/api-explorer/cli-coverage/capture", data={"appliance_id": aid},
                follow_redirects=True)
    assert seen["method"] == "ssh"


def test_the_partial_is_the_only_author_of_this_section():
    """Four hubs include it; none of them copies it.

    Sharing a partial and then copying its markup per page is what made the
    sidebar accordion and the status badge drift in this repo. The anchor is the
    section id, because that is what the JS and the guards both key on.
    """
    assert 'id="cliCoverage"' in PARTIAL.read_text(encoding="utf-8")
    for rel in HUB_TEMPLATES:
        raw = (REPO / rel).read_text(encoding="utf-8")
        # The comment that documents the include NAMES the partial, so a
        # substring test is satisfied by the comment after the include itself is
        # deleted — the mutation that removed it survived exactly that way.
        # Strip Jinja comments and assert the INCLUDE TAG. Eleventh time.
        body = re.sub(r"\{#.*?#\}", "", raw, flags=re.S)
        assert "{% include 'partials/_cli_coverage.html' %}" in body, rel
        assert 'id="cliCoverage"' not in body, "%s grew its own copy" % rel
    others = [p for p in (REPO / "app" / "templates").rglob("*.html")
              if p != PARTIAL and 'id="cliCoverage"' in p.read_text(encoding="utf-8")]
    assert others == []


def test_the_sections_javascript_is_scoped_to_its_own_root():
    """Not a document-level listener.

    The hub pages already handle clicks on table cells and tree leaves. A
    listener on ``document`` here would fire inside theirs, and a guard written
    as "this file mentions stopPropagation" would be satisfied by THEIR handler
    while the mutation that deletes this one survives.
    """
    js = _section_js()
    assert "getElementById('cliCoverage')" in js
    assert "document.addEventListener" not in js
    assert "root.addEventListener" in js
    assert "stopPropagation" in js


def test_device_configuration_text_is_never_assigned_as_html():
    """Block text is whatever an operator typed into an appliance.

    ``textContent`` on the ``<pre>``; ``innerHTML`` anywhere in this block is
    the bug. The comments in the partial name ``innerHTML`` in order to forbid
    it, which is why this asserts against comment-stripped JS.
    """
    js = _section_js()
    assert "textContent" in js
    assert "innerHTML" not in js


def test_the_row_cap_is_printed_rather_than_silently_truncating():
    """A capped list that does not say it is capped reads as "that is all"."""
    from app.views import _clicoverage

    assert _clicoverage.ROW_CAP > 0
    page = _jinja_text_only()
    assert "cc_row_cap" in page
    assert page.count("Showing the first") >= 2, \
        "both capped lists must declare the cap"
    # The literal surviving proves nothing: disabling the {% if %} around it
    # leaves the sentence in the file and truncates in silence anyway. Assert the
    # GUARD, once per capped list.
    guards = re.findall(r"\{%\s*if\s+D\.(\w+)\|length\s*>\s*cc_row_cap\s*%\}", page)
    assert set(guards) == {"cli_only", "no_block"}, guards


def test_the_service_never_writes_anything(app):
    """A derived report with no artifact: nothing to go stale, nothing to back up.

    Measured on 248 at 20 ms for the 690 KB FortiWeb dump, which is why this is
    derived per request instead of persisted like ``api_matrix``. A future
    ``rebuild``/JSON store would put a derived view in a different backup path
    from the evidence it summarises.
    """
    code = _py_code_only(SERVICE)
    for forbidden in ("db.session.add", "db.session.commit", "_write_json",
                      "os.replace", "mkstemp"):
        assert forbidden not in code, forbidden
    assert re.search(r"open\([^)]*['\"]w", code) is None


# ==========================================================================
# phase C — promoting a finding into the catalog
# ==========================================================================

def test_candidate_urns_offer_every_joiner_because_the_cli_cannot_tell():
    """FortiWeb joins sub-tables with '.' and child lists with '/'.

    The CLI spells both the same way, so a single derived path is a coin flip —
    and it would be written into the catalog, which every service resolves names
    through (``loader.resolve``). Offering all of them and letting the DEVICE
    answer is the only version of this that cannot invent an endpoint.
    """
    from app.services import cli_coverage as cc

    got = cc.candidate_urns("fortiweb", "system admin-certificate local")
    assert "/api/v2.0/cmdb/system/admin-certificate.local" in got
    assert "/api/v2.0/cmdb/system/admin-certificate/local" in got
    # a two-word path is unambiguous and must NOT be padded with guesses
    assert cc.candidate_urns("fortiweb", "system settings") == \
        ["/api/v2.0/cmdb/system/settings"]
    assert cc.candidate_urns("fortiweb", "system") == []


@pytest.mark.parametrize("product,cli_path,real_urn", [
    ("fortiweb", "system admin-certificate local",
     "/api/v2.0/cmdb/system/admin-certificate.local"),
    ("fortiweb", "system snmp community",
     "/api/v2.0/cmdb/system/snmp.community"),
    ("fortiweb", "server-policy allow-hosts host-list",
     "/api/v2.0/cmdb/server-policy/allow-hosts/host-list"),
    ("fortiweb", "server-policy policy http-content-routing-list",
     "/api/v2.0/cmdb/server-policy/policy/http-content-routing-list"),
    ("fortiweb", "waf graphql-validation policy graphql-rule-list",
     "/api/v2.0/cmdb/waf/graphql-validation.policy/graphql-rule-list"),
    ("fortiadc", "load-balance pool pool_member",
     "/api/load_balance_pool_child_pool_member"),
    ("fortiadc", "load-balance virtual-server",
     "/api/load_balance_virtual_server"),
])
def test_the_derivation_reproduces_paths_the_catalog_already_holds(
        product, cli_path, real_urn):
    """Anti-vacuity, and the only evidence the derivation is not fiction.

    These CLI paths and these URNs are both real: the paths come out of the live
    dumps, the URNs out of the shipped catalogs. If the candidate list could not
    reproduce the ones we already know, it would not find the ones we do not.
    """
    from app.services import cli_coverage as cc

    assert real_urn in cc.candidate_urns(product, cli_path)


def test_the_candidate_list_is_capped_and_the_cap_is_reported():
    """A deep child table yields 2^(n-1) combinations, each one a device GET."""
    from app.services import cli_coverage as cc

    deep = cc.candidate_urns("fortiweb", "waf a b c d e f")
    assert len(deep) <= cc.MAX_CANDIDATES
    view_src = VIEW.read_text(encoding="utf-8")
    assert '"capped"' in view_src, "a silent cap reads as a complete answer"


def test_the_derived_name_looks_like_a_seeded_one():
    """``system_automation_stitch_action_member`` — not an announcement of which
    tool made the row."""
    from app.services import cli_coverage as cc

    assert cc.catalog_name_for("system automation-stitch action_member") == \
        "system_automation_stitch_action_member"
    assert re.match(r"^[A-Za-z0-9_.\-]+$", cc.catalog_name_for("waf data-mining"))


def test_the_probe_delegates_its_verdicts_to_the_sweep(app, client, monkeypatch):
    """``absent`` is a claim about the catalog; ``error`` is a claim about the
    device. The reconciler acts on that distinction, so a second reading of an
    HTTP status here would eventually disagree with it."""
    from app.services import rediscovery

    aid = _make_appliance(app)
    login(client, admin_user_id(app))
    seen = []

    def _probe(appliance, urn):
        seen.append(urn)
        if urn.endswith(".local"):
            return [{"name": "x"}], "ok", ""
        return [], "absent", "errcode -20001"

    monkeypatch.setattr(rediscovery, "probe_endpoint", _probe)
    r = client.post("/web/api-explorer/cli-coverage/probe",
                    data={"appliance_id": aid,
                          "path": "system admin-certificate local"})
    d = r.get_json()
    assert r.status_code == 200 and d["ok"] is True
    assert len(seen) == 2, seen
    assert d["served"] == ["/api/v2.0/cmdb/system/admin-certificate.local"]
    verdicts = {c["urn"]: c["verdict"] for c in d["candidates"]}
    assert set(verdicts.values()) == {"ok", "absent"}
    assert d["name"] == "system_admin_certificate_local"


def test_a_candidate_that_raises_does_not_sink_the_probe(app, client, monkeypatch):
    from app.services import rediscovery

    aid = _make_appliance(app)
    login(client, admin_user_id(app))

    def _boom(appliance, urn):
        raise RuntimeError("transport died")

    monkeypatch.setattr(rediscovery, "probe_endpoint", _boom)
    r = client.post("/web/api-explorer/cli-coverage/probe",
                    data={"appliance_id": aid, "path": "system a b"})
    d = r.get_json()
    assert d["ok"] is True and d["served"] == []
    assert all(c["verdict"] == "error" for c in d["candidates"])
    assert "transport died" in d["candidates"][0]["detail"]


def test_serving_none_of_the_candidates_is_itself_the_answer(app, client,
                                                            monkeypatch):
    """An element that really is CLI-only must not look like a failed probe."""
    from app.services import rediscovery

    aid = _make_appliance(app)
    login(client, admin_user_id(app))
    monkeypatch.setattr(rediscovery, "probe_endpoint",
                        lambda a, urn: ([], "absent", "errcode -20001"))
    r = client.post("/web/api-explorer/cli-coverage/probe",
                    data={"appliance_id": aid, "path": "system automation-slack"})
    assert r.get_json()["served"] == []
    js = _section_js()
    assert "really is CLI-only" in js, \
        "the empty result has to say what it means"


def test_a_path_no_rest_shape_can_be_derived_from_is_refused(app, client):
    login(client, admin_user_id(app))
    aid = _make_appliance(app)
    r = client.post("/web/api-explorer/cli-coverage/probe",
                    data={"appliance_id": aid, "path": "vdom"})
    assert r.status_code == 400
    assert "no REST path can be derived" in r.get_json()["error"]


def test_the_probe_refuses_another_products_appliance(app, client, monkeypatch):
    """Same two doors as the live read: 404 from the ADOM scope over HTTP, and
    the route's own check exercised directly with the scope lifted."""
    from app.views import _clicoverage

    aid = _make_appliance(app, name="adc-probe", kind="fortiadc")
    login(client, admin_user_id(app))
    r = client.post("/web/api-explorer/cli-coverage/probe",
                    data={"appliance_id": aid, "path": "system a b"})
    assert r.status_code == 404

    with app.app_context():
        from app.models import Appliance
        adc = Appliance.query.get(aid)
        monkeypatch.setattr(_clicoverage, "visible_appliance_or_404", lambda _i: adc)
        r = client.post("/web/api-explorer/cli-coverage/probe",
                        data={"appliance_id": aid, "path": "system a b"})
        assert r.status_code == 403


def test_the_probe_is_not_gated_on_backup_and_the_reads_are(app, client,
                                                            operator_id,
                                                            monkeypatch):
    """A verdict and a row count is strictly LESS than the console on this same
    page already gives every logged-in user. Gating the smaller read harder than
    the bigger one beside it would be theatre; gating the block TEXT is not.
    """
    from app.services import rediscovery

    aid = _make_appliance(app)
    bid = _seed_dump(app)
    login(client, operator_id)
    monkeypatch.setattr(rediscovery, "probe_endpoint",
                        lambda a, urn: ([], "absent", ""))

    r = client.post("/web/api-explorer/cli-coverage/probe",
                    data={"appliance_id": aid, "path": "system a b"})
    assert r.status_code == 200, "the probe must work without BACKUP"

    r = client.get("/web/api-explorer/cli-coverage/block?dump=%d&path=system+admin"
                   % bid)
    assert r.status_code in (302, 403), "block TEXT must still need BACKUP"


def test_the_catalog_write_is_the_existing_registry_editor(app):
    """No second writer of a catalog row.

    ``registry.save`` / ``adc_api.registry_save`` already validate the name and
    the URN, refuse duplicates, invalidate the loader cache and write the audit
    line. A write here would be a second author of one row — the failure this
    repo has paid for in the sidebar accordion, the status badge and the
    Authentik group naming.
    """
    page = _jinja_text_only()
    assert "url_for(cc_registry_save_endpoint)" in page

    for path in (VIEW, SERVICE):
        code = _py_code_only(path)
        assert "RegistryEndpoint" not in code, path
        assert "invalidate_cache" not in code, path


def test_the_register_form_is_only_armed_from_a_url_the_device_served():
    """The guessed URN must never reach the form on its own.

    The ``use`` button is created ONLY inside the ``verdict === 'ok'`` branch and
    the form reads its URN from that button's dataset — so the value posted to
    the catalog is one the appliance answered, not one SATOM derived.
    """
    js = _section_js()
    assert "c.verdict === 'ok'" in js
    assert "pick.dataset.urn = c.urn" in js
    assert "ccRegUrn" in js


def test_probe_rows_are_built_as_nodes_not_markup():
    """Every string in that table came off an appliance."""
    js = _section_js()
    assert "createElement('code')" in js
    assert "innerHTML" not in js
    assert js.count("textContent") >= 5


def test_rediscovery_exposes_one_public_probe_and_dispatches_by_kind(app,
                                                                    monkeypatch):
    from app.services import rediscovery

    assert callable(getattr(rediscovery, "probe_endpoint", None))
    seen = {}

    class _Snap:
        id = 1
        name = "x"
        host = "h"
        port = 443
        verify_ssl = False
        username = "u"
        password = "p"
        vdom = None
        kind = "fortiadc"

    def _fake_make_probe(snap):
        seen["kind"] = snap.kind
        return lambda ep: ([], "absent", ep["urn"])

    from app.services import adc_ops
    monkeypatch.setattr(adc_ops, "make_probe", _fake_make_probe)
    with app.app_context():
        rows, verdict, detail = rediscovery.probe_endpoint(_Snap(), "/api/x")
    assert seen["kind"] == "fortiadc" and verdict == "absent" and detail == "/api/x"

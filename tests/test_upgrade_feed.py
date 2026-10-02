"""Guards for the system-upgrade feed (satom-system-upgrades/).

The feed is an address book: it may say where a package is, never whether to
trust it. These tests pin that split -- a download that does not match the
feed's sha256 never appears under a real name, the generator can never write a
feed the nodes would refuse, and fetching never applies anything on its own.
"""
from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]


def _load(name, rel):
    spec = importlib.util.spec_from_file_location(name, REPO / rel)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


feed = _load("satom_upgrade_feed_t", "deploy/upgrade_feed.py")
sys.path.insert(0, str(REPO / "deploy"))
gen = _load("satom_gen_upgrade_feed_t", "deploy/gen_upgrade_feed.py")

PAYLOAD = b"satom-update-payload" * 1000
SHA = hashlib.sha256(PAYLOAD).hexdigest()


def _doc(version="9.9.9", payload=PAYLOAD, **pkg):
    name = "satom-update-%s.tar.gz" % version
    p = {"name": name, "url": "https://example.test/v%s/%s" % (version, name),
         "sha256": hashlib.sha256(payload).hexdigest(), "size": len(payload)}
    p.update(pkg)
    return {"schema": feed.FEED_SCHEMA, "product": "satom", "version": version,
            "package": p}


def _serve(monkeypatch, mod, body: bytes):
    seen = []

    def fake_open(url, timeout):
        seen.append(url)
        if not url.startswith("https://"):
            raise mod.FeedError("only https:// URLs are fetched (got %r)" % url)
        return io.BytesIO(body)
    monkeypatch.setattr(mod, "_open", fake_open)
    return seen


# ---------------------------------------------------------------------------
# the reader
# ---------------------------------------------------------------------------
def test_a_valid_feed_parses():
    assert feed.parse_feed(json.dumps(_doc()).encode())["version"] == "9.9.9"


@pytest.mark.parametrize("mutate,why", [
    (lambda d: d.update(schema="other/1"), "schema"),
    (lambda d: d["package"].update(url="http://example.test/satom-update-9.9.9.tar.gz"), "https"),
    (lambda d: d["package"].update(url="https://example.test/other.tar.gz"), "https"),
    (lambda d: d["package"].update(name="../../etc/x.tar.gz"), "not an update package"),
    (lambda d: d["package"].update(sha256="abc"), "sha256"),
    (lambda d: d["package"].update(size=0), "implausible size"),
    (lambda d: d["package"].update(size=10 ** 10), "implausible size"),
    (lambda d: d.update(version="9.9.8"), "does not match"),
])
def test_a_malformed_feed_is_refused(mutate, why):
    d = _doc()
    mutate(d)
    with pytest.raises(feed.FeedError, match=why):
        feed.parse_feed(json.dumps(d).encode())


def test_a_download_that_matches_is_staged_under_its_name(tmp_path, monkeypatch):
    _serve(monkeypatch, feed, PAYLOAD)
    calls = []
    p = feed.download_package(_doc(), tmp_path, progress=lambda d, t: calls.append((d, t)))
    assert p == tmp_path / "satom-update-9.9.9.tar.gz"
    assert p.read_bytes() == PAYLOAD
    assert calls[-1] == (len(PAYLOAD), len(PAYLOAD))


@pytest.mark.parametrize("body,why", [
    (PAYLOAD[:-1], "interrupted"),
    (PAYLOAD + b"x", "larger than"),
    (PAYLOAD[:-1] + b"X", "does not match"),
])
def test_a_download_that_does_not_match_leaves_nothing(tmp_path, monkeypatch, body, why):
    _serve(monkeypatch, feed, body)
    with pytest.raises(feed.FeedError, match=why):
        feed.download_package(_doc(), tmp_path)
    assert list(tmp_path.iterdir()) == [], "a partial or swapped download must not survive"


def test_redirects_away_from_https_are_refused():
    h = feed._HttpsOnlyRedirect()
    with pytest.raises(feed.FeedError, match="away from HTTPS"):
        h.redirect_request(None, None, 302, "Found", {}, "http://cdn.example/x")


def test_the_reader_is_stdlib_only_and_never_imports_the_app():
    import ast
    tree = ast.parse((REPO / "deploy" / "upgrade_feed.py").read_text())
    mods = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            mods |= {a.name.split(".")[0] for a in n.names}
        elif isinstance(n, ast.ImportFrom):
            mods.add((n.module or "").split(".")[0])
    assert not mods & {"app", "flask", "requests", "httpx", "cryptography"}, mods


def test_the_feed_url_is_overridable_for_a_mirror(monkeypatch):
    monkeypatch.delenv("SATOM_UPGRADE_FEED", raising=False)
    assert feed.feed_url() == feed.DEFAULT_FEED_URL
    monkeypatch.setenv("SATOM_UPGRADE_FEED", "https://mirror.example/latest.json")
    assert feed.feed_url() == "https://mirror.example/latest.json"


# ---------------------------------------------------------------------------
# the generator (run by the release pipeline)
# ---------------------------------------------------------------------------
def _readme(d):
    (d / "README.md").write_text("# x\n\n%s\n%s\n\ntail\n" % (gen.START, gen.END))


def test_the_generator_writes_entry_latest_and_table_and_is_idempotent(tmp_path):
    _readme(tmp_path)
    assert gen.main(["2.6.0", "a" * 64, "100", "--released", "2026-10-02",
                     "--dir", str(tmp_path)]) == 0
    assert gen.main(["2.10.0", "b" * 64, "200", "--released", "2026-11-01",
                     "--dir", str(tmp_path)]) == 0
    latest = json.loads((tmp_path / "latest.json").read_text())
    assert latest["version"] == "2.10.0", "latest must be the highest VERSION, not the last written"
    feed.parse_feed((tmp_path / "latest.json").read_bytes())
    table = (tmp_path / "README.md").read_text()
    assert table.index("| 2.10.0 |") < table.index("| 2.6.0 |")
    assert table.endswith("tail\n")
    before = {p.name: p.read_text() for p in tmp_path.iterdir()}
    assert gen.write(tmp_path, gen.entry("2.6.0", "a" * 64, 100, "2026-10-02",
                                         "visionebc/SATOM")) == []
    assert before == {p.name: p.read_text() for p in tmp_path.iterdir()}


def test_the_generator_refuses_what_a_node_would_refuse(tmp_path):
    assert gen.main(["2.6.0", "not-a-sha", "100", "--dir", str(tmp_path)]) == 2
    assert not (tmp_path / "latest.json").exists()


def test_the_published_folder_is_a_valid_feed():
    d = REPO / "satom-system-upgrades"
    latest = feed.parse_feed((d / "latest.json").read_bytes())
    entries = [json.loads(p.read_text()) for p in d.glob("satom-update-*.json")]
    assert latest["version"] == max((e["version"] for e in entries),
                                    key=lambda v: [int(x) for x in v.split(".")])
    readme = (d / "README.md").read_text()
    for e in entries:
        feed.parse_feed(json.dumps(e).encode())
        assert e["package"]["sha256"] in readme, "README table is stale for %s" % e["version"]


def test_packages_are_never_committed_into_the_folder():
    assert not list((REPO / "satom-system-upgrades").glob("*.tar.gz")), (
        "update packages are release assets; a 64 MB blob per release in git "
        "grows every clone for ever")


# ---------------------------------------------------------------------------
# the console (service + routes)
# ---------------------------------------------------------------------------
@pytest.fixture()
def svc(tmp_path, monkeypatch):
    monkeypatch.setenv("FM_APP_DIR", str(tmp_path))
    import importlib
    import app.services.update_package_service as m
    m = importlib.reload(m)
    import app.version as appver
    monkeypatch.setattr(appver, "app_version", lambda: "9.9.0")
    yield m
    importlib.reload(m)


def test_check_feed_reports_unreachable_without_raising(svc, monkeypatch):
    def boom(url="", timeout=10):
        raise svc.FeedError("cannot reach it")
    monkeypatch.setattr(svc.feed, "fetch_feed", boom)
    res = svc.check_feed()
    assert res["reachable"] is False and "cannot reach" in res["error"]


def test_check_feed_says_newer_and_download_stages_without_applying(svc, monkeypatch):
    doc = dict(_doc(), _feed_url="https://example.test/latest.json")
    monkeypatch.setattr(svc.feed, "fetch_feed", lambda url="", timeout=10: doc)
    _serve(monkeypatch, svc.feed, PAYLOAD)
    res = svc.check_feed()
    assert res["newer"] is True and res["staged"] is False
    got = svc.download_from_feed()
    assert got["name"] == "satom-update-9.9.9.tar.gz"
    assert svc.check_feed()["staged"] is True
    assert not svc.REQ_DIR.exists() or not list(svc.REQ_DIR.iterdir()), (
        "downloading must only stage: applying stays the operator's decision")


def test_the_page_offers_the_feed_and_downloads_as_a_job(app, client, monkeypatch, tmp_path):
    from conftest import admin_user_id, login
    from app.services import jobs as jobsvc
    from app.services import update_package_service as upkg
    monkeypatch.setenv("SATOM_JOBS_DIR", str(tmp_path / "jobs"))
    monkeypatch.setattr(jobsvc, "run_async", lambda a, jid, w: w(a, jid))
    monkeypatch.setattr(upkg, "check_feed", lambda: {"reachable": True, "newer": True,
                                                     "version": "9.9.9"})
    monkeypatch.setattr(upkg, "download_from_feed", lambda progress=None: {
        "name": "satom-update-9.9.9.tar.gz", "size": 1, "version": "9.9.9", "sha256": SHA})
    login(client, admin_user_id(app))
    assert client.get("/self-update/package/feed").get_json()["version"] == "9.9.9"
    r = client.post("/self-update/package/fetch", headers={"X-Requested-With": "XMLHttpRequest"})
    assert r.status_code == 202
    job = jobsvc.get_job(r.get_json()["job_id"])
    assert job["status"] == "success"
    assert job["result"]["name"] == "satom-update-9.9.9.tar.gz"
    html = client.get("/self-update/").get_data(as_text=True)
    assert 'id="feed-check-btn"' in html and "/self-update/package/fetch" in html


# ---------------------------------------------------------------------------
# the CLI: satom execute update fetch
# ---------------------------------------------------------------------------
@pytest.fixture()
def cli(tmp_path, monkeypatch):
    from satom_cli import cmd_trust
    from satom_cli.context import Ctx
    c = Ctx()
    c.is_root, c.uid = True, 0
    c.app_dir = tmp_path
    c.app_user = "root"
    (tmp_path / "VERSION").write_text("9.9.0\n")
    return cmd_trust, c


def test_fetch_without_the_root_copy_points_at_reinstall_runner(cli, monkeypatch):
    mod, ctx = cli
    monkeypatch.setattr(mod, "_feed_module", lambda: None)
    res = mod.update_fetch(ctx, [])
    assert res.status == "bad"
    assert "reinstall runner" in json.dumps(res.sections)


def test_fetch_is_a_dry_run_until_yes_and_says_when_up_to_date(cli, monkeypatch):
    mod, ctx = cli
    doc = dict(_doc(), _feed_url="https://example.test/latest.json")
    monkeypatch.setattr(feed, "fetch_feed", lambda url="", timeout=10: doc)
    monkeypatch.setattr(mod, "_feed_module", lambda: feed)
    res = mod.update_fetch(ctx, [])
    assert res.status == "warn" and "dry run" in res.title
    assert not (ctx.app_dir / "data" / "update-uploads").exists(), "a dry run downloads nothing"
    (ctx.app_dir / "VERSION").write_text("9.9.9\n")
    assert mod.update_fetch(ctx, ["--yes"]).status == "ok"


def test_fetch_download_only_stages_the_verified_bytes(cli, monkeypatch):
    mod, ctx = cli
    doc = dict(_doc(), _feed_url="https://example.test/latest.json")
    monkeypatch.setattr(feed, "fetch_feed", lambda url="", timeout=10: doc)
    monkeypatch.setattr(mod, "_feed_module", lambda: feed)
    _serve(monkeypatch, feed, PAYLOAD)
    res = mod.update_fetch(ctx, ["--download-only"])
    assert res.status == "ok"
    assert (ctx.app_dir / "data" / "update-uploads" / "satom-update-9.9.9.tar.gz"
            ).read_bytes() == PAYLOAD


def test_fetch_is_a_registered_root_command():
    from satom_cli import tree
    node = tree.ROOT.children["execute"].children["update"].children["fetch"]
    assert node.needs_root and node.run is not None


def test_fetch_loads_the_reader_only_from_the_root_owned_copy():
    from satom_cli import cmd_trust
    import inspect
    src = inspect.getsource(cmd_trust._feed_module)
    assert "RUNNER_LIB" in src and "app_dir" not in src, (
        "root must not execute upgrade_feed.py from the service account's tree")
    body = (REPO / "deploy" / "install-runner.sh").read_text()
    files = next(l for l in body.splitlines() if l.startswith("FILES="))
    assert "upgrade_feed.py" in files


# ---------------------------------------------------------------------------
# the runner: the shipped API pack is imported after an update
# ---------------------------------------------------------------------------
class _St:
    def __init__(self):
        self.steps = []

    def begin(self, name):
        pass

    def step(self, name, ok=True, detail=""):
        self.steps.append((name, ok, detail))


@pytest.fixture()
def runner(tmp_path, monkeypatch):
    monkeypatch.setenv("FM_APP_DIR", str(tmp_path))
    monkeypatch.setenv("FM_APP_USER", "satom")
    mod = _load("satom_runner_t", "deploy/self_update_runner.py")
    return mod


def test_runner_imports_the_shipped_pack_through_the_cli(runner, tmp_path, monkeypatch):
    (tmp_path / "api-packs").mkdir()
    (tmp_path / "api-packs" / "satom-apipack-9.9.9.tar.gz").write_bytes(b"x")
    seen = []

    class P:
        returncode, stdout, stderr = 0, "imported 3", ""
    monkeypatch.setattr(runner.subprocess, "run", lambda cmd, **kw: seen.append(cmd) or P())
    st = _St()
    runner.import_shipped_api_pack(st)
    assert seen == [["/usr/local/sbin/satom", "execute", "apipack", "import", "shipped", "--yes"]]
    assert st.steps[-1][:2] == ("import shipped API pack", True)


def test_runner_import_failure_is_reported_never_raised(runner, tmp_path, monkeypatch):
    (tmp_path / "api-packs").mkdir()
    (tmp_path / "api-packs" / "satom-apipack-9.9.9.tar.gz").write_bytes(b"x")

    class P:
        returncode, stdout, stderr = 1, "", "signature refused"
    monkeypatch.setattr(runner.subprocess, "run", lambda cmd, **kw: P())
    st = _St()
    runner.import_shipped_api_pack(st)
    name, ok, detail = st.steps[-1]
    assert ok is False and "retry with" in detail


def test_runner_import_that_hangs_is_reported_never_raised(runner, tmp_path, monkeypatch):
    (tmp_path / "api-packs").mkdir()
    (tmp_path / "api-packs" / "satom-apipack-9.9.9.tar.gz").write_bytes(b"x")

    def hang(cmd, **kw):
        raise runner.subprocess.TimeoutExpired(cmd, kw.get("timeout"))
    monkeypatch.setattr(runner.subprocess, "run", hang)
    st = _St()
    runner.import_shipped_api_pack(st)      # must not raise: the update already passed
    assert st.steps[-1][1] is False and "retry with" in st.steps[-1][2]


@pytest.mark.parametrize("env,packs", [("0", True), ("1", False)])
def test_runner_skips_when_disabled_or_nothing_ships(runner, tmp_path, monkeypatch, env, packs):
    monkeypatch.setenv("SATOM_API_PACK_AUTO", env)
    if packs:
        (tmp_path / "api-packs").mkdir()
        (tmp_path / "api-packs" / "satom-apipack-9.9.9.tar.gz").write_bytes(b"x")
    monkeypatch.setattr(runner.subprocess, "run",
                        lambda *a, **k: pytest.fail("must not run the import"))
    st = _St()
    runner.import_shipped_api_pack(st)
    assert st.steps[-1][1] is True and "skipped" in st.steps[-1][2]


def test_runner_calls_the_import_on_both_apply_paths_primary_only():
    src = (REPO / "deploy" / "self_update_runner.py").read_text()
    import re
    assert len(re.findall(r"^\s+import_shipped_api_pack\(st\)$", src, re.M)) == 2
    pkg_path = src[src.index('st.step("record deployed revision"'):]
    assert pkg_path.index("if not is_standby:") < pkg_path.index("import_shipped_api_pack(st)")
    git_path = src[:src.index("# POST-FLIGHT: compare the after-state")]
    assert git_path.rindex("if is_standby:") < git_path.rindex("import_shipped_api_pack(st)")


# ---------------------------------------------------------------------------
# 'sudo satom' on openSUSE / RHEL
# ---------------------------------------------------------------------------
def test_install_cli_links_usr_bin_satom_without_clobbering():
    body = (REPO / "deploy" / "install-cli.sh").read_text()
    assert 'ALIAS="/usr/bin/satom"' in body
    assert 'ln -sfn "$BIN" "$ALIAS"' in body
    guard = body[body.index('ALIAS="/usr/bin/satom"'):body.index('ln -sfn "$BIN" "$ALIAS"')]
    assert '[ -L "$ALIAS" ] || [ ! -e "$ALIAS" ]' in guard, (
        "a /usr/bin/satom that is a real file belongs to someone else")

"""Phase 9 — system backup service (pure parts) + catalog wiring."""
from app.services import system_backup as SB
from app.services import scheduled_actions as SA


def test_parse_db_url_strips_driver():
    c = SB.parse_db_url("postgresql+psycopg://fortinet:p%40ss@192.0.2.5:5433/fmw")
    assert c["host"] == "192.0.2.5" and c["port"] == "5433"
    assert c["user"] == "fortinet" and c["dbname"] == "fmw"
    assert c["password"] == "p@ss"     # url-decoded


def test_pg_dump_cmd_custom_format():
    c = {"host": "h", "port": "5432", "user": "u", "password": "x", "dbname": "d"}
    cmd = SB.pg_dump_cmd(c, "/tmp/db.dump")
    assert cmd[0] == "pg_dump" and "-Fc" in cmd and "/tmp/db.dump" in cmd
    assert "x" not in cmd     # password never on the command line


def test_pg_restore_cmd_clean():
    c = {"host": "h", "port": "5432", "user": "u", "password": "x", "dbname": "d"}
    cmd = SB.pg_restore_cmd(c, "/tmp/db.dump")
    assert cmd[0] == "pg_restore" and "--clean" in cmd and "--if-exists" in cmd


def test_catalog_has_system_backup():
    assert SA.get_spec("system_backup") is not None
    assert SA.get_spec("system_backup").needs_targets is False


def test_system_backup_dry_run():
    r = SA.run_action(SA.get_spec("system_backup"), None, {}, dry_run=True)
    assert r["ok"] is True and "dry-run" in r["summary"]

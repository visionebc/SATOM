"""Firmware-flash before/after REPORT — self-contained HTML + JSON artifact.

Both the upgrade and the downgrade paths capture a read-only snapshot BEFORE the
flash (``services.upgrade.prepare`` → config backup + SSH health battery +
published-service probes) and AFTER it (``services.upgrade.postflight`` → re-probe
+ SSH health battery + a per-policy service diff). Those snapshots used to live
only inside the background job's JSON result, invisible to the operator.

This module renders them into a viewable, self-contained ``status.html`` (own CSS,
opens standalone) + a machine-readable ``service-validation.json`` under
``data/jobs/reports/<job_id>/`` and returns the URL the job/toast links to. The
report shows, for BOTH directions:

* firmware before → after + an overall verdict badge;
* the published-service before/after/diff table
  (reuses :func:`services.service_probe.render_status_html`); and
* the **SSH command battery before vs after**, one collapsible block per
  ``diagnose``/``get`` command, flagged *changed* / *unchanged*.

Pure stdlib + :mod:`services.service_probe`; the caller (the flash worker) writes
nothing itself — it just calls :func:`write_report`.
"""
from __future__ import annotations

import html
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any

from . import service_probe


# --------------------------------------------------------------------------- #
#  Paths                                                                       #
# --------------------------------------------------------------------------- #
def _reports_dir() -> Path:
    d = Path(__file__).resolve().parents[2] / "data" / "jobs" / "reports"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _job_dir(job_id: str) -> Path:
    d = _reports_dir() / str(job_id)
    d.mkdir(parents=True, exist_ok=True)
    return d


def report_url(job_id: str) -> str:
    return f"/appliances/flash-report/{job_id}"


def read_report(job_id: str) -> str | None:
    """Return the stored ``status.html`` for a job, or ``None`` if absent."""
    p = _job_dir(job_id) / "status.html"
    if not p.exists():
        return None
    try:
        return p.read_text(encoding="utf-8")
    except Exception:  # noqa: BLE001
        return None


# --------------------------------------------------------------------------- #
#  SSH health battery parsing + rendering                                     #
# --------------------------------------------------------------------------- #
_SECT_RE = re.compile(r"(?m)^=====\s*(.*?)\s*=====\s*$")


def split_health_text(text: str) -> dict[str, str]:
    """Parse ``ssh_ops.health_text`` output (``===== <cmd> =====`` blocks) back
    into an ordered ``{command: output}`` map. Empty / missing → ``{}``."""
    out: dict[str, str] = {}
    if not text:
        return out
    parts = _SECT_RE.split(text)
    # parts = [pre, cmd1, body1, cmd2, body2, ...]
    it = iter(parts[1:])
    for cmd in it:
        body = next(it, "")
        out[cmd.strip()] = body.strip("\n")
    return out


def _health_section(before: dict | None, after: dict | None) -> str:
    """Render the SSH command battery before-vs-after as collapsible blocks."""
    b = before or {}
    a = after or {}
    b_ok, a_ok = b.get("ok"), a.get("ok")
    b_cmds = split_health_text(b.get("text") or "") if b_ok else {}
    a_cmds = split_health_text(a.get("text") or "") if a_ok else {}

    notes = []
    if before is not None and not b_ok:
        notes.append(f"before: {html.escape(str(b.get('error') or 'not captured'))}")
    if after is not None and not a_ok:
        notes.append(f"after: {html.escape(str(a.get('error') or 'not captured'))}")

    names = list(dict.fromkeys([*b_cmds.keys(), *a_cmds.keys()]))
    if not names:
        msg = " · ".join(notes) if notes else "No SSH diagnostic battery was captured."
        return (f'<section class="card"><h2>SSH command battery — before / after</h2>'
                f'<p class="muted">{msg}</p></section>')

    changed = 0
    blocks = []
    empty = '<span class="muted">(empty)</span>'
    for cmd in names:
        bt = b_cmds.get(cmd, "")
        at = a_cmds.get(cmd, "")
        present = (cmd in b_cmds) and (cmd in a_cmds)
        is_diff = bt.strip() != at.strip()
        if present and is_diff:
            changed += 1
        if not present:
            pill = '<span class="pill warn">only one side</span>'
        elif is_diff:
            pill = '<span class="pill warn">changed</span>'
        else:
            pill = '<span class="pill ok">unchanged</span>'
        open_attr = " open" if (present and is_diff) else ""
        bpre = html.escape(bt) or empty
        apre = html.escape(at) or empty
        blocks.append(
            '<details class="cmd"' + open_attr + '><summary><span class="mono">'
            + html.escape(cmd) + '</span> ' + pill + '</summary>'
            + '<div class="ba"><div><div class="lbl">Before</div><pre>' + bpre + '</pre></div>'
            + '<div><div class="lbl">After</div><pre>' + apre + '</pre></div></div>'
            + '</details>'
        )
    head_note = (f'<p class="muted small">{" · ".join(notes)}</p>' if notes else "")
    return (
        f'<section class="card"><h2>SSH command battery — before / after '
        f'<span class="muted small">({len(names)} commands · {changed} changed)</span></h2>'
        f'{head_note}{"".join(blocks)}</section>'
    )


# --------------------------------------------------------------------------- #
#  Service-probe section (reuses service_probe.render_status_html)            #
# --------------------------------------------------------------------------- #
def _probes_of(snap: dict | None) -> list[dict]:
    s = (snap or {}).get("services") or {}
    return s.get("probes") or [] if isinstance(s, dict) else []


def _service_section(meta: dict, before_snap: dict | None, after_snap: dict | None) -> str:
    before = _probes_of(before_snap)
    after = _probes_of(after_snap)
    diff = None
    a_svc = (after_snap or {}).get("services") or {}
    if isinstance(a_svc, dict):
        diff = a_svc.get("diff")
    if diff is None and before and after:
        try:
            diff = service_probe.diff_probes(before, after)
        except Exception:  # noqa: BLE001
            diff = []
    if not (before or after):
        return ('<section class="card"><h2>Published services — before / after</h2>'
                '<p class="muted">No published services were probed.</p></section>')
    frag = service_probe.render_status_html(meta, before, after, diff or [])
    return f'<section class="card"><h2>Published services — before / after</h2>{frag}</section>'


# --------------------------------------------------------------------------- #
#  Full page                                                                  #
# --------------------------------------------------------------------------- #
_CSS = """
:root{color-scheme:dark}
*{box-sizing:border-box}
body{margin:0;background:#080d1a;color:#e2e8f0;font:14px/1.5 -apple-system,Segoe UI,Roboto,Inter,sans-serif}
.wrap{max-width:1100px;margin:0 auto;padding:28px 20px 60px}
h1{font-size:20px;margin:0 0 4px}h2{font-size:15px;margin:0 0 12px}
.sub{color:#94a3b8;font-size:12px;margin:0 0 20px}
.card{background:rgba(15,23,42,.6);border:1px solid rgba(148,163,184,.10);border-radius:16px;padding:18px 20px;margin:0 0 18px;backdrop-filter:blur(6px)}
.muted{color:#64748b}.small{font-size:11px}.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
.ok{color:#10b981}.warn{color:#fbbf24}.bad{color:#ef4444}
.hdr-badge{display:inline-block;font-weight:700;font-size:13px;padding:8px 14px;border-radius:10px;margin:0 0 8px}
.hdr-badge.ok{background:rgba(16,185,129,.14);color:#10b981;border:1px solid rgba(16,185,129,.4)}
.hdr-badge.bad{background:rgba(239,68,68,.14);color:#ef4444;border:1px solid rgba(239,68,68,.4)}
.fw{font-size:13px;margin:6px 0 0}
table{width:100%;border-collapse:collapse;font-size:12px}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid rgba(148,163,184,.10);vertical-align:top}
th{text-transform:uppercase;font-size:10px;letter-spacing:.04em;color:#94a3b8}
.pill{display:inline-block;padding:2px 9px;border-radius:999px;font-size:11px;font-weight:600}
.pill.ok{background:rgba(16,185,129,.14);color:#10b981}
.pill.warn{background:rgba(251,191,36,.14);color:#fbbf24}
.pill.bad{background:rgba(239,68,68,.14);color:#ef4444}
.sp-badge{display:inline-block;font-weight:700;padding:6px 12px;border-radius:8px;margin:0 0 8px}
.sp-badge.ok{background:rgba(16,185,129,.14);color:#10b981}
.sp-badge.bad{background:rgba(239,68,68,.14);color:#ef4444}
.sp-meta{margin:0 0 12px}
details.cmd{border:1px solid rgba(148,163,184,.12);border-radius:10px;margin:0 0 8px;padding:0 12px}
details.cmd summary{cursor:pointer;padding:10px 0;display:flex;gap:10px;align-items:center;justify-content:space-between}
details.cmd summary .mono{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;flex:1}
.ba{display:grid;grid-template-columns:1fr 1fr;gap:12px;padding:0 0 12px}
.ba .lbl{font-size:10px;text-transform:uppercase;letter-spacing:.05em;color:#94a3b8;margin:0 0 4px}
.ba pre{margin:0;background:#0b1220;border:1px solid rgba(148,163,184,.10);border-radius:8px;padding:10px;
        overflow:auto;max-height:340px;font-family:ui-monospace,Menlo,monospace;font-size:11px;white-space:pre;color:#cbd5e1}
@media(max-width:760px){.ba{grid-template-columns:1fr}}
.cards{display:flex;flex-wrap:wrap;gap:12px;margin:0 0 20px}
.mcard{background:rgba(15,23,42,.6);border:1px solid rgba(148,163,184,.12);border-radius:12px;padding:12px 16px;min-width:148px}
.mcard .mlbl{color:#94a3b8;font-size:10px;text-transform:uppercase;letter-spacing:.05em}
.mcard .mval{font-size:16px;font-weight:600;margin-top:4px}
"""


def render_page(meta: dict, before_snap: dict | None, after_snap: dict | None) -> str:
    """Build the full self-contained report page (pure)."""
    app_name = html.escape(str(meta.get("appliance") or "appliance"))
    kind = str(meta.get("kind") or "flash").lower()
    verb = "Downgrade" if kind == "downgrade" else "Upgrade"
    fw_b = html.escape(str(meta.get("firmware_before") or "?"))
    fw_a = html.escape(str(meta.get("firmware_after") or "?"))
    ts = html.escape(str(meta.get("generated_at") or datetime.utcnow().isoformat()))
    img = html.escape(str(meta.get("image") or ""))

    # Overall verdict: recovered AND no service policy flipped verdict.
    diff = ((after_snap or {}).get("services") or {}).get("diff") if isinstance(
        (after_snap or {}).get("services"), dict) else None
    svc_changes = sum(1 for d in (diff or []) if d.get("verdict") not in ("same", None))
    reachable = bool(meta.get("reachable_after"))
    ok = reachable and svc_changes == 0
    badge = ("OK — recovered, no service changes" if ok
             else f"ATTENTION — {svc_changes} service change(s)" if reachable
             else "ATTENTION — appliance not confirmed back online")
    badge_cls = "ok" if ok else "bad"

    # Summary cards (standalone-style): firmware / downtime / backup / policies / changed / operator.
    n_pol = len({p.get("target", {}).get("policy")
                 for p in (_probes_of(before_snap) + _probes_of(after_snap))
                 if p.get("target", {}).get("policy")})
    dt = meta.get("downtime_s")
    dt_txt = f"{int(dt)}s" if isinstance(dt, (int, float)) else "—"
    bk = meta.get("backup")
    bk_txt = ("\u2705 " + html.escape(str(bk))) if bk else "—"
    by = html.escape(str(meta.get("by") or "—"))
    chg_cls = "bad" if svc_changes else "ok"

    def _card(label: str, value: str) -> str:
        return (f'<div class="mcard"><div class="mlbl">{html.escape(label)}</div>'
                f'<div class="mval">{value}</div></div>')

    cards = (
        '<div class="cards">'
        + _card("Firmware", f'<span class="mono">{fw_b}</span> &rarr; <span class="mono">{fw_a}</span>')
        + _card("Downtime", html.escape(dt_txt))
        + _card("Backup", bk_txt)
        + _card("Service policies", str(n_pol))
        + _card("Changed", f'<span class="{chg_cls}">{svc_changes}</span>')
        + _card("Operator", by)
        + '</div>'
    )

    body = (
        f'<div class="wrap">'
        f'<h1>{verb} report — {app_name}</h1>'
        f'<p class="sub">Generated {ts}{" · image " + img if img else ""}</p>'
        f'<div class="hdr-badge {badge_cls}">{html.escape(badge)}</div>'
        f'{cards}'
        f'{_service_section(meta, before_snap, after_snap)}'
        f'{_health_section((before_snap or {}).get("health"), (after_snap or {}).get("health"))}'
        f'</div>'
    )
    return (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        f"<title>{verb} report — {app_name}</title><style>{_CSS}</style></head>"
        f"<body>{body}</body></html>"
    )


def write_report(job_id: str, meta: dict, before_snap: dict | None,
                 after_snap: dict | None) -> str:
    """Render + persist ``status.html`` and ``service-validation.json`` for a job.

    Returns the URL the toast/notification links to (``report_url``). Never
    raises meaningfully — a report failure must not sink a completed flash.
    """
    meta = dict(meta or {})
    meta.setdefault("generated_at", datetime.utcnow().isoformat())
    d = _job_dir(job_id)
    page = render_page(meta, before_snap, after_snap)
    (d / "status.html").write_text(page, encoding="utf-8")
    payload: dict[str, Any] = {"meta": meta, "before": before_snap, "after": after_snap}
    (d / "service-validation.json").write_text(
        json.dumps(payload, default=str, indent=2), encoding="utf-8")
    return report_url(job_id)


# --------------------------------------------------------------------------- #
#  History / listing (every persisted report)                                 #
# --------------------------------------------------------------------------- #
def _verdict_of(meta: dict, after_snap: dict | None) -> tuple[str, int]:
    """Return ``(verdict_key, service_changes)`` for a stored report.
    ``verdict_key`` \u2208 'ok' | 'attention' | 'not_recovered'."""
    a_svc = (after_snap or {}).get("services")
    diff = a_svc.get("diff") if isinstance(a_svc, dict) else None
    changes = sum(1 for d in (diff or []) if d.get("verdict") not in ("same", None))
    if not bool(meta.get("reachable_after")):
        return "not_recovered", changes
    return ("attention" if changes else "ok"), changes


def report_meta(job_id: str) -> dict | None:
    """Read a job's ``service-validation.json`` and return an enriched summary
    dict for the history listing, or ``None`` if absent/unreadable."""
    p = _job_dir(job_id) / "service-validation.json"
    if not p.exists():
        return None
    try:
        payload = json.loads(p.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return None
    meta = dict(payload.get("meta") or {})
    verdict, changes = _verdict_of(meta, payload.get("after"))
    return {
        "job_id": str(job_id),
        "appliance": meta.get("appliance") or "appliance",
        "appliance_id": meta.get("appliance_id"),
        "kind": (meta.get("kind") or "flash").lower(),
        "firmware_before": meta.get("firmware_before") or "?",
        "firmware_after": meta.get("firmware_after") or "?",
        "generated_at": meta.get("generated_at") or "",
        "image": meta.get("image") or "",
        "by": meta.get("by") or "",
        "downtime_s": meta.get("downtime_s"),
        "backup": meta.get("backup"),
        "reachable_after": bool(meta.get("reachable_after")),
        "verdict": verdict,
        "service_changes": changes,
        "has_report": (_job_dir(job_id) / "status.html").exists(),
    }


def list_reports(appliance_id: int | None = None) -> list[dict]:
    """Every persisted flash report (newest first). Optionally filter to one
    appliance. Pure disk scan of ``data/jobs/reports/<job_id>/``."""
    out: list[dict] = []
    for d in _reports_dir().iterdir():
        if not d.is_dir():
            continue
        m = report_meta(d.name)
        if not m:
            continue
        if appliance_id is not None and m.get("appliance_id") != appliance_id:
            continue
        out.append(m)
    out.sort(key=lambda r: r.get("generated_at") or "", reverse=True)
    return out


__all__ = ["write_report", "read_report", "render_page", "report_url",
           "split_health_text", "list_reports", "report_meta"]

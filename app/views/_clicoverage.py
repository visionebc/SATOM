"""Shared body of the CLI ↔ API coverage section of each ADOM's API hub.

Mounted the way :mod:`app.views._apiversions` is, and for the same reason: the
catalog is product-scoped and each product's API area is its own ADOM page, so
one implementation serves four pages instead of four copies drifting apart.
The section is NOT a page of its own — it renders inside the existing API
Explorer / API hub template (``partials/_cli_coverage.html``), which is where
the operator already is when the question "is this endpoint even in the
catalog?" comes up.

Three routes back it, and the permission split between them is the point:

* the **counts and the CLI paths** are catalog metadata — table names, nothing
  from inside a device — so they render for anyone who may see the API hub;
* the **block text**, the **live ``show``** and the **capture** all hand over
  device configuration, so they carry ``Permission.BACKUP`` — the same
  permission that gates the config vault those dumps live in. Without that the
  section would be a way to read a device config without the permission that
  exists to gate exactly that (see ``views/backups.py``, every route).

No new transport: the capture calls ``backup.fetch_device_backup_auto(
method="ssh")``, already live since 2026-07-04, and the live read calls
``ssh_ops.run_command``, whose ``assert_readonly`` gate accepts ``show`` and
refuses everything that could mutate a box. Nothing here can write to an
appliance.
"""
from __future__ import annotations

from flask import flash, jsonify, redirect, request, url_for
from flask_login import current_user

from ..models import Permission, visible_appliance_or_404
from ..services import cli_coverage
from ..services.audit import log_action

# How many rows of each bucket reach the template. A 94-row "no block in this
# dump" list is not 94 findings, it is one fact repeated, and rendering all of
# it buries the 55 rows that ARE findings. The cap is stated in the payload and
# printed by the template — a silent truncation reads as "that is all there
# is", which is the one thing this section must never say.
ROW_CAP = 300


def _appliances_for(product: str):
    """Appliances of this product the current user may see, for the capture
    picker. ``visible_appliances`` already applies the ADOM scope and the
    maintenance filter, so this cannot offer a box the user cannot see."""
    from ..models import Appliance, visible_appliances

    return (visible_appliances().filter(Appliance.kind == product)
            .order_by(Appliance.name).all())


def context(product: str, *, page_endpoint: str, block_endpoint: str = "",
            capture_endpoint: str = "", live_endpoint: str = "",
            probe_endpoint: str = "", registry_save_endpoint: str = "") -> dict:
    """Everything ``partials/_cli_coverage.html`` needs for one product.

    The three action endpoints default to empty because a product with no CLI
    config tree (FortiAnalyzer, FortiAuthenticator) has no block to read, no
    dump to capture and no ``show`` to run — the section renders the reason and
    stops. The template only resolves them inside its supported branch, so an
    empty name is never handed to ``url_for``.
    """
    backup_id = request.args.get("dump", type=int)
    try:
        rep = cli_coverage.report(product, backup_id)
    except Exception as exc:  # noqa: BLE001 — the API hub must not 500 on this
        # A failure here is reported as a failure. An empty section and "the
        # parse blew up" look identical and mean opposite things.
        return {
            "cc_product": product, "cc_error": "%s: %s" % (type(exc).__name__, exc),
            "cc_report": None, "cc_can_read": False, "cc_appliances": [],
            "cc_block_endpoint": block_endpoint,
            "cc_capture_endpoint": capture_endpoint,
            "cc_live_endpoint": live_endpoint, "cc_page_endpoint": page_endpoint,
            "cc_probe_appliances": [], "cc_probe_endpoint": "",
            "cc_registry_save_endpoint": "",
            "cc_row_cap": ROW_CAP,
            # No diff means no provenance. ``None`` makes every badge on
            # the page render as "—"; a bare Provenance built from an
            # empty diff would render 500 rows of "no CLI block here",
            # which is a claim, not a blank.
            "cc_prov": None,
        }

    can_read = bool(current_user.is_authenticated
                    and current_user.can(Permission.BACKUP))
    return {
        "cc_product": product,
        "cc_error": "",
        "cc_report": rep,
        "cc_can_read": can_read,
        # Two lists on purpose. ``cc_appliances`` feeds the CAPTURE form, which
        # writes a device config into the vault, so it is empty without BACKUP.
        # ``cc_probe_appliances`` feeds the probe, which returns a verdict and a
        # row count -- strictly less than the console on this same page already
        # gives every logged-in user -- so it is not gated on BACKUP.
        "cc_appliances": _appliances_for(product) if can_read else [],
        "cc_probe_appliances": _appliances_for(product),
        "cc_block_endpoint": block_endpoint,
        "cc_capture_endpoint": capture_endpoint,
        "cc_live_endpoint": live_endpoint,
        "cc_page_endpoint": page_endpoint,
        "cc_probe_endpoint": probe_endpoint,
        "cc_registry_save_endpoint": registry_save_endpoint,
        "cc_row_cap": ROW_CAP,
        # Projected from the report ALREADY computed above — the menu
        # tree's badges cost no second parse of a 690 KB dump, and they
        # cannot disagree with the coverage table underneath them,
        # because both are the same diff.
        "cc_prov": cli_coverage.provenance_from(rep["diff"], rep.get("chosen")),
    }


# ---------------------------------------------------------------------------
# phase B — reading the element the API does not expose
# ---------------------------------------------------------------------------

def block_payload(product: str):
    """JSON: the scrubbed CLI text of one block out of one stored dump.

    ``path`` is taken from the report the caller is looking at, and it is
    resolved through :func:`cli_coverage.extract_block`, which only ever
    returns a block that EXISTS in that dump — so an arbitrary string cannot
    address anything else, and a path that is not a block comes back empty
    rather than as a slice of someone else's configuration.
    """
    backup_id = request.args.get("dump", type=int)
    path = (request.args.get("path") or "").strip()
    if not backup_id or not path:
        return jsonify({"ok": False, "error": "dump and path are required"}), 400

    text, rec = cli_coverage.read_dump(backup_id)
    if not text:
        return jsonify({"ok": False,
                        "error": rec.get("reason") or "that dump is not readable"}), 404
    # The dump has to belong to the product whose page is asking. Without this
    # the FortiWeb hub could render a FortiADC config, which is the ADOM
    # isolation this app enforces everywhere else (product_scope).
    if rec.get("product") != product:
        return jsonify({"ok": False,
                        "error": "that dump is %s evidence, not %s"
                                 % (rec.get("product") or "unlabelled", product)}), 403

    body = cli_coverage.extract_block(text, path)
    if not body:
        return jsonify({"ok": False,
                        "error": "no such block in this dump: %r" % path[:120]}), 404
    log_action("cli_coverage.read_block", target=rec.get("appliance") or "",
               extra={"product": product, "path": path, "dump": backup_id})
    return jsonify({"ok": True, "path": path, "text": body,
                    "device": rec.get("appliance") or "",
                    "captured": rec.get("created_at") or "",
                    "firmware": rec.get("firmware") or ""})


def live_payload(product: str):
    """JSON: ``show <path>`` run against a live appliance, right now.

    A stored dump answers "what did this box look like when we captured it".
    For an element the REST API does not expose, that is often not the question
    — so this runs the read against the device. ``show`` is already an allowed
    verb in :func:`app.services.ssh_ops.assert_readonly`; the command is built
    from the block path the report produced, and the gate re-validates it, so a
    write verb cannot be smuggled through the ``path`` parameter.
    """
    appliance_id = request.form.get("appliance_id", type=int)
    path = (request.form.get("path") or "").strip()
    if not appliance_id or not path:
        return jsonify({"ok": False, "error": "appliance and path are required"}), 400

    appliance = visible_appliance_or_404(appliance_id)
    if getattr(appliance, "kind", "") != product:
        return jsonify({"ok": False, "error": "that appliance is not a %s" % product}), 403

    from ..services import ssh_ops
    try:
        out = ssh_ops.run_command(appliance, "show " + path, timeout=20.0)
    except ssh_ops.ReadOnlyViolation as exc:
        return jsonify({"ok": False, "error": "refused: %s" % exc}), 400
    except Exception as exc:  # noqa: BLE001 — uniform surface for the console
        return jsonify({"ok": False, "error": "%s: %s" % (type(exc).__name__, exc)}), 502

    log_action("cli_coverage.live_show", target=appliance.name,
               extra={"product": product, "path": path})
    return jsonify({"ok": True, "path": path, "device": appliance.name,
                    "text": cli_coverage.scrub_block(out or "")})


def probe_payload(product: str):
    """JSON: which of a CLI block's candidate REST paths the device actually serves.

    This is the only honest way to promote a CLI-only finding into the catalog.
    The catalog is what every service resolves names through
    (``loader.resolve``), so writing a DERIVED path into it would put a guessed
    URL behind a friendly key and the failure would surface later, somewhere
    else, as a phantom endpoint.

    Verdicts come from :func:`rediscovery.probe_endpoint` — the same three the
    sweep and the reconciler already act on. ``login_required`` only, and NOT
    ``Permission.BACKUP``: this returns a verdict and a row COUNT, never row
    content, and the console two panels to the left already lets the same user
    GET any path they like. Gating a strictly smaller read harder than the
    bigger one next to it would be theatre.
    """
    appliance_id = request.form.get("appliance_id", type=int)
    path = (request.form.get("path") or "").strip()
    if not appliance_id or not path:
        return jsonify({"ok": False, "error": "appliance and path are required"}), 400

    appliance = visible_appliance_or_404(appliance_id)
    if getattr(appliance, "kind", "") != product:
        return jsonify({"ok": False, "error": "that appliance is not a %s" % product}), 403

    candidates = cli_coverage.candidate_urns(product, path)
    if not candidates:
        return jsonify({"ok": False,
                        "error": "no REST path can be derived from %r" % path[:120]}), 400

    from ..services import rediscovery
    results = []
    for urn in candidates:
        try:
            rows, verdict, detail = rediscovery.probe_endpoint(appliance, urn)
        except Exception as exc:  # noqa: BLE001 — one candidate never sinks the probe
            rows, verdict, detail = [], "error", "%s: %s" % (type(exc).__name__, exc)
        results.append({"urn": urn, "verdict": verdict, "rows": len(rows),
                        "detail": (detail or "")[:200]})

    log_action("cli_coverage.probe", target=appliance.name,
               extra={"product": product, "path": path,
                      "served": [r["urn"] for r in results if r["verdict"] == "ok"]})
    return jsonify({
        "ok": True, "path": path, "device": appliance.name,
        "name": cli_coverage.catalog_name_for(path),
        "candidates": results,
        # An ``absent`` verdict from the device is the useful negative: it says
        # the path does not exist, which is not the same as the probe failing.
        "served": [r["urn"] for r in results if r["verdict"] == "ok"],
        "capped": len(candidates) >= cli_coverage.MAX_CANDIDATES,
    })


def capture(product: str, page_endpoint: str):
    """Capture a fresh CLI dump into the vault, then come back to the section.

    This is the "also check over SSH when you scan the API" half of the ask,
    made an explicit operator action rather than a silent addition to the REST
    sweep. Reason: ``show full-configuration`` is a single SSH session that
    reads for up to 300 s, and folding that into ``rediscovery`` would triple
    the duration of every sweep — including the ones that run inside inventory
    apply — and would let an SSH failure sink a REST sweep that had already
    succeeded.
    """
    appliance_id = request.form.get("appliance_id", type=int)
    appliance = visible_appliance_or_404(appliance_id)
    if getattr(appliance, "kind", "") != product:
        flash("%s is not a %s." % (appliance.name, product), "danger")
        return redirect(url_for(page_endpoint))

    from ..services import backup as backup_svc
    try:
        row = backup_svc.fetch_device_backup_auto(
            appliance, created_by=getattr(current_user, "username", ""),
            method="ssh")
    except Exception as exc:  # noqa: BLE001 — the reason is the useful part
        flash("CLI capture from %s failed: %s: %s"
              % (appliance.name, type(exc).__name__, exc), "danger")
        return redirect(url_for(page_endpoint))

    log_action("cli_coverage.capture", target=appliance.name,
               extra={"product": product, "backup_id": row.id})
    flash("Captured %d KB of CLI configuration from %s — the coverage diff below "
          "now runs against it." % (row.size_kb(), appliance.name), "success")
    return redirect(url_for(page_endpoint, dump=row.id))


__all__ = ["ROW_CAP", "context", "block_payload", "live_payload",
           "probe_payload", "capture"]

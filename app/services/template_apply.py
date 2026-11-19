"""The one template-apply engine: Template Library > Apply and Operations >
Automation > Mass Deploy both go through here (2026-10-24).

Two deploy paths would drift apart in their safeguards, so the steps live once:

1. targets = the visible devices named (a hand-made id is refused);
2. the body is flattened to push items and ``{{ variables }}`` are rendered per
   device from its binding (a device left without a value is BLOCKED);
3. secret fields are never sent from the template (``services.secret_mask``):
   dropped unless a value is typed at apply time;
4. a device of a product the bulk runner cannot write is BLOCKED (it writes
   FortiWeb REST objects through ``FortiWebOps``);
5. with ``respect_pins`` (a fleet rollout, and every Mass Deploy) a device bound
   to ANOTHER version of the family is BLOCKED: its binding says which version
   it runs, and changing that is done on the binding, not by a push;
6. the firmware check (``template_compat``) — preview shows it, ``start``
   enforces it (approver override with a reason, as before);
7. the live write runs as the canary-gated background job (``services.bulk``).
"""
from __future__ import annotations

from typing import Any

from ..models import Appliance, Template, visible_appliances
from . import secret_mask
from . import template_bindings as tb
from . import template_compat as tc
from .bulk import BulkRunner, iter_push_items

#: Device kinds the bulk runner writes (``services.bulk`` -> ``FortiWebOps``).
SUPPORTED_KINDS = ("fortiweb",)


def parse_ids(values) -> list[int]:
    out: list[int] = []
    for v in values or []:
        try:
            out.append(int(v))
        except (TypeError, ValueError):
            continue
    return out


def pin_state(row: Template, appliance_id: int) -> dict | None:
    """``None`` when ``appliance_id`` may take ``row``; else why not: its
    binding follows another version of the family."""
    for b in tb.for_template(row):
        if b.appliance_id != appliance_id:
            continue
        t = tb.resolve(b)
        if t is not None and t.id == row.id:
            return None
        if b.pinned_version:
            return {"reason": "pinned to v%s of %r" % (b.pinned_version, row.name),
                    "pinned_version": b.pinned_version}
        return {"reason": "its binding follows the newest approved version of %r%s"
                          % (row.name, " (v%s)" % t.version if t is not None else ""),
                "pinned_version": None}
    return None


class Plan:
    """Everything one apply needs, computed once for preview and for start."""

    def __init__(self, row: Template, device_ids, *, secrets: dict | None = None,
                 respect_pins: bool = False, fleet: bool | None = None):
        self.row = row
        self.device_ids = [int(d) for d in device_ids]
        # A fleet rollout needs an approval validated for every target build.
        # The library's single-device apply is the "try it on one box" path and
        # is exempt; Mass Deploy passes ``fleet=True`` even for one device.
        self.fleet = len(self.device_ids) > 1 if fleet is None else bool(fleet)
        visible = {a.id: a for a in visible_appliances()
                   .filter(Appliance.id.in_(self.device_ids)).all()} if self.device_ids else {}
        self.unknown = [d for d in self.device_ids if d not in visible]
        self.targets = [visible[d] for d in self.device_ids if d in visible]
        names = {a.id: a.name for a in self.targets}

        raw_items = iter_push_items(row.body_dict)
        self.secret_fields = secret_mask.secret_fields(raw_items)
        self.items, self.secrets = secret_mask.prepare(raw_items, secrets)
        bodies, self.missing_vars = tb.render_for_devices(row, self.device_ids)
        self.items_by_device = {aid: secret_mask.prepare(iter_push_items(b), secrets)[0]
                                for aid, b in bodies.items()}

        blocks = ['%s: no value for %s (set it on the device binding)'
                  % (names.get(aid, aid), ', '.join(m))
                  for aid, m in sorted(self.missing_vars.items())]
        self.unsupported = {a.id: a.kind for a in self.targets
                            if (a.kind or '') not in SUPPORTED_KINDS}
        blocks += ['%s: SATOM cannot push templates to a %s (the bulk deploy '
                   'writes FortiWeb objects only)' % (names[aid], kind or 'device')
                   for aid, kind in sorted(self.unsupported.items())]
        self.pinned: dict[int, dict] = {}
        if respect_pins:
            for a in self.targets:
                st = pin_state(row, a.id)
                if st:
                    self.pinned[a.id] = st
            blocks += ['%s: %s — change its binding to deploy v%s'
                       % (names[aid], st['reason'], row.version)
                       for aid, st in sorted(self.pinned.items())]
        self.blocks = blocks

    # -- views ---------------------------------------------------------------
    def preview(self) -> dict[str, Any]:
        """The dry-run JSON (no device is contacted). Secrets masked."""
        compat = tc.for_appliances(self.row, self.targets, require_validated=self.fleet)
        if self.blocks:
            compat['blocked'] = True
            compat['blocks'] = self.blocks + list(compat.get('blocks') or [])
        compat['variables_missing'] = {str(k): v for k, v in self.missing_vars.items()}
        preview = BulkRunner(self.items, skips=compat.get('skips'),
                             items_by_device=self.items_by_device).preview(self.device_ids)
        return {'item_count': len(self.items), 'preview': secret_mask.mask(preview),
                'compat': compat, 'secrets': self.secrets,
                'secret_fields': [{k: f[k] for k in ('key', 'label', 'field')}
                                  for f in self.secret_fields]}

    def enforce(self, user, override_reason: str, action: str):
        """``(allowed, compat)``. Our own blocks are not overridable: there is
        no value to write, no runner for the product, or a binding says no."""
        if self.blocks:
            return False, {'blocked': True, 'blocks': list(self.blocks),
                           'overridden': False, 'skips': {}}
        return tc.enforce(self.row, self.targets, user=user,
                          override_reason=override_reason,
                          require_validated=self.fleet, action=action)

    def start(self, flask_app, *, by: str, compat: dict, meta: dict | None = None,
              title: str = '', audit_action: str = 'template.apply', on_done=None) -> dict:
        from .bulk import start_apply_job
        row = self.row
        return start_apply_job(
            flask_app,
            title=title or f'Apply "{row.name}" v{row.version} to '
                           f'{len(self.device_ids)} device(s)',
            items=self.items, device_ids=self.device_ids, by=by,
            meta={'template_id': row.id, 'kind': row.kind, 'name': row.name,
                  'compat_overridden': compat.get('overridden'),
                  'secrets_sent': self.secrets['sent'], **(meta or {})},
            audit_action=audit_action, audit_target=f'{row.kind}/{row.name}',
            skips=compat.get('skips'), items_by_device=self.items_by_device or None,
            on_done=on_done)

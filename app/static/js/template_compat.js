/* Firmware stamp + compatibility verdict renderers for templates.
 *
 * Shared by the Template Library and the per-section configuration page so
 * both show the SAME verdict for the same template (services.template_compat
 * is the only author of the verdict; this file only draws it). Colours are the
 * .fw-badge-* set, calibrated against the light theme.
 */
(function (root) {
  'use strict';

  function esc(v) {
    var d = document.createElement('div');
    d.textContent = (v === null || v === undefined) ? '' : String(v);
    return d.innerHTML;
  }

  function badge(cls, text, title) {
    return '<span class="fw-badge fw-badge-' + cls + '"' +
      (title ? ' title="' + esc(title) + '"' : '') + '>' + esc(text) + '</span>';
  }

  function verdictBadge(s) {
    if (!s) return badge('secondary', 'unchecked');
    if (s.blocking) return badge('danger', 'does not fit');
    if (s.state === 'ok' || s.state === 'same') return badge('success', s.state);
    return badge('warning', s.state || 'unchecked', s.reason || '');
  }

  /** One-line stamp: build, API, provenance, source appliance. */
  function stamp(t) {
    if (!t.source_firmware) {
      return badge('warning', 'no firmware recorded',
        'Saved before builds were recorded: fields are checked against each target, renames cannot be.');
    }
    return badge('secondary', 'FW ' + t.source_firmware) + ' API ' + esc(t.api_version || '—') +
      ' · ' + esc(t.provenance || '') +
      (t.source_appliance ? ' from <strong>' + esc(t.source_appliance) + '</strong>' : '') +
      (t.adapted_from_id ? ' · adapted from #' + esc(t.adapted_from_id) : '');
  }

  function findings(s) {
    var out = [];
    Object.keys(s.dropped || {}).forEach(function (k) {
      out.push(esc(k) + ': not served — ' + esc((s.dropped[k] || []).join(', ')));
    });
    Object.keys(s.renamed || {}).forEach(function (k) {
      (s.renamed[k] || []).forEach(function (r) {
        out.push(esc(k) + ': renamed ' + esc(r.from) + ' → ' + esc(r.to));
      });
    });
    (s.absent_keys || []).forEach(function (k) { out.push(esc(k) + ': endpoint not served'); });
    return out;
  }

  /** {build: summary} as a table (self-check, validations, /check reports). */
  function buildsTable(map, emptyText) {
    var keys = Object.keys(map || {});
    if (!keys.length) return '<div class="text-muted">' + esc(emptyText || 'None.') + '</div>';
    var h = '<table class="fw-table" style="margin-bottom:0;font-size:12.5px;"><thead><tr>' +
      '<th>Build</th><th>Verdict</th><th>Findings</th><th>By / when</th></tr></thead><tbody>';
    keys.forEach(function (b) {
      var s = map[b] || {};
      var f = findings(s);
      h += '<tr><td>' + esc(b) + '</td><td>' + verdictBadge(s) + '</td><td>' +
        (f.length ? f.join('<br>') : (s.reason ? esc(s.reason) : '—')) + '</td><td>' +
        esc(s.by || '') + ' ' + esc((s.at || '').replace('T', ' ').substring(0, 16)) + '</td></tr>';
    });
    return h + '</tbody></table>';
  }

  /** Apply-preview block: per-device verdicts + override box when blocked. */
  function applyPanel(c, canOverride) {
    if (!c) return '';
    var h = '<div class="fw-card mt-2 mb-2"><div class="fw-card-header d-flex justify-content-between align-items-center">' +
      '<span class="fw-card-title"><i class="bi bi-shield-check me-1"></i>Firmware compatibility</span>' +
      (c.blocked ? badge('danger', 'blocked') : badge('success', 'no blocking finding')) +
      '</div><div class="fw-card-body" style="font-size:12.5px;">' +
      '<div class="mb-1">' + (c.source_firmware ? 'Written for <strong>' + esc(c.source_firmware) + '</strong>'
        : badge('warning', 'no firmware recorded')) + '</div>' +
      '<table class="fw-table" style="margin-bottom:0;"><thead><tr><th>Device</th><th>Build</th><th>Verdict</th><th>Detail</th></tr></thead><tbody>';
    (c.devices || []).forEach(function (d) {
      h += '<tr><td>' + esc(d.appliance) + '</td><td>' + esc(d.build || '—') +
        (d.validated ? ' <i class="bi bi-patch-check text-success" title="Validated at approval"></i>' : '') +
        '</td><td>' + (d.blocking ? badge('danger', 'blocks') : d.level === 'ok' ? badge('success', d.state) : badge('warning', d.state)) +
        '</td><td style="word-break:break-word;">' + esc(d.reason) + '</td></tr>';
    });
    h += '</tbody></table>';
    (c.warnings || []).forEach(function (w) {
      h += '<div class="text-muted mt-1"><i class="bi bi-exclamation-circle me-1"></i>' + esc(w) + '</div>';
    });
    if ((c.outside || []).length) {
      h += '<div class="text-muted mt-1"><i class="bi bi-eye-slash me-1"></i>Not checked (outside the API sweep): ' +
        esc(c.outside.slice(0, 8).join(', ')) + (c.outside.length > 8 ? ' … (+' + (c.outside.length - 8) + ')' : '') + '</div>';
    }
    if (c.blocked) {
      h += canOverride
        ? '<label class="fw-form-label mt-2" for="ap-override">Override reason (required to proceed; audited)</label>' +
          '<textarea class="form-control" id="ap-override" name="override_reason" rows="2" ' +
          'placeholder="Why is it safe to write this body to these builds?"></textarea>'
        : '<div class="fw-alert fw-alert-danger mt-2 mb-0">Applying is refused. Adapt the template to the target build, ' +
          'or ask an approver (Approve templates permission) to override with a reason.</div>';
    }
    return h + '</div></div>';
  }

  /** Adapt preview: what a new version would rename / remove. */
  function adaptPlan(p) {
    var h = '<div style="font-size:12.5px;">Target <strong>' + esc(p.target_version) + '</strong> — ' +
      esc(p.changes) + ' change(s).';
    Object.keys(p.renames || {}).forEach(function (k) {
      Object.keys(p.renames[k]).forEach(function (f) {
        h += '<div>' + esc(k) + ': rename ' + esc(f) + ' → ' + esc(p.renames[k][f]) + '</div>';
      });
    });
    Object.keys(p.drops || {}).forEach(function (k) {
      h += '<div>' + esc(k) + ': remove ' + esc((p.drops[k] || []).join(', ')) + '</div>';
    });
    if ((p.absent_keys || []).length) {
      h += '<div class="text-danger">Not served at all (cannot be adapted): ' + esc(p.absent_keys.join(', ')) + '</div>';
    }
    if ((p.unmeasured || []).length) {
      h += '<div class="text-muted">No field evidence on that build for: ' + esc(p.unmeasured.join(', ')) +
        ' — these are left as they are.</div>';
    }
    return h + '</div>';
  }

  root.TplCompat = {esc: esc, stamp: stamp, buildsTable: buildsTable,
                    applyPanel: applyPanel, adaptPlan: adaptPlan, verdictBadge: verdictBadge};
})(window);

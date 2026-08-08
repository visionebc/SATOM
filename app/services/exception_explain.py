"""Render a carve-out as something a non-specialist can approve or refuse.

A drafted exception used to reach the operator as a JSON blob in a textarea.
That is a fine representation for the machine that will POST it and a poor one
for the person who has to say yes: it shows the payload and hides the three
things the decision actually turns on — **where** the rule lands, **how wide**
it is, and **what stops being inspected** once it exists.

So this module answers those three, from the same catalogues the rest of the
product uses:

* *where* — the type's category and GUI group from :mod:`wpp_exceptions`, plus
  the FortiWeb object the row is written into, resolved through
  :mod:`exception_inject` (a dedicated named container, an inline sub-policy,
  the signature set, or a custom rule). That last one is read from the registry
  mapping that performs the write, so the explanation cannot drift away from
  what actually happens.
* *how wide* — a base breadth per type, then **widened by the payload**. A
  per-signature exception is narrow only if it names an element to match; with
  the match left open it is a signature disabled by another name, and the
  panel says so rather than calling it narrow because its type usually is.
* *what it costs* — one sentence per type on which inspection stops, and one on
  what is still enforced. Operators approve carve-outs they understand; the
  ones they do not understand get approved anyway, later, under pressure.

Nothing here talks to a device and nothing here decides anything. It is the
label on the box.
"""
from __future__ import annotations

from . import wpp_exceptions as store

NARROW, MODERATE, WIDE = 'narrow', 'moderate', 'wide'

BREADTH_LABEL = {
    NARROW: 'Narrow — targeted at what you named',
    MODERATE: 'Moderate — applies to a class of requests',
    WIDE: 'Wide — turns an inspection off for everything on this profile',
}

#: ``exc_type`` → (what stops being checked, what remains enforced).
EFFECTS: dict[str, tuple[str, str]] = {
    'http_constraint_exception_item': (
        'HTTP protocol-constraint checks — header and URL length limits, '
        'malformed syntax, illegal characters — are skipped for requests that '
        'match this scope.',
        'Signature detection, bot mitigation and every other module still '
        'inspect these requests normally.'),
    'allow_method_exception_item': (
        'The HTTP method restriction is lifted for requests matching this '
        'scope, so verbs the policy normally rejects are allowed through.',
        'The request is still inspected by signatures and the rest of the '
        'profile — only the method check is bypassed.'),
    'geo_ip_exception_member_item': (
        'The named address or range is exempted from geographic blocking and '
        'reaches the site regardless of the country it maps to.',
        'Geo blocking still applies to every other source address.'),
    'syntax_exception_item': (
        'Syntax-based detection (the semantic SQL/XSS parser) stops examining '
        'the element you named.',
        'Signature-based detection of the same attack classes still runs.'),
    'bot_exception_element_item': (
        'Bot mitigation stops scoring the element you named, so clients are no '
        'longer challenged or throttled on that basis.',
        'Attack signatures and protocol constraints are unaffected.'),
    'http_header_security_exception_item': (
        'HTTP header security checks are skipped for URLs matching this scope.',
        'All other inspection of those requests continues.'),
    'cookie_security_exception_item': (
        'The named cookie is no longer signed or encrypted by FortiWeb, so it '
        'can be modified by the client without being rejected.',
        'Other cookies keep their protection.'),
    'url_enc_exc_item': (
        'URL encryption is not applied to the matching URLs, so they appear in '
        'plain form to clients.',
        'The rest of the URL-encryption rule is unchanged.'),
    'link_cloak_exc_item': (
        'Link cloaking is not applied to the matching URLs.',
        'The rest of the link-cloaking rule is unchanged.'),
    'file_exception_item': (
        'File security checks are skipped for the named file, so uploads or '
        'downloads of it are not scanned by that module.',
        'Other files are still checked.'),
    'signature_filter_item': (
        'The named signature is skipped when the element you specified matches '
        '— and only then.',
        'The same signature still fires for every other request, and every '
        'other signature is untouched.'),
    'signature_disable_item': (
        'The signature is switched OFF for this entire profile: every request, '
        'every host, every URL behind it.',
        'Other signatures continue to run — but nothing this signature detects '
        'will be detected here again.'),
    'signature_alert_only_item': (
        'The signature no longer blocks anywhere on this profile; matches are '
        'logged and the request is allowed through.',
        'You keep visibility — the log entries continue — but not enforcement.'),
    'signature_subclass_disable_item': (
        'Every signature in the sub-class is switched off for this profile, not '
        'just the one that fired.',
        'Signatures outside the sub-class still run.'),
    'signature_class_action': (
        'The action for an entire main class of signatures is overridden across '
        'this profile.',
        'Detection still happens; what changes is what FortiWeb does about it.'),
    'signature_group_rule_condition': (
        'A match condition is added to a custom rule, changing when that rule '
        'considers a request to be an attack.',
        'Only the custom rule is affected; the standard signature set is not.'),
}

#: Base breadth by type, before the payload is taken into account.
_BASE_BREADTH: dict[str, str] = {
    'signature_disable_item': WIDE,
    'signature_alert_only_item': WIDE,
    'signature_subclass_disable_item': WIDE,
    'signature_class_action': WIDE,
    'signature_filter_item': NARROW,
    'signature_group_rule_condition': NARROW,
    'http_constraint_exception_item': NARROW,
    'allow_method_exception_item': NARROW,
    'http_header_security_exception_item': NARROW,
    'url_enc_exc_item': NARROW,
    'link_cloak_exc_item': NARROW,
    'file_exception_item': NARROW,
    'cookie_security_exception_item': MODERATE,
    'geo_ip_exception_member_item': MODERATE,
    'syntax_exception_item': MODERATE,
    'bot_exception_element_item': MODERATE,
}

#: Fields that PIN a carve-out to something specific. A type whose narrowness
#: depends on them is only as narrow as the ones actually filled in.
_PINNING: dict[str, tuple[str, ...]] = {
    'signature_filter_item': ('match-target', 'value', 'ip', 'http-method'),
    'http_constraint_exception_item': ('request-file', 'host', 'source-ip'),
    'allow_method_exception_item': ('request-file', 'host'),
    'http_header_security_exception_item': ('request-url-pattern', 'host'),
    'url_enc_exc_item': ('url-pattern',),
    'link_cloak_exc_item': ('url-pattern',),
    'file_exception_item': ('file-name',),
    'syntax_exception_item': ('value', 'name'),
    'bot_exception_element_item': ('value', 'name'),
    'signature_group_rule_condition': ('value',),
}

#: How the row is written, in words. Keyed on ``ExcRest.parent_logical`` groups
#: rather than spelled per type, because the write mechanism is what differs.
_CONTAINER_WORDS = {
    'signature': ('the signature set',
                  'The entry is added to the signature set the profile uses. '
                  'Every Server Policy bound to a profile that uses this set '
                  'sees the change.'),
    'signature_group_rule': ('the custom rule',
                             'The condition is added to an existing custom '
                             'rule. Custom rules are shared objects — check '
                             'which profiles reference this one.'),
}


def _pinned(exc_type: str, payload: dict) -> list[str]:
    return [k for k in _PINNING.get(exc_type, ())
            if str((payload or {}).get(k, '')).strip() not in ('', 'disable')]


def breadth(exc_type: str, payload: dict) -> tuple[str, str]:
    """(level, why). Widened when the payload leaves its scoping fields empty."""
    base = _BASE_BREADTH.get(exc_type, MODERATE)
    keys = _PINNING.get(exc_type, ())
    if not keys:
        return base, ''
    hit = _pinned(exc_type, payload)
    if hit:
        return base, 'Pinned by: ' + ', '.join(hit) + '.'
    if base == NARROW:
        return MODERATE, (
            'This type is normally narrow, but none of its scoping fields '
            '(%s) are filled in — so it applies far more broadly than the type '
            'suggests.' % ', '.join(keys))
    return base, ''


def _field_rows(exc_type: str, payload: dict) -> list[dict]:
    """Payload as labelled rows, in catalogue order, required ones marked.

    Order comes from :func:`wpp_exceptions.fields_for` — the same source the
    manual authoring form renders — so the review card and the form cannot
    disagree about what a field is called.
    """
    payload = payload or {}
    required = set((getattr(store, 'REQUIRED_FIELDS', {}) or {}).get(exc_type, ()))
    try:
        specs = store.fields_for(exc_type)
    except Exception:  # noqa: BLE001 — an unmodelled type still shows its payload
        specs = []
    rows, seen = [], set()
    for f in specs:
        key = f.get('key')
        if key is None or key not in payload:
            continue
        seen.add(key)
        rows.append({'key': key, 'label': f.get('label') or key,
                     'value': payload.get(key), 'required': key in required,
                     'known': True})
    for key in payload:
        if key not in seen:
            # A key the catalogue does not model is shown, flagged. Hiding it
            # would let a payload carry a field the reviewer never saw.
            rows.append({'key': key, 'label': key, 'value': payload[key],
                         'required': key in required, 'known': False})
    return rows


def explain(exc_type: str, payload: dict, *, wpp: str = '',
            policy: str = '') -> dict:
    """A carve-out described for a human. Never raises."""
    payload = dict(payload or {})
    t = store.type_for(exc_type) or {}
    category = store.category_for(exc_type)
    is_sig = category == store.CAT_SIGNATURE

    from . import exception_inject
    rest = exception_inject.rest_for(exc_type)
    if rest is None:
        container, container_note = '', ''
        injectable = False
    else:
        injectable = True
        if rest.parent_logical in _CONTAINER_WORDS:
            container, container_note = _CONTAINER_WORDS[rest.parent_logical]
        elif rest.inline:
            container = 'the %s sub-policy itself' % rest.parent_logical.replace('_', ' ')
            container_note = ('The entry lives on an existing sub-policy of the '
                              'Web Protection Profile — no new object is created.')
        else:
            container = 'a dedicated %s object' % rest.parent_logical.replace('_', ' ')
            container_note = ('The entry goes into a named exception container, '
                              'which the profile then references. The container '
                              'can be reused by other profiles, so check what '
                              'else points at it before adding to an existing one.')

    path = []
    if policy:
        path.append('Server Policy "%s"' % policy)
    if wpp:
        path.append('Web Protection Profile "%s"' % wpp)
    if is_sig:
        path.append('Known Attacks — Signatures')
    elif t.get('group'):
        path.append(t['group'])
    if t.get('label'):
        path.append(t['label'])

    level, why = breadth(exc_type, payload)
    stops, keeps = EFFECTS.get(
        exc_type,
        ('This carve-out changes how the named inspection treats matching '
         'requests.', 'Everything not named here is still inspected.'))

    return {
        'type_key': exc_type,
        'type_label': t.get('label') or exc_type,
        'group': t.get('group') or '',
        'category': category,
        'category_label': ('Signature customisation — this is a change to how a '
                           'KNOWN ATTACK rule behaves'
                           if is_sig else
                           'WAF exception — this is a carve-out from a '
                           'protection module'),
        'gui_path': path,
        'container': container,
        'container_note': container_note,
        'injectable': injectable,
        'breadth': level,
        'breadth_label': BREADTH_LABEL[level],
        'breadth_why': why,
        'stops': stops,
        'keeps': keeps,
        'fields': _field_rows(exc_type, payload),
        'unknown_fields': [r['key'] for r in _field_rows(exc_type, payload)
                           if not r['known']],
        'missing_required': [
            k for k in (getattr(store, 'REQUIRED_FIELDS', {}) or {}).get(exc_type, ())
            if str(payload.get(k, '')).strip() == ''],
    }

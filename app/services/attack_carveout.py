"""Build a carve-out from the fields of an attack-log entry the operator picked.

The AI path drafts a carve-out only when it judges the block a false positive at
acceptable risk — correct as a default, and useless in the case operators hit
most: *"I can see it is a real attack pattern, but this one parameter on this
one URL from our own integration partner has to go through."* That judgement is
the operator's to make, and before this module they had no way to act on it here
— the panel offered a button or nothing.

So: pick the fields of the entry that describe what must be allowed, pick the
type of carve-out, and SATOM assembles a FortiWeb-valid payload from **the entry
as the device reported it**. Never from values the browser sent back — the same
rule the AI path already follows, for the same reason. A page that lets a client
supply the "evidence" lets a client author the exception.

Two things this module refuses to paper over:

* **A signature exception matches ONE element.** FortiWeb's ``filter_list`` row
  has a single ``match-target``. Selecting a URL *and* a client IP cannot mean
  "both" — so the highest-precision one is used and the rest are reported as
  needing their own entry, rather than being quietly dropped into a payload that
  matches less than the operator believes.
* **A field that cannot scope a type is said out loud.** Offering every log
  field for every carve-out type would produce payloads FortiWeb rejects, at the
  end of the flow, with a device error the operator cannot map back to a choice
  they made at the start.
"""
from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit


@dataclass(frozen=True)
class Scoper:
    """One log field that can narrow one carve-out type."""

    row_key: str
    label: str
    note: str


def _path_of(url: str) -> str:
    """The path part of a logged URL, always rooted.

    FortiWeb URL patterns are matched against the path; carrying the query
    string into ``request-file`` produces a pattern that matches only the exact
    parameter values seen once, which reads as "narrow" and behaves as "never
    matches again".
    """
    raw = str(url or '').strip()
    if not raw:
        return ''
    parts = urlsplit(raw if '://' in raw else 'http://x' + (
        raw if raw.startswith('/') else '/' + raw))
    return parts.path or '/'


def _basename(url: str) -> str:
    return _path_of(url).rsplit('/', 1)[-1]


# --------------------------------------------------------------------------- #
#  Which log fields can scope which carve-out type, and how                    #
# --------------------------------------------------------------------------- #
#: ``exc_type`` → ordered scopers. The order is the order the panel offers them,
#: most precise first.
SCOPERS: dict[str, list[Scoper]] = {
    'http_constraint_exception_item': [
        Scoper('http_url', 'URL',
               'Limits the exception to this path. The query string is not part '
               'of the pattern — a pattern carrying one request\'s parameters '
               'would match that request and nothing else.'),
        Scoper('http_host', 'Host',
               'Limits the exception to this site, which matters when the '
               'profile serves several.'),
        Scoper('src', 'Source IP',
               'Limits the exception to this client address.'),
    ],
    'allow_method_exception_item': [
        Scoper('http_url', 'URL', 'Only this path may use the extra method.'),
        Scoper('http_host', 'Host', 'Only this site.'),
    ],
    'geo_ip_exception_member_item': [
        Scoper('src', 'Source IP',
               'Exempts exactly this address from geographic blocking.'),
    ],
    'signature_filter_item': [
        Scoper('http_url', 'URL',
               'The signature is skipped only on this path — the most precise '
               'element available.'),
        Scoper('http_host', 'Host', 'The signature is skipped only on this site.'),
        Scoper('src', 'Source IP',
               'The signature is skipped only for this client. Prefer a URL: an '
               'address can be spoofed or reassigned, a path cannot.'),
        Scoper('http_method', 'HTTP Method',
               'The signature is skipped only for this verb.'),
    ],
    'syntax_exception_item': [
        Scoper('http_url', 'URL', 'Syntax detection is skipped on this path.'),
        Scoper('http_host', 'Host', 'Syntax detection is skipped on this site.'),
    ],
    'bot_exception_element_item': [
        Scoper('http_url', 'URL', 'Bot scoring is skipped on this path.'),
        Scoper('http_host', 'Host', 'Bot scoring is skipped on this site.'),
    ],
    'http_header_security_exception_item': [
        Scoper('http_url', 'URL', 'Header checks are skipped on this path.'),
        Scoper('http_host', 'Host', 'Header checks are skipped on this site.'),
    ],
    'url_enc_exc_item': [
        Scoper('http_url', 'URL', 'This path is not URL-encrypted.'),
    ],
    'link_cloak_exc_item': [
        Scoper('http_url', 'URL', 'This path is not link-cloaked.'),
    ],
    'file_exception_item': [
        Scoper('http_url', 'File name (from the URL)',
               'The file named at the end of the path is exempted.'),
    ],
    'signature_group_rule_condition': [
        Scoper('http_url', 'URL', 'The condition matches this path.'),
        Scoper('http_host', 'Host', 'The condition matches this host.'),
    ],
    # Types whose subject IS the signature and which take no element scope.
    'signature_disable_item': [],
    'signature_alert_only_item': [],
    'signature_subclass_disable_item': [],
    'signature_class_action': [],
    'cookie_security_exception_item': [],
}

#: For a signature exception FortiWeb matches ONE element per row. When the
#: operator selects several, this is the order of precision that decides which
#: one the row uses; the rest are reported, never silently discarded.
_SIG_PRECEDENCE = ('http_url', 'http_host', 'http_method', 'src')

_SIG_ELEMENT = {
    'http_url': ('URI', 'value'),
    'http_host': ('HOST', 'value'),
    'http_method': ('HTTP_METHOD', 'http-method'),
    'src': ('CLIENT_IP', 'ip'),
}


def scopers_for(exc_type: str) -> list[dict]:
    """The log fields that can narrow *exc_type*, for the picker."""
    return [{'row_key': s.row_key, 'label': s.label, 'note': s.note}
            for s in SCOPERS.get(exc_type, [])]


def _val(row: dict, key: str) -> str:
    v = (row or {}).get(key)
    s = '' if v is None else str(v).strip()
    return '' if s in ('', 'N/A') else s


# --------------------------------------------------------------------------- #
#  Suggestion — which carve-out this entry actually calls for                  #
# --------------------------------------------------------------------------- #
#: Substrings of the entry's ``main_type`` → the carve-out type that addresses
#: it. Checked in order; a signature id present outranks all of them, because a
#: per-signature exception is the narrowest fix there is.
_TYPE_HINTS: list[tuple[str, str, str]] = [
    ('http protocol constraint', 'http_constraint_exception_item',
     'The block came from an HTTP protocol constraint, so the exception belongs '
     'to the HTTP Protocol Constraints module — not to a signature.'),
    ('http constraint', 'http_constraint_exception_item',
     'The block came from an HTTP protocol constraint.'),
    ('protocol', 'http_constraint_exception_item',
     'A protocol-level check produced this block.'),
    ('allow method', 'allow_method_exception_item',
     'The method was rejected by the Allow Method check, so the exception goes '
     'there.'),
    ('illegal method', 'allow_method_exception_item',
     'The method was rejected by the Allow Method check.'),
    ('geo', 'geo_ip_exception_member_item',
     'A geographic block produced this, so the fix is a Geo IP exemption for '
     'the source address.'),
    ('bot', 'bot_exception_element_item',
     'Bot mitigation produced this block.'),
    ('syntax', 'syntax_exception_item',
     'Syntax-based detection produced this block.'),
    ('cookie', 'cookie_security_exception_item',
     'Cookie security produced this block.'),
    ('file', 'file_exception_item', 'File security produced this block.'),
    ('custom', 'signature_group_rule_condition',
     'A custom rule produced this block, so the change belongs on that rule '
     'rather than in the standard signature set.'),
    ('signature', 'signature_filter_item',
     'A known-attack signature produced this block.'),
]


def suggest_types(row: dict) -> list[dict]:
    """Which carve-out types fit this entry, best first, each with its reason.

    This is the question a non-specialist cannot answer and must: a block from
    an HTTP protocol constraint is not fixed by a signature exception, and
    nothing on the log row says so in those words.
    """
    from . import wpp_exceptions as store

    main = _val(row, 'main_type').lower()
    sub = _val(row, 'sub_type').lower()
    hay = main + ' ' + sub
    out: list[dict] = []
    seen: set[str] = set()

    def _add(key, why, rank):
        if key in seen or store.type_for(key) is None:
            return
        seen.add(key)
        t = store.type_for(key)
        out.append({'exc_type': key, 'label': t['label'], 'group': t['group'],
                    'category': t['category'], 'why': why, 'rank': rank})

    if _val(row, 'signature_id'):
        _add('signature_filter_item',
             'This entry names signature %s, and a per-signature exception '
             'scoped to one element is the narrowest change that clears it.'
             % _val(row, 'signature_id'), 0)
    for needle, key, why in _TYPE_HINTS:
        if needle in hay:
            _add(key, why, 1)
    if not out:
        _add('signature_filter_item',
             'No module could be identified from the entry, so start from the '
             'narrowest option and widen only if it does not clear the block.', 2)
    # The wide ones are always reachable, always last, never recommended.
    if _val(row, 'signature_id'):
        _add('signature_alert_only_item',
             'Wider fallback: the signature stops blocking anywhere on this '
             'profile but keeps logging. Use only if a scoped exception cannot '
             'express the case.', 8)
        _add('signature_disable_item',
             'Widest option: the signature is off for the whole profile. This '
             'removes the detection entirely.', 9)
    return sorted(out, key=lambda d: d['rank'])


# --------------------------------------------------------------------------- #
#  Payload assembly                                                            #
# --------------------------------------------------------------------------- #
def build(row: dict, exc_type: str, selected: list[str]) -> dict:
    """Assemble a payload for *exc_type* from the *selected* fields of *row*.

    Returns ``{payload, used, ignored, warnings, errors}``. ``errors`` is a
    validation result, not an exception: a half-built carve-out with a clear
    reason beats a 500, and the operator can fix the selection and retry.
    """
    from . import wpp_exceptions as store

    row = row or {}
    exc_type = (exc_type or '').strip()
    selected = [s for s in (selected or []) if s]
    payload: dict = {}
    used: list[str] = []
    ignored: list[dict] = []
    warnings: list[str] = []

    if store.type_for(exc_type) is None:
        return {'payload': {}, 'used': [], 'ignored': [], 'warnings': [],
                'errors': ['"%s" is not a carve-out type SATOM knows.' % exc_type]}

    allowed = {s.row_key for s in SCOPERS.get(exc_type, [])}
    for key in selected:
        if key not in allowed:
            ignored.append({'row_key': key, 'why': (
                'A %s carve-out cannot be scoped by this field — FortiWeb has '
                'nowhere to put it.' % (store.type_for(exc_type)['label']))})

    picked = [k for k in selected if k in allowed and _val(row, k)]
    empty = [k for k in selected if k in allowed and not _val(row, k)]
    for key in empty:
        ignored.append({'row_key': key, 'why': (
            'The entry has no value for this field, so it cannot narrow '
            'anything.')})

    sig_id = _val(row, 'signature_id')

    # ── signature family ───────────────────────────────────────────────────
    if exc_type in ('signature_disable_item', 'signature_alert_only_item'):
        payload['signature_id'] = sig_id
    elif exc_type == 'signature_subclass_disable_item':
        payload['sub_class_id'] = _val(row, 'signature_subclass')
    elif exc_type == 'signature_filter_item':
        payload['signature_id'] = sig_id
        chosen = next((k for k in _SIG_PRECEDENCE if k in picked), '')
        if chosen:
            target, field = _SIG_ELEMENT[chosen]
            payload['match-target'] = target
            payload['operator'] = 'STRING_MATCH'
            payload[field] = (_path_of(_val(row, chosen))
                              if chosen == 'http_url' else _val(row, chosen))
            if field == 'value':
                payload['value-check'] = 'enable'
            used.append(chosen)
            rest = [k for k in picked if k != chosen]
            if rest:
                warnings.append(
                    'FortiWeb matches ONE element per signature exception, so '
                    'this entry uses %s. To also require %s, add a second '
                    'exception entry — a single row cannot mean "both".'
                    % (_SIG_ELEMENT[chosen][0],
                       ' and '.join(_SIG_ELEMENT[k][0] for k in rest)))
                for k in rest:
                    ignored.append({'row_key': k, 'why': (
                        'One element per exception entry; %s was used instead.'
                        % _SIG_ELEMENT[chosen][0])})
        else:
            warnings.append(
                'No element was selected, so this exception skips signature %s '
                'for EVERY request on the profile — the same reach as disabling '
                'it. Pick a URL or host to keep it narrow.' % (sig_id or '?'))

    # ── protocol / module exceptions ───────────────────────────────────────
    elif exc_type in ('http_constraint_exception_item',
                      'allow_method_exception_item'):
        if 'http_url' in picked:
            payload['request-type'] = 'plain'
            payload['request-file'] = _path_of(_val(row, 'http_url'))
            used.append('http_url')
        if 'http_host' in picked:
            payload['host-status'] = 'enable'
            payload['host'] = _val(row, 'http_host')
            used.append('http_host')
        if 'src' in picked and exc_type == 'http_constraint_exception_item':
            payload['source-ip-status'] = 'enable'
            payload['source-ip'] = _val(row, 'src')
            used.append('src')
    elif exc_type == 'geo_ip_exception_member_item':
        if 'src' in picked:
            payload['ip'] = _val(row, 'src')
            used.append('src')
    elif exc_type in ('syntax_exception_item', 'bot_exception_element_item'):
        if 'http_url' in picked:
            payload['match-target'] = 'URI'
            payload['operator'] = 'STRING_MATCH'
            payload['value'] = _path_of(_val(row, 'http_url'))
            used.append('http_url')
        elif 'http_host' in picked:
            payload['match-target'] = 'HOST'
            payload['operator'] = 'STRING_MATCH'
            payload['value'] = _val(row, 'http_host')
            used.append('http_host')
    elif exc_type == 'http_header_security_exception_item':
        if 'http_url' in picked:
            payload['request-url-type'] = 'plain'
            payload['request-url-pattern'] = _path_of(_val(row, 'http_url'))
            used.append('http_url')
        if 'http_host' in picked:
            payload['host'] = _val(row, 'http_host')
            used.append('http_host')
    elif exc_type in ('url_enc_exc_item', 'link_cloak_exc_item'):
        if 'http_url' in picked:
            payload['url-type'] = 'plain'
            payload['url-pattern'] = _path_of(_val(row, 'http_url'))
            used.append('http_url')
    elif exc_type == 'file_exception_item':
        if 'http_url' in picked:
            name = _basename(_val(row, 'http_url'))
            payload['file-name'] = name
            used.append('http_url')
            if not name:
                warnings.append('The logged URL ends in a directory, so no file '
                                'name could be taken from it. Type one instead.')
    elif exc_type == 'signature_group_rule_condition':
        if 'http_url' in picked:
            payload['match-target'] = 'URI'
            payload['operator'] = 'STRING_MATCH'
            payload['value'] = _path_of(_val(row, 'http_url'))
            used.append('http_url')
        elif 'http_host' in picked:
            payload['match-target'] = 'HOST'
            payload['operator'] = 'STRING_MATCH'
            payload['value'] = _val(row, 'http_host')
            used.append('http_host')

    payload = {k: v for k, v in payload.items() if str(v).strip() != ''}
    errors = store.validate_payload(exc_type, payload)
    return {'payload': payload, 'used': used, 'ignored': ignored,
            'warnings': warnings, 'errors': list(errors or [])}

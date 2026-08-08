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

import re
from dataclasses import dataclass
from urllib.parse import urlsplit


@dataclass(frozen=True)
class Scoper:
    """One log field that can narrow one carve-out type.

    ``required`` marks a scoper the type cannot be saved without: FortiWeb keys
    an Allow Method or HTTP-constraint exception on a URL pattern, so leaving
    that box unticked is not "a wider exception", it is "no exception". Offering
    it in a list headed *tick any of these to narrow it* and then failing
    validation with a device field name is how an operator ends up staring at
    ``'request-file' is required`` with nothing on screen connecting the two.
    """

    row_key: str
    label: str
    note: str
    required: bool = False


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
               'would match that request and nothing else.', required=True),
        Scoper('http_host', 'Host',
               'Limits the exception to this site, which matters when the '
               'profile serves several.'),
        Scoper('src', 'Source IP',
               'Limits the exception to this client address.'),
    ],
    'allow_method_exception_item': [
        Scoper('http_url', 'URL', 'Only this path may use the extra method. '
               'FortiWeb keys this exception on a URL pattern, so it is not '
               'optional — without it there is no exception to save.',
               required=True),
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

#: ``exc_type`` → ``(row_key, payload_key, note)`` for the field that is the
#: SUBJECT of the carve-out rather than a narrowing of it.
#:
#: An Allow Method exception does not *narrow* by method — the method is the
#: thing being allowed, and an entry without one is inert: FortiWeb stores a row
#: whose allow list is empty, the request stays blocked, and nothing anywhere
#: says why. So it is taken from the entry every time, because the appliance
#: already recorded which method it rejected. Ticking it in the table is
#: therefore neither required nor an error — it is simply already done.
SUBJECTS: dict[str, tuple[str, str, str]] = {
    'allow_method_exception_item': (
        'http_method', 'allow-request',
        'The method to allow is taken from the entry itself — the appliance '
        'already recorded which one it rejected. You do not need to tick it.'),
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
    return [{'row_key': s.row_key, 'label': s.label, 'note': s.note,
             'required': s.required}
            for s in SCOPERS.get(exc_type, [])]


def subject_for(exc_type: str, row: dict | None = None) -> dict | None:
    """The field this carve-out is *about*, taken from the entry, or ``None``.

    Returned to the panel so the operator is told the method is already
    accounted for. Silence here reads as "SATOM ignored the method", which is
    the reading that sends someone to tick it and be told it cannot be used.
    """
    spec = SUBJECTS.get(exc_type)
    if not spec:
        return None
    row_key, payload_key, note = spec
    return {'row_key': row_key, 'payload_key': payload_key, 'note': note,
            'value': _val(row or {}, row_key)}


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


#: Carve-out types for which FortiWeb matches exactly ONE element per row.
#: Ticking a second element on one of these does not narrow it further — the
#: assembly picks by ``_SIG_PRECEDENCE`` and reports the rest — so a default
#: that ticks several would be recommending a selection the device cannot honour.
_SINGLE_ELEMENT = ('signature_filter_item',)

#: Log fields that describe WHO sent the request rather than WHAT was sent.
#:
#: Not preselected while a request-shaped element (URL, host) is available. A
#: carve-out says which traffic is legitimate; the source address in one log
#: entry is one observation of one caller at one moment, so defaulting to it
#: yields an exception that stops working the next time that integration is
#: re-addressed — and the operator reads that as "the exception did nothing".
#: It stays one click away, with its note, and the skip is REPORTED: a default
#: that quietly declines to use available evidence is worse than a wrong one.
_CALLER_FIELDS = ('src',)


def recommend(row: dict, exc_type: str) -> dict:
    """Which fields SATOM would tick for *exc_type*, and why for each.

    The picker used to open with nothing selected, which asks the operator the
    one question they came here unable to answer. Every input this needs — which
    fields exist, which are required, which order is most precise — is already
    declared in :data:`SCOPERS`, so the recommendation is derived from the same
    table the picker renders instead of a second list that would drift from it.

    Deliberately local and deterministic: it costs nothing, works on an isolated
    management network, and produces the same answer twice. The Advisor may
    disagree and the operator may overrule either — this is the starting point,
    not the decision.

    Returns ``{picked, reasons, skipped, single_element, subject, summary}``.
    """
    row = row or {}
    exc_type = (exc_type or '').strip()
    scopers = SCOPERS.get(exc_type, [])
    reasons: dict[str, str] = {}
    skipped: list[dict] = []
    picked: list[str] = []

    # Present in the ENTRY — a field the appliance did not record cannot narrow
    # anything, whatever the type allows.
    available = [s for s in scopers if _val(row, s.row_key)]
    for s in scopers:
        if not _val(row, s.row_key):
            skipped.append({'row_key': s.row_key, 'label': s.label, 'why': (
                'The entry records no %s, so it cannot narrow this exception.'
                % s.label)})

    single = exc_type in _SINGLE_ELEMENT
    if single:
        keys = [s.row_key for s in available]
        chosen = next((k for k in _SIG_PRECEDENCE if k in keys), '')
        for s in available:
            if s.row_key == chosen:
                picked.append(chosen)
                reasons[chosen] = (
                    'FortiWeb matches one element per signature exception, and '
                    '%s is the most precise one this entry carries.' % s.label)
            else:
                skipped.append({'row_key': s.row_key, 'label': s.label, 'why': (
                    'One element per signature exception — %s was chosen as the '
                    'more precise. Tick this instead to swap, or author a second '
                    'entry to require both.'
                    % dict((x.row_key, x.label) for x in scopers).get(chosen, chosen))})
    else:
        request_shaped = [s for s in available if s.row_key not in _CALLER_FIELDS]
        for s in available:
            if s.required:
                picked.append(s.row_key)
                reasons[s.row_key] = (
                    'Required: without it FortiWeb has no exception to key on.')
            elif s.row_key in _CALLER_FIELDS and request_shaped:
                skipped.append({'row_key': s.row_key, 'label': s.label, 'why': (
                    'Left off on purpose. This identifies the caller, not the '
                    'request, so an exception scoped to it stops applying when '
                    'that client is re-addressed. Tick it to pin the exception '
                    'to this address anyway.')})
            else:
                picked.append(s.row_key)
                reasons[s.row_key] = (
                    'Narrows the exception to this %s, and the entry records '
                    'one.' % s.label.lower())

    subject = subject_for(exc_type, row)
    if subject and not subject.get('value'):
        # The subject is taken from the entry unconditionally, so an entry that
        # lacks it produces a rule that saves, applies and changes nothing.
        skipped.append({'row_key': subject['row_key'], 'label': 'subject',
                        'why': ('This entry records no %s, which is the value '
                                'this exception is ABOUT — the rule would save '
                                'and unblock nothing.' % subject['row_key'])})

    if picked:
        names = dict((s.row_key, s.label) for s in scopers)
        summary = ('Pre-selected %s from the entry. Add or remove any of them '
                   'before previewing.'
                   % ', '.join(names.get(k, k) for k in picked))
    elif scopers:
        summary = ('Nothing could be pre-selected — this entry carries none of '
                   'the fields that narrow this exception type. Saving it as-is '
                   'applies it to every request on the profile.')
    else:
        summary = ('This exception type takes no element scope; it is defined '
                   'entirely by its subject.')
    return {'picked': picked, 'reasons': reasons, 'skipped': skipped,
            'single_element': single, 'subject': subject, 'summary': summary}


# --------------------------------------------------------------------------- #
#  Payload assembly                                                            #
# --------------------------------------------------------------------------- #
def _assemble(row: dict, exc_type: str,
              picked: list[str]) -> tuple[dict, list[str], list[str], list[dict]]:
    """``(payload, used, warnings, ignored)`` for *exc_type* from *picked*.

    Split out of :func:`build` so that "which box would have fixed this error"
    is answered by RE-RUNNING THE REAL ASSEMBLY with one more box ticked —
    never by a second, hand-written table of device-key → log-field. Two tables
    agree on the day they are written and diverge at the first schema change,
    and the one that drifts is the one printed in the error message.
    """
    payload: dict = {}
    used: list[str] = []
    warnings: list[str] = []
    # A selection can be dropped by the ASSEMBLY itself and not just by the
    # eligibility check — one element per signature row — so this list belongs
    # here with the code that drops it.
    ignored: list[dict] = []
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
        # The method is the SUBJECT of an Allow Method exception, not a scope:
        # it is what gets allowed. Taken from the entry unconditionally, because
        # a row with an empty allow list is stored happily by FortiWeb, changes
        # nothing, and leaves the request blocked with no trace of why.
        if exc_type == 'allow_method_exception_item':
            method = _val(row, 'http_method').lower()
            if method:
                payload['allow-request'] = method
                used.append('http_method')
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
    return payload, used, warnings, ignored


_REQUIRED_RX = re.compile(r"^'([^']+)' is required for this carve-out type$")

#: Required payload keys that no tickable field can supply, and what to say
#: instead. Reached only when the ENTRY lacks the value, so "tick something" is
#: not the remedy and offering it would send the operator round a loop.
_UNSUPPLIABLE: dict[str, str] = {
    'allow-request': (
        'the entry does not record which HTTP method the appliance rejected, so '
        'there is nothing to put in the allow list — author this one by hand '
        'from the Exceptions page'),
    'signature_id': (
        'this entry names no signature id, so a per-signature carve-out cannot '
        'be built from it — choose the module that produced the block instead'),
    'sub_class_id': (
        'this entry names no signature sub-class, so there is nothing to '
        'disable'),
}


def _explain_errors(row: dict, exc_type: str, picked: list[str],
                    errors: list[str]) -> list[str]:
    """Rewrite device-schema validation errors as the choice that fixes them.

    ``'request-file' is required for this carve-out type`` is true, unactionable
    and the operator never typed ``request-file`` — they ticked, or did not
    tick, a row in a table. The remedy is found by trying each unticked field
    through :func:`_assemble` and keeping the first that fills the missing key.
    """
    out: list[str] = []
    # One tick usually supplies several device keys at once — a URL fills both
    # request-type and request-file. Printing the same remedy twice reads as two
    # separate problems and doubles the apparent distance to a valid carve-out.
    grouped: dict[str, list[str]] = {}
    order: list[str] = []
    for msg in errors or []:
        m = _REQUIRED_RX.match(msg)
        if m is None:
            out.append(msg)
            continue
        key = m.group(1)
        fix = None
        for sc in SCOPERS.get(exc_type, []):
            if sc.row_key in picked or not _val(row, sc.row_key):
                continue
            trial = _assemble(row, exc_type, picked + [sc.row_key])[0]
            if str(trial.get(key, '')).strip():
                fix = sc
                break
        if fix is not None:
            remedy = ('tick %s (%s) in the Entry table above'
                      % (fix.label, _val(row, fix.row_key)))
        elif key in _UNSUPPLIABLE:
            remedy = _UNSUPPLIABLE[key]
        else:
            out.append(msg)
            continue
        if remedy not in grouped:
            grouped[remedy] = []
            order.append(remedy)
        grouped[remedy].append(key)
    for remedy in order:
        keys = grouped[remedy]
        out.append('%s %s missing — %s'
                   % (' and '.join(keys), 'is' if len(keys) == 1 else 'are',
                      remedy))
    return out


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
    ignored: list[dict] = []

    if store.type_for(exc_type) is None:
        return {'payload': {}, 'used': [], 'ignored': [], 'warnings': [],
                'errors': ['"%s" is not a carve-out type SATOM knows.' % exc_type]}

    allowed = {s.row_key for s in SCOPERS.get(exc_type, [])}
    subject_key = (SUBJECTS.get(exc_type) or ('', '', ''))[0]
    for key in selected:
        # The subject field is already in the payload by construction, so
        # reporting it as unusable would be a lie the operator can see through.
        if key in allowed or key == subject_key:
            continue
        ignored.append({'row_key': key, 'why': (
            'A %s carve-out cannot be scoped by this field — FortiWeb has '
            'nowhere to put it.' % (store.type_for(exc_type)['label']))})

    picked = [k for k in selected if k in allowed and _val(row, k)]
    empty = [k for k in selected if k in allowed and not _val(row, k)]
    for key in empty:
        ignored.append({'row_key': key, 'why': (
            'The entry has no value for this field, so it cannot narrow '
            'anything.')})

    payload, used, warnings, dropped = _assemble(row, exc_type, picked)
    ignored.extend(dropped)
    errors = _explain_errors(row, exc_type, picked,
                             store.validate_payload(exc_type, payload))
    return {'payload': payload, 'used': used, 'ignored': ignored,
            'warnings': warnings, 'errors': errors}

"""Which children of a same-device clone may be duplicated, and under what name.

``ClonePlanner`` was written to copy a tree from ONE appliance to ANOTHER, and
its central verdict — ``exists`` ⇒ do not copy — is correct there. Reused to
copy a tree onto the SAME appliance (``wpp_clone_flow.clone_and_rebind``, where
``src is dst``) that verdict inverts its own meaning: every sub-object of the
source WPP already exists at the "destination", so NOTHING was ever created and
the clone was a rename of the root with ~40 shared children hanging off it.

The consequence is the one this module exists to end: a carve-out authored on
the "isolated" profile lands in an object the original still points at. On
2026-08-08 a clone of ``wpp-shop-full`` produced ``wpp-pol-shop-cms`` whose
``allow-method-policy`` was still ``am-std`` — shared by three other profiles —
so a GET allow-list written "for pol-shop-cms" went live for five Server
Policies.

**A new profile owns its whole tree.** Anything it shares is a channel through
which a later edit reaches policies nobody was thinking about. So the default
here is CLONE, and the interesting work is the three cases where cloning is
impossible or worse than sharing:

``factory``
    A FortiWeb PREDEFINED object (``Standard Protection``, ``Predefined - Known
    Bots``, ``Inline Standard Protection``…). Detected from the live payload's
    ``can_view`` flag — the same marker the Web Protection overview page already
    badges as "Default" — verified on fortiweb08 7.6.8, where user objects
    (``am-std``, ``am-exc``, ``kb-std``) carry ``can_view: 0`` and the vendor's
    carry ``can_view: 1``. Copying one freezes a baseline that FortiGuard
    otherwise updates, so the copy silently stops receiving vendor changes.

``template``
    An object governed by an APPROVED template. Cloning it takes that Server
    Policy out of the template's reach without anybody deciding to — the exact
    inverse of the drift this product exists to prevent.

``blocked-by-parent``
    Not a property of the object at all: **re-pointing a reference is a write to
    the PARENT.** A child may only be duplicated if the parent that names it is
    itself being created, because otherwise the re-point mutates a shared object
    and leaks the change to everyone standing behind it — the same failure mode
    the clone is meant to close, one level up. This is a consequence, never an
    operator choice, which is why (unlike the other two) it is not offered as
    "clone anyway".

``factory`` and ``template`` ARE offered as "clone anyway": FortiWeb reports
``can_clone: 1`` on the predefined objects, and a site that wants the copy has a
legitimate reason SATOM cannot know. What is never offered is doing it silently.

Pure and Flask-free except :func:`managed_names_by_collection`, which reads the
template library. That read is deliberately allowed to RAISE: template
governance that could not be read is not "no templates", and guessing it away is
how an object leaves a template without a decision.
"""
from __future__ import annotations

from . import objform

#: Verdicts. ``CLONABLE`` is the default and the one that needs no explanation.
CLONABLE = 'clonable'
FACTORY = 'factory'
TEMPLATE = 'template'
BLOCKED_BY_PARENT = 'blocked-by-parent'
NO_ENDPOINT = 'no-endpoint'
CERT = 'cert'

#: The verdicts an operator may override with an explicit "clone anyway".
OVERRIDABLE = (FACTORY, TEMPLATE)

#: Live-payload marker of a FortiWeb PREDEFINED object. ``fortiweb_ops`` strips
#: it from every write, so it has to be read off the RAW payload before
#: ``sanitize_payload`` runs — see ``clone.ClonePlanner._visit``.
FACTORY_FIELD = 'can_view'

#: FortiWeb object-name ceiling. A derived name that overflows it is rejected by
#: the box at POST time, i.e. half-way through a clone.
MAX_NAME = 63

_WPP_URNS = ('cmdb/waf/web-protection-profile.inline-protection',
             'cmdb/waf/web-protection-profile.offline-protection')


def is_factory(raw) -> bool:
    """Is this LIVE payload a FortiWeb predefined object?

    Reads ``can_view`` because that is what the box actually sets: on
    fortiweb08 7.6.8 ``is_default`` came back ``None`` for every object,
    predefined and user-made alike, so keying on it would classify the whole
    tree as user-made and clone the vendor's baselines.
    """
    if not isinstance(raw, dict):
        return False
    return str(raw.get(FACTORY_FIELD, '')).strip() in ('1', 'True', 'true')


def managed_names_by_collection() -> dict[str, set[str]]:
    """``{cmdb collection: {names governed by an APPROVED template}}``.

    Raises whatever the template store raises. A caller that swallows it would
    be deciding, on a DB hiccup, that nothing is templated.
    """
    from . import templates as tpl
    from ..models import Template

    out: dict[str, set[str]] = {}

    wpp_names = set(tpl.managed_wpp_names())
    if wpp_names:
        for urn in _WPP_URNS:
            out.setdefault(objform.collection_of(urn), set()).update(wpp_names)

    for t in Template.query.filter_by(status=Template.STATUS_APPROVED).all():
        # ONLY ``config:<section>`` templates. ``config_template_collection``
        # attributes a body to one object type by reading its FIRST sub-object,
        # which is exactly right for a single-object config template and exactly
        # wrong for a multi-object one: an approved WPP template
        # ("WPP-PCI-Compliance") resolved to collection ``signature``, so a
        # signature policy that happened to share that name would have been
        # refused as template-managed. Verified against the live library on
        # fortiweb08's manager, not reasoned about.
        if not str(t.kind or '').startswith(Template.KIND_CONFIG_PREFIX):
            continue
        coll = tpl.config_template_collection(t)
        if not coll:
            continue
        names = out.setdefault(coll, set())
        if t.name:
            names.add(str(t.name))
        # A template captured under an alias names its object in the body; the
        # library entry's name is then not the name on the box.
        try:
            body = t.body_dict or {}
            root = body.get('data') or {}
            inner = root.get('data') if isinstance(root.get('data'), dict) else root
            n = (inner or {}).get('name')
            if n:
                names.add(str(n))
        except Exception:  # noqa: BLE001 — a malformed body never breaks the lock
            continue
    return out


def classify(item, managed: dict[str, set[str]] | None = None) -> tuple[str, str]:
    """``(verdict, reason)`` for one collected :class:`clone.CloneItem`.

    Order matters: an object with no write endpoint cannot be duplicated no
    matter what else is true of it, and a certificate never travels over REST.
    """
    managed = managed or {}
    if item.urn in _CERT_URNS:
        return CERT, ('a certificate is SSH-only — the copy keeps naming the '
                      'same one')
    if item.logical is None:
        return NO_ENDPOINT, ('the registry has no write endpoint for this '
                             'object type, so SATOM cannot create a copy of it')
    if getattr(item, 'factory', False):
        return FACTORY, ('"%s" is a FortiWeb predefined object. A copy stops '
                         'receiving FortiGuard updates.' % item.mkey)
    coll = objform.collection_of(item.urn)
    if item.mkey and item.mkey in managed.get(coll, ()):
        return TEMPLATE, ('"%s" is governed by an approved template. Cloning it '
                          'takes this Server Policy out of the template.'
                          % item.mkey)
    return CLONABLE, ''


_CERT_URNS = {'cmdb/system/certificate.local', 'cmdb/system/certificate.sni'}


def derive_name(old: str, suffix: str, is_taken=None) -> str:
    """``<old>-<suffix>``, capped at :data:`MAX_NAME` and disambiguated.

    The BASE is truncated, never the suffix: the suffix is what makes the name
    unique per Server Policy, so trimming it is how two policies end up sharing
    a "private" object again. Returns ``''`` when no usable name exists (the
    caller then leaves the object shared and says so, rather than writing a
    truncated collision).
    """
    old = (old or '').strip()
    suffix = (suffix or '').strip().strip('-')
    if not old or not suffix:
        return ''
    if len(suffix) + 1 >= MAX_NAME:
        return ''

    def _fit(base: str, tag: str = '') -> str:
        room = MAX_NAME - len(suffix) - 1 - len(tag)
        return '%s-%s%s' % (base[:room], suffix, tag) if room >= 1 else ''

    cand = _fit(old)
    if not cand:
        return ''
    n = 1
    while is_taken and is_taken(cand):
        n += 1
        if n > 50:
            return ''
        cand = _fit(old, '-%d' % n)
        if not cand:
            return ''
    return cand


def question(item) -> dict:
    """The operator-facing row for an object the clone is leaving SHARED."""
    return {
        'label': item.label,
        'urn': item.urn,
        'mkey': item.mkey,
        'verdict': item.scope,
        'reason': item.scope_reason,
        'ref': '%s|%s' % (item.urn, item.mkey),
        'overridable': item.scope in OVERRIDABLE,
    }


def questions(items) -> list[dict]:
    """Every object this plan will keep SHARED with the source profile.

    Only ``object`` nodes that carry a live payload: an ``empty`` node is a
    reference the source itself does not resolve, and a sub-table row is created
    with its parent. Certificates are excluded — they are shared by design on
    every appliance and reporting them as a decision would bury the real ones.

    An object the operator already overrode with ``clone_anyway`` keeps its
    ``factory``/``template`` verdict (that is what it IS) but is no longer a
    question: it is being copied. Listing it anyway would ask the operator to
    decide something they just decided, and — worse — would keep the "N objects
    would stay shared" gate closed on a plan that shares none.
    """
    out: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for it in items:
        if it.kind != 'object' or it.depth == 0 or not it.payload:
            continue
        if it.scope in ('', CLONABLE, CERT) or it.renamed_from:
            continue
        key = (it.urn, it.mkey)
        if key in seen:
            continue
        seen.add(key)
        out.append(question(it))
    return out


__all__ = [
    'CLONABLE', 'FACTORY', 'TEMPLATE', 'BLOCKED_BY_PARENT', 'NO_ENDPOINT',
    'CERT', 'OVERRIDABLE', 'FACTORY_FIELD', 'MAX_NAME',
    'is_factory', 'managed_names_by_collection', 'classify', 'derive_name',
    'question', 'questions',
]

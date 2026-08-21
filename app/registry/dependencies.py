"""FortiWeb object **dependency map** — the in-repo capture of the policy exporter.

Why this file exists. The team's ``fortiweb_policy_inspector.py`` (the "policy
export" script that lived only on a USB stick) encodes, *in code*, how every
FortiWeb object hangs off another: a **Server Policy** points at a Virtual
Server, a Server Pool, a Health Check, a Web Protection Profile…; the **WPP** in
turn points at ~40 protection sub-policies, each with its own child rule-lists.
That map used to exist ONLY on the USB — pull the stick and the knowledge was
gone.

This module lifts that structure into the repository as **pure data** so the app
no longer needs the USB to know the shape of a FortiWeb config. It mirrors the
exporter's ``fetch_policy_full`` (the server-policy side) and its ``FIELD_MAP`` +
``SUB_MAP`` (the web-protection-profile side), keyed by the **FortiWeb GUI name**
of each object together with the REST ``urn`` it resolves to. Because those URNs
are the same ones used in ``endpoints.yaml``, the tree can be cross-referenced
against the endpoint **registry** — see ``services/structure.py`` — so the
Structure page can show, side by side, the *endpoint library* AND the *functional
dependency tree* the exporter walks.

Two roots, mirroring the user's mental model::

    Server Policy
    --> Virtual Server
    ----> Virtual IP (VIP)
    --> Server Pool
    ----> Real Servers (members)
    --> Web Protection Profile  (-> its own tree)
    ...
    Web Protection Profile
    --> Signatures
    ----> Signature Classes
    --> URL Rewriting
    ----> Rewrite Rules
    ...

Pure data + rendering — no Qt, no network, no registry coupling (the registry
cross-reference lives in ``services/structure.py``, which consumes this module).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Iterator


# --------------------------------------------------------------------------- #
#  Node model                                                                  #
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class DepNode:
    """One FortiWeb object in the dependency tree.

    ``fortiweb`` — the label as it reads in the FortiWeb 7.6 GUI (what the user
    sees on the box). ``urn`` — the REST path the exporter fetches it from; it
    matches an ``endpoints.yaml`` urn when the object is in the registry (blank
    for pure grouping nodes). ``via`` — the *field on the parent* that
    references this object, i.e. the dependency edge (e.g. a Server Policy links
    its pool through the ``server-pool`` field). ``note`` — GUI section or a
    short remark.
    """

    fortiweb: str
    urn: str = ""
    via: str = ""
    note: str = ""
    children: tuple["DepNode", ...] = ()
    #: ``(field, value)`` — follow this edge ONLY when the object/row carrying it
    #: has ``field == value``. Needed where ONE name field addresses TWO
    #: collections chosen by a sibling discriminator (measured:
    #: ``custom-access.rule/custom-signature`` — ``custom-signature-name`` names a
    #: custom-protection-GROUP or a custom-protection-RULE depending on
    #: ``custom-signature-type``). Declaring both edges unconditionally is not a
    #: cheaper equivalent: the wrong collection answers with no object, which the
    #: classifier reads as "referenced on the source but not found live" and
    #: BLOCKS — a false block on every row using the other type.
    when: tuple[str, str] = ()


def _n(
    fortiweb: str,
    urn: str = "",
    via: str = "",
    note: str = "",
    children: Iterable["DepNode"] = (),
    when: tuple = (),
) -> DepNode:
    """Terse constructor used to keep the big literal trees readable."""
    return DepNode(fortiweb, urn, via, note, tuple(children), tuple(when))


# --------------------------------------------------------------------------- #
#  CROSS-CUTTING reference FIELDS (not tree positions)                          #
# --------------------------------------------------------------------------- #
# `trigger` and `recaptcha-server` are fields that recur across MANY collections
# rather than properties of one place in the tree. Measured on fortiweb12 (7.6.8)
# by reading every object collection this tree declares: `trigger` is carried by
# 10 of them — INCLUDING `server-policy/policy` itself — and `recaptcha-server`
# by 3. The 7.6.8 CLI reference confirms the semantics do not vary by host
# collection: every one of those pages spells `set trigger "<trigger-policy_name>"`
# and links the SAME log trigger-policy page.
#
# WHY FIELD-DRIVEN AND NOT A LIST OF PARENTS: only 51 of the 130 object
# collections had any row on the lab appliance, so 79 could not be inspected at
# all. Attaching these edges to the measured parents would leave the identical
# defect latent everywhere nobody happened to have something configured.
#
# The failure was reproduced end to end, not argued: the payload the planner
# builds for a custom-protection-rule whose `trigger` names a policy the
# destination lacks is REJECTED (HTTP 500, no errcode, no message); the same
# payload minus `trigger` is accepted (HTTP 200).
_TRIGGER_POLICY_REF: DepNode = _n(
    "Trigger Policy", "cmdb/log/trigger-policy", "trigger",
    note="log trigger -> email/syslog/FortiAnalyzer/SIEM notification policies",
    children=[
        # Field name and collection name diverge on exactly one of these four:
        # the field is `analyzer-policy`, the collection is
        # `log/fortianalyzer-policy`. `cmdb/log/analyzer-policy` answers -20001.
        # A notification policy without its SERVER list is a shell: it clones,
        # it reports success, and it notifies nobody. The three server lists
        # below were settled by CREATING a parent on 7.6.8 and reading the child
        # path (all three answer with a list); `email-policy` is deliberately a
        # LEAF because the same probe on `mail-server-list` came back non-list,
        # and an unverified sub-table path does not 404 on FortiWeb — it echoes
        # the parent, which would then be POSTed back into itself.
        _n("Email Policy", "cmdb/log/email-policy", "email-policy",
           note="server list name unverified on 7.6.8 — left a leaf on purpose"),
        _n("Syslog Policy", "cmdb/log/syslog-policy", "syslog-policy",
           children=[_n("Syslog Servers",
                        "cmdb/log/syslog-policy/syslog-server-list")]),
        _n("FortiAnalyzer Policy", "cmdb/log/fortianalyzer-policy", "analyzer-policy",
           children=[_n("FortiAnalyzer Servers",
                        "cmdb/log/fortianalyzer-policy/fortianalyzer-server-list")]),
        _n("SIEM Policy", "cmdb/log/siem-policy", "siem-policy",
           children=[_n("SIEM Servers", "cmdb/log/siem-policy/siem-server-list")]),
    ],
)

_RECAPTCHA_REF: DepNode = _n(
    "reCAPTCHA User", "cmdb/user/recaptcha-user", "recaptcha-server",
    note="bot-confirmation reCAPTCHA server",
)

# The SAME trigger-policy subtree, reached through a DIFFERENT field name.
# A Web Protection Profile does NOT carry `trigger`; it carries
# `quarantined-ip-trigger` — measured on 7.6.8, where
# `set quarantined-ip-trigger ?` answers `<datasource>  choose Email or syslog
# policy`, and the CLI reference links that field to `log trigger-policy`.
# FIELD_REFS matches the field name EXACTLY, so the `trigger` edge could never
# fire here and the WPP payload rode out naming a policy nothing created. That
# is not a partial copy: POSTing the planner's own payload to a clean
# destination answers -651 and the WHOLE profile fails, taking `redirect-url`
# and every other setting on it down with the dangling reference.
#
# Children are SHARED with `_TRIGGER_POLICY_REF` (DepNode is frozen). A second
# literal copy would be a second author of one shape, and the two would drift
# the first time only one of them was corrected.
_QUARANTINED_IP_TRIGGER_REF: DepNode = _n(
    "Quarantined IP Trigger", "cmdb/log/trigger-policy", "quarantined-ip-trigger",
    note="WPP quarantined-IP notification -> the same log trigger-policy",
    children=_TRIGGER_POLICY_REF.children,
)

#: field -> shared ref node, followed when a live object (or sub-row) carries
#: that field. Deliberately tiny: a field earns a place only once its target
#: collection has been READ on a real appliance (both answer 200 on 7.6.8).
#: Guessing a target is worse than omitting it — an unverified collection
#: answers 200/zero-rows, not 404, so the reference would be reported as
#: missing-on-the-source and block the apply.
FIELD_REFS: dict = {
    "trigger": _TRIGGER_POLICY_REF,
    "recaptcha-server": _RECAPTCHA_REF,
    "quarantined-ip-trigger": _QUARANTINED_IP_TRIGGER_REF,
}


def when_holds(node: "DepNode", row: dict) -> bool:
    """Does this conditional edge apply to ``row``?

    Unconditional edges always apply; a conditional one only on an EXACT match.
    Deliberately not lenient: a row whose discriminator is missing or unknown is
    left alone rather than guessed at, because a guess sends the name to the
    wrong collection, where it reads back empty and blocks the apply on a
    reference that was never broken.
    """
    if not node.when:
        return True
    field, value = node.when
    return row.get(field, row.get(field.replace("-", "_"))) == value


def field_ref_edges(obj: dict) -> list:
    """The cross-cutting reference edges ``obj`` actually carries.

    Skipping objects without the field is a cheap PRE-FILTER, not a correctness
    gate: ``referenced_names`` is the single place that decides what counts as a
    name and already drops the empty ones, so an edge returned for a blank field
    is a no-op iteration and never a phantom object in the plan.
    """
    if not isinstance(obj, dict):
        return []
    return [ref for field, ref in FIELD_REFS.items()
            if isinstance(obj.get(field, obj.get(field.replace("-", "_"))), str)]


# What a CERTIFICATE VERIFY object points at. Both verify collections carry the
# same fields (`ca` / `crl` / `ocsp` + a firmware-specific toggle), read off
# `set ?` on fortiweb12 (7.6.8). The two targets were settled by BINDING, not by
# name: on a live `certificate.verify`, `set ca <a ca-group>` and
# `set crl <a crl-group>` are ACCEPTED. So `ca` names a CA GROUP, not a CA --
# wiring it to `certificate.ca` would leave the group empty, which is a verify
# policy that trusts nothing while reporting success.
#
# The groups are REST-creatable (POST -> 200) so they travel; their member rows
# travel through the generic by-parent path, and the field they use is `name`
# (measured on a real row: POST .../members {"name": ...} -> id/type/name/...).
#
# What the members NAME is MATERIAL, and REST refuses it -- `cmdb/system/
# certificate.ca` answers -7721 even for a valid public root PEM. That refusal
# used to be written up here as "a file upload", which is wrong about the
# OBJECT rather than about REST: measured on fortiweb12 (7.6.8), the CLI
# imports a CA cleanly with `config system certificate ca ; edit "x" ;
# set certificate "-----BEGIN..."` -- the field is `certificate`, not `ca` --
# and the object is visible over REST afterwards. Same story for `certificate.
# crl` (read back through `get`, never `show`) and `certificate.
# intermediate-certificate`. So material travels over SSH, exactly like
# `certificate.local` does through :mod:`app.services.cert_ssh`.
#
# The third field, `ocsp`, was left unmodelled until 2026-08-19 and the omission
# was SILENT: a verify object migrated or audited here simply lost its real-time
# revocation check, and nothing said so. The write-up that justified leaving it
# out claimed the collection "could not be determined" -- that was wrong about
# the METHOD, not about the device. The probe had run at the CLI's top level on
# an ADOM-enabled box, where `config system certificate <anything>` answers
# "Parsing error at 'system'" and lists NOTHING. Inside `config vdom` / `edit
# <adom>` there are THREE ocsp tables, and binding picks exactly one: on a live
# `certificate.verify`, `set ocsp <an ocsp-responder>` is ACCEPTED while both
# `set ocsp <an ocsp-signing-certs>` and a name that exists nowhere are
# REJECTED. `server-certificate-verify` accepts the same responder.
#
# A `?` at the CLI root is NOT evidence of absence on an ADOM-enabled appliance.
#
# The responder's own signer is the trap. `set ocsp-signing-certs ?` enumerates
# its <datasource> as `system certificate.ocsp-signing-certs` -- the LEAF table.
# The registry also carries `certificate.ocsp-signing-certs-group`, and reading
# the two by NAME would repeat exactly the mistake this file records above about
# `ca` naming a GROUP: here it is the other way round, and the table that LOOKS
# like the right answer refuses `set` outright.
#
# That leaf is MATERIAL, and it is the WORST of the material tables because it
# does not refuse. `certificate.ca` answers -7721 and stops the caller; a cmdb
# POST to `certificate.ocsp-signing-certs` carrying a valid PEM answers **200**,
# creates the row and DISCARDS the certificate -- and REST then prints
# `certificate: ""` for the empty shell and for a real entry alike, so the read
# back cannot tell them apart either. It is therefore modelled as a node (so the
# operator is TOLD it exists) and listed in `clone._CERT_URNS` (so the clone
# reports it "SSH-only, not cloned over REST" instead of REST-creating a shell
# that reports success). `cert_import.SSH_ONLY_SPECS` carries the CLI door.
#
# Why the 2026-08-19 sweep of all 37 writable tabs missed it: that sweep
# classified by ERRCODE -7721. A collection that answers 200 could never appear
# in its results, whatever it did with the body.
_CERT_VERIFY_REFS: tuple = (
    _n("CA Group", "cmdb/system/certificate.ca-group", "ca",
       "verify -> the CA group whose CAs sign the accepted certificates",
       children=[_n("CA Group Members", "cmdb/system/certificate.ca-group/members")]),
    _n("CRL Group", "cmdb/system/certificate.crl-group", "crl",
       "verify -> the CRL group checked for revocation",
       children=[_n("CRL Group Members", "cmdb/system/certificate.crl-group/members")]),
    _n("OCSP Responder", "cmdb/system/certificate.ocsp-responder", "ocsp",
       "verify -> the OCSP responder asked for revocation in real time",
       children=[_n("OCSP Signing Certificate",
                    "cmdb/system/certificate.ocsp-signing-certs",
                    "ocsp-signing-certs",
                    "responder -> the certificate whose signature validates its "
                    "responses; MATERIAL, travels over SSH, never over REST")]),
)


# An IP List member may select an IP GROUP instead of a literal IP (the member's
# ``ip-group`` field, used when group-type=ip-group). That group is a SEPARATE
# object the clone must carry FIRST, or the member POST -651s on the dangling
# reference — exactly why some members of a list clone and others don't (the
# literal-IP rows succeed, the group-backed rows fail). Shared by both the
# Standard-Protection and IP-Protection IP-list nodes (frozen => safe to reuse).
_IP_GROUP_REF: DepNode = _n(
    "IP Group", "cmdb/server-policy/ip-group", "ip-group",
    note="member ip-group reference",
    children=[_n("IP Group Members", "cmdb/server-policy/ip-group/members")],
)

# The Bot-Mitigation EXCEPTION (a WAF object) is named by an `exception` field on
# the bot-mitigate-policy AND — firmware-dependent — on each bot sub-object
# (known-bots / bot-deception / biometrics / threshold), exactly as the WPP
# editor (wpp_specs) models it. Wire it at EVERY point so the clone discovers it
# wherever the live config names it (harmless where the field is absent: an empty
# ref is simply not walked). Shared frozen node => safe to reuse; the planner's
# visited-set creates it once. Verified against the FortiWeb 8.0 CLI Reference.
_BOT_EXCEPTION_REF: DepNode = _n(
    "Bot Exceptions", "cmdb/waf/bot-mitigation-exception", "exception",
    children=[_n("Exception Elements",
                 "cmdb/waf/bot-mitigation-exception/exception-element-list")],
)

# Every FILTER sub-table of a Custom Access Rule (waf/custom-access.rule/*), taken
# verbatim from the endpoint registry. These are by-parent rows, not referenced
# objects, so they clone with the rule itself.
#
# CAUTION when editing: FortiWeb answers a sub-table path it does not implement
# by returning the PARENT OBJECT, so a typo here yields a "row" that is really
# the rule itself and would be POSTed back as a bogus filter. ``subtable_rows``
# in services/clone.py drops that echo, and tests/test_clone_subtables.py pins
# both halves. Keep these names in sync with endpoints.yaml.
# The Custom Signature subtree, factored out because TWO places reach it: the
# Signatures node of a Web Protection Profile (via the signature object's
# `custom-protection-group` field) and the Custom Signature FILTER of a Custom
# Access Rule (via `custom-signature-name`). Two literal copies would be two
# authors of one shape, and the one nobody looks at goes stale.
#
# Sub-tables measured on 7.6.8, not assumed: a custom-protection-GROUP has
# `type-list` and nothing else (`max-alert-interval` is a scalar); a
# custom-protection-RULE has `meet-condition` and nothing else. `threat-weight`
# and `severity` are SCALARS on the rule and travel inside its own body — there
# is no threat-weight object to carry.
_CUSTOM_SIG_RULE_CHILDREN: tuple = (
    _n("Match Conditions", "cmdb/waf/custom-protection-rule/meet-condition"),
)
_CUSTOM_SIG_GROUP_CHILDREN: tuple = (
    _n("Custom Signature Rules", "cmdb/waf/custom-protection-group/type-list",
       children=[_n("Custom Signature Rule", "cmdb/waf/custom-protection-rule",
                    "custom-protection-rule",
                    children=_CUSTOM_SIG_RULE_CHILDREN)]),
)

# The Custom Signature FILTER row addresses ONE of two collections through ONE
# name field. Measured on fortiweb12 (7.6.8) on a row built for the purpose:
#   custom-signature-enable  enable|disable
#   custom-signature-type    custom-signature-group | custom-signature
#   custom-signature-name    <the referenced name>   <- validated by the box: a
#                            name that does not exist is REJECTED (HTTP 500), a
#                            real one accepted — a true reference, not free
#                            text, so a dangling one breaks the row.
# Hence `when=`: without the discriminator the group-typed rows would be looked
# up in the rule collection (and vice versa), come back empty, and BLOCK.
_CUSTOM_SIGNATURE_FILTER_REFS: tuple = (
    _n("Custom Signature Group (filter)", "cmdb/waf/custom-protection-group",
       "custom-signature-name", note="filter row, type=custom-signature-group",
       children=_CUSTOM_SIG_GROUP_CHILDREN,
       when=("custom-signature-type", "custom-signature-group")),
    _n("Custom Signature (filter)", "cmdb/waf/custom-protection-rule",
       "custom-signature-name", note="filter row, type=custom-signature",
       children=_CUSTOM_SIG_RULE_CHILDREN,
       when=("custom-signature-type", "custom-signature")),
)

_CUSTOM_ACCESS_RULE_FILTERS: tuple[DepNode, ...] = tuple(
    _n(label, "cmdb/waf/custom-access.rule/" + coll,
       children=(_CUSTOM_SIGNATURE_FILTER_REFS if coll == "custom-signature" else ()))
    for label, coll in (
        ("Source IP Filter", "source-ip-filter"),
        ("Geo Filter", "geo-filter"),
        ("Time Range Filter", "time-range-filter"),
        ("Method Filter", "method"),
        ("URL Filter", "url-filter"),
        ("HTTP Header Filter", "http-header-filter"),
        ("Parameter Filter", "parameter"),
        ("User Filter", "user-filter"),
        ("Access Limit Filter", "access-limit-filter"),
        ("HTTP Transaction Filter", "http-transaction"),
        ("Response Code Filter", "response-code"),
        ("Content Type Filter", "content-type"),
        ("Packet Interval Filter", "packet-interval"),
        ("Main Class Filter", "main-class"),
        ("Sub Class Filter", "sub-class"),
        ("Custom Signature Filter", "custom-signature"),
        ("Occurrence Filter", "occurrence"),
    )
)

# An API rule names an api-user-group by `allow-user-group` at BOTH the rule level
# AND inside each `sub-url-setting` row (verified vs the 8.0 CLI ref) — wire the
# same full group subtree (-> user-list -> api-users -> referer/ip lists) at both.
_API_USER_GROUP_REF: DepNode = _n(
    "API User Group", "cmdb/waf/api-user-group", "allow-user-group",
    children=[_n("User List", "cmdb/waf/api-user-group/user-list",
                 children=[
                     _n("API User", "cmdb/waf/api-users", "api-user-name",
                        children=[
                            _n("HTTP Referer List", "cmdb/waf/api-users/http-referer-list"),
                            _n("IP Access List", "cmdb/waf/api-users/ip-access-list"),
                        ]),
                 ])],
)


# --------------------------------------------------------------------------- #
#  Web Protection Profile — FIELD_MAP + SUB_MAP from the exporter              #
#  (cmdb/waf/web-protection-profile.inline-protection -> ~40 sub-policies)     #
# --------------------------------------------------------------------------- #
WEB_PROTECTION_PROFILE: DepNode = _n(
    "Web Protection Profile",
    "cmdb/waf/web-protection-profile.inline-protection",
    note="Web Protection · also .offline-protection",
    children=[
        # -- Standard Protection --------------------------------------------
        _n("Signatures", "cmdb/waf/signature", "signature-rule", "Standard Protection",
           children=[
               _n("Signature Classes", "cmdb/waf/signature/main_class_list"),
               _n("Disabled Signatures", "cmdb/waf/signature/signature_disable_list"),
               _n("Signature Exceptions", "cmdb/waf/signature/filter_list"),
               _n("Disabled Sub-Classes", "cmdb/waf/signature/sub_class_disable_list"),
               _n("Alert-Only Signatures", "cmdb/waf/signature/alert_only_list"),
               _n("FPM-Disabled Signatures", "cmdb/waf/signature/fpm_disable_list"),
               _n("Scoring Override Disabled",
                  "cmdb/waf/signature/scoring_override_disable_list"),
               _n("Score Grades", "cmdb/waf/signature/score_grade_list"),
               _n("Custom Protection Group", "cmdb/waf/custom-protection-group",
                  "custom-protection-group",
                  children=_CUSTOM_SIG_GROUP_CHILDREN),
           ]),
        _n("HTTP Protocol Constraints", "cmdb/waf/http-protocol-parameter-restriction",
           "http-protocol-parameter-restriction", "Standard Protection",
           children=[
               _n("HTTP Constraints Exception", "cmdb/waf/http-constraints-exceptions",
                  "exception_name",
                  children=[_n("Exception List",
                               "cmdb/waf/http-constraints-exceptions/http_constraints-exception-list")]),
           ]),
        _n("X-Forwarded-For", "cmdb/waf/x-forwarded-for", "x-forwarded-for-rule",
           "Standard Protection",
           children=[_n("Trusted IP List", "cmdb/waf/x-forwarded-for/ip-list")]),
        _n("Allow Method Policy", "cmdb/waf/allow-method-policy", "allow-method-policy",
           "Standard Protection",
           children=[_n("Method Exception", "cmdb/waf/allow-method-exceptions",
                        "allow-method-exception",
                        children=[_n("Exception List",
                                     "cmdb/waf/allow-method-exceptions/allow-method-exception-list")])]),
        _n("IP List Policy", "cmdb/waf/ip-list", "ip-list-policy", "Standard Protection",
           children=[_n("IP Members", "cmdb/waf/ip-list/members",
                        children=[_IP_GROUP_REF])]),
        _n("Geo Block List", "cmdb/waf/geo-block-list", "geo-block-list-policy",
           "Standard Protection",
           children=[
               _n("Blocked Countries", "cmdb/waf/geo-block-list/country-list"),
               _n("Geo Exceptions", "cmdb/waf/geo-ip-except", "exception-rule",
                  children=[_n("Exception Members", "cmdb/waf/geo-ip-except/members")]),
           ]),
        _n("URL Access Policy", "cmdb/waf/url-access.url-access-policy", "url-access-policy",
           "Standard Protection",
           children=[_n("URL Access Rules", "cmdb/waf/url-access.url-access-policy/rule",
                        children=[_n("URL Access Rule", "cmdb/waf/url-access.url-access-rule",
                                     "url-access-rule-name",
                                     children=[_n("Match Conditions",
                                                  "cmdb/waf/url-access.url-access-rule/match-condition")])])]),
        # A Custom Access Rule is NOT a leaf: its whole meaning lives in the
        # per-rule FILTER sub-tables (which URL, which source IP, which rate
        # limit…). Declaring the rule without them cloned the rule's NAME and
        # dropped every condition it matched on — a rule that looks migrated in
        # the GUI and enforces nothing. Verified on fortiweb08: car-ratelimit
        # carried url-filter(^/api/) + access-limit-filter(100) and migrated to
        # fortiweb09 with both empty. The 17 names below are the registry's
        # (endpoints.yaml), NOT guesses: an invented sub-table path does not 404
        # on FortiWeb — it ECHOES THE PARENT OBJECT back (see clone.subtable_rows).
        _n("Custom Access Policy", "cmdb/waf/custom-access.policy", "custom-access-policy",
           "Standard Protection",
           children=[_n("Custom Policy Rules", "cmdb/waf/custom-access.policy/rule",
                        children=[_n("Custom Access Rule", "cmdb/waf/custom-access.rule",
                                     "rule-name",
                                     children=_CUSTOM_ACCESS_RULE_FILTERS)])]),
        # DoS Prevention bundles four SEPARATE rule objects, each named by a field
        # on the policy (these are NOT by-parent sub-tables) — so the clone must
        # walk into them via that field and create them FIRST, or the policy POST
        # -651s on the dangling reference (and the WPP naming this policy -651s in
        # turn). The `via` here = the ddos_policy field name (see wpp_specs).
        _n("DoS Prevention", "cmdb/waf/application-layer-dos-prevention",
           "application-layer-dos-prevention", "Standard Protection",
           children=[
               _n("HTTP Access Limit", "cmdb/waf/layer4-access-limit-rule",
                  "layer4-access-limit-rule"),
               _n("TCP Flood Prevention", "cmdb/waf/layer4-connection-flood-check-rule",
                  "layer4-connection-flood-check-rule"),
               _n("HTTP Flood Prevention", "cmdb/waf/http-request-flood-prevention-rule",
                  "http-request-flood-prevention-rule"),
               _n("Malicious IP Check", "cmdb/waf/http-connection-flood-check-rule",
                  "http-connection-flood-check-rule"),
           ]),
        # Bot Mitigation likewise references FIVE separate objects by field name
        # (known-bots / bot-deception / biometrics-based-detection /
        # threshold-based-detection / exception); each is its own cmdb object the
        # clone must create first, not a by-parent sub-table. `via` = the
        # bot_mitigation_policy field name (see wpp_specs).
        _n("Bot Mitigation", "cmdb/waf/bot-mitigate-policy",
           "bot-mitigate-policy", "Standard Protection",
           children=[
               _n("Known Bots", "cmdb/waf/known-bots", "known-bots",
                  children=[
                      _n("Malicious Bots Disable List",
                         "cmdb/waf/known-bots/malicious-bot-disable-list"),
                      _n("Known Good Bots Disable List",
                         "cmdb/waf/known-bots/known-good-bots-disable-list"),
                      _BOT_EXCEPTION_REF,
                  ]),
               _n("Bot Deception", "cmdb/waf/bot-deception", "bot-deception",
                  children=[_n("Deception URL List", "cmdb/waf/bot-deception/url-list"),
                            _BOT_EXCEPTION_REF]),
               _n("Biometric Detection", "cmdb/waf/biometrics-based-detection",
                  "biometrics-based-detection",
                  children=[_n("Biometric URL List",
                               "cmdb/waf/biometrics-based-detection/url-list"),
                            _BOT_EXCEPTION_REF]),
               _n("Threshold Detection", "cmdb/waf/threshold-based-detection.policy",
                  "threshold-based-detection", children=[_BOT_EXCEPTION_REF]),
               _BOT_EXCEPTION_REF,
           ]),
        _n("Advanced Bot Protection", "cmdb/waf/advanced-bot-protection",
           "advanced-bot-protection", "Bot Mitigation · FortiGuard ABP"),
        _n("Syntax Based Detection", "cmdb/waf/syntax-based-attack-detection",
           "syntax-based-attack-detection", "Standard Protection",
           children=[_n("Syntax Exceptions",
                        "cmdb/waf/syntax-based-attack-detection/exception-element-list")]),
        # -- Client Side Security -------------------------------------------
        _n("HTTP Header Security", "cmdb/waf/http-header-security", "http-header-security",
           "Client Side Security",
           children=[
               _n("Secure Header Table", "cmdb/waf/http-header-security/http-header-security-list",
                  children=[
                      _n("Header Security Exception", "cmdb/waf/http-header-security-exception",
                         "exception",
                         children=[_n("Exception List",
                                      "cmdb/waf/http-header-security-exception/list")]),
                  ]),
           ]),
        _n("CORS Protection", "cmdb/waf/cors-protection-policy", "cors-protection-policy",
           "Client Side Security",
           children=[_n("CORS Rules", "cmdb/waf/cors-protection-policy/rule-list",
                        children=[_n("CORS Rule", "cmdb/waf/cors-protection-rule", "cors-rule",
                                     children=[
                                         _n("Allowed Methods",
                                            "cmdb/waf/cors-protection-rule/allowed-methods-list"),
                                         _n("Allowed Headers",
                                            "cmdb/waf/cors-protection-rule/allowed-headers-list"),
                                         _n("Exposed Headers",
                                            "cmdb/waf/cors-protection-rule/exposed-headers-list"),
                                         _n("Allowed Origins", "cmdb/waf/allowed-origins",
                                            "allowed-origins-list",
                                            children=[_n("Origins",
                                                         "cmdb/waf/allowed-origins/origin-list")]),
                                     ])])]),
        _n("Cookie Security Policy", "cmdb/waf/cookie-security", "cookie-security-policy",
           "Client Side Security",
           children=[_n("Cookie Exceptions",
                        "cmdb/waf/cookie-security/cookie-security-exception-list")]),
        _n("WebSocket Security", "cmdb/waf/websocket-security.policy",
           "websocket-security-policy", "Client Side Security",
           children=[_n("WebSocket Rules", "cmdb/waf/websocket-security.policy/rule-list",
                        children=[_n("WebSocket Rule", "cmdb/waf/websocket-security.rule", "rule",
                                     children=[_n("Allowed Origins",
                                                  "cmdb/waf/websocket-security.rule/allowed-origin-list")])])]),
        _n("MITB Protection", "cmdb/waf/mitb-policy", "mitb-protection",
           "Client Side Security",
           children=[_n("MITB Rules", "cmdb/waf/mitb-policy/rule-list",
                        children=[_n("MITB Rule", "cmdb/waf/mitb-rule", "mitb-rule",
                                     children=[
                                         _n("Protected Parameters",
                                            "cmdb/waf/mitb-rule/protected-parameter-list"),
                                         _n("Allowed External Domains",
                                            "cmdb/waf/mitb-rule/allowed-external-domains-list"),
                                     ])])]),
        _n("Subresource Integrity", "cmdb/waf/subresource-integrity-policy",
           "subresource-integrity-policy", "Client Side Security"),
        _n("Client Side Protection", "cmdb/waf/client-side-protection-policy",
           "client-side-protection-policy", "Client Side Security"),
        # -- Advanced Protection --------------------------------------------
        _n("CSRF Protection", "cmdb/waf/csrf-protection", "csrf-protection",
           "Advanced Protection",
           children=[
               _n("CSRF URL List", "cmdb/waf/csrf-protection/csrf-url-list"),
               _n("CSRF Page List", "cmdb/waf/csrf-protection/csrf-page-list"),
           ]),
        _n("Padding Oracle", "cmdb/waf/padding-oracle", "padding-oracle",
           "Advanced Protection",
           children=[_n("Protected URLs", "cmdb/waf/padding-oracle/protected-url-list")]),
        _n("URL Encryption", "cmdb/waf/url-encryption.url-encryption-policy",
           "url-encryption-policy", "Advanced Protection",
           children=[_n("Encryption Rules",
                        "cmdb/waf/url-encryption.url-encryption-policy/rule-list",
                        children=[_n("URL Encryption Rule",
                                     "cmdb/waf/url-encryption.url-encryption-rule", "rule",
                                     children=[
                                         _n("URL List",
                                            "cmdb/waf/url-encryption.url-encryption-rule/url-list"),
                                         _n("Exceptions",
                                            "cmdb/waf/url-encryption.url-encryption-rule/exceptions"),
                                     ])])]),
        _n("Link Cloaking", "cmdb/waf/link-cloaking.link-cloaking-policy",
           "link-cloaking-policy", "Advanced Protection",
           children=[_n("Cloaking Rules",
                        "cmdb/waf/link-cloaking.link-cloaking-policy/rule-list",
                        children=[_n("Link Cloaking Rule",
                                     "cmdb/waf/link-cloaking.link-cloaking-rule", "rule",
                                     children=[_n("Exceptions",
                                                  "cmdb/waf/link-cloaking.link-cloaking-rule/exceptions")])])]),
        _n("Hidden Field Protection", "cmdb/waf/hidden-fields-protection",
           "hidden-fields-protection", "Advanced Protection",
           children=[_n("Hidden Field Rules",
                        "cmdb/waf/hidden-fields-protection/hidden_fields_list",
                        children=[_n("Hidden Field Rule", "cmdb/waf/hidden-fields-rule",
                                     "hidden-field-rule",
                                     children=[_n("Hidden Field Names",
                                                  "cmdb/waf/hidden-fields-rule/hidden-field-name")])])]),
        _n("Parameter Validation", "cmdb/waf/parameter-validation-rule",
           "parameter-validation-rule", "Advanced Protection",
           children=[_n("Input Rules", "cmdb/waf/parameter-validation-rule/input-rule-list",
                        children=[_n("Input Rule", "cmdb/waf/input-rule", "input-rule",
                                     children=[_n("Parameters", "cmdb/waf/input-rule/rule-list")])])]),
        _n("File Upload Policy", "cmdb/waf/file-upload-restriction-policy",
           "file-upload-policy", "Advanced Protection",
           children=[
               _n("Upload Rules", "cmdb/waf/file-upload-restriction-policy/rule",
                  children=[
                      _n("File Security Rule", "cmdb/waf/file-upload-restriction-rule",
                         "file-upload-restriction-rule",
                         children=[
                             _n("File Types", "cmdb/waf/file-upload-restriction-rule/file-types"),
                             _n("Custom File Types",
                                "cmdb/waf/file-upload-restriction-rule/custom-file-types",
                                children=[
                                    _n("Custom File Type", "cmdb/waf/file-upload-custom-file-type",
                                       "file-type",
                                       children=[_n("Content Match Rule",
                                                    "cmdb/waf/file-upload-custom-file-type/file-content-match-rule")]),
                                ]),
                         ]),
                  ]),
           ]),
        _n("File Security Exception", "cmdb/waf/file-exception-policy", "file-exception-policy",
           "Advanced Protection",
           children=[_n("File Exceptions", "cmdb/waf/file-exception-policy/exception-list")]),
        _n("Web Shell Detection", "cmdb/waf/webshell-detection-policy",
           "webshell-detection-policy", "Advanced Protection",
           children=[_n("Fuzzy Disable List",
                        "cmdb/waf/webshell-detection-policy/fuzzy-disable-list")]),
        _n("DLP Policy", "cmdb/waf/dlp.policy", "dlp-policy", "Advanced Protection",
           # sub-table is 'dlp-rules' (fw6 objects carry sz_dlp-rules; registry
           # key dlp_policy_rule_item) — 'rule-list' was a doc-derived guess.
           children=[_n("DLP Rules", "cmdb/waf/dlp.policy/dlp-rules")]),
        # -- API / XML / JSON -----------------------------------------------
        _n("XML Validation", "cmdb/waf/xml-validation.policy",
           "xml-validation-policy / xml-protection", "API Protection",
           children=[_n("XML Rules", "cmdb/waf/xml-validation.policy/input-rule-list",
                        children=[_n("XML Protection Rule", "cmdb/waf/xml-validation.rule",
                                     "input-rule",
                                     children=[
                                         _n("XML Schema File", "cmdb/waf/xml-schema.file", "schema-file"),
                                         _n("XML DTD File", "cmdb/waf/xml-dtd.file", "dtd-file",
                                            children=[_n("DTD File List",
                                                         "cmdb/waf/xml-dtd.file/file-list")]),
                                         _n("WSDL File", "cmdb/waf/xml-wsdl.file", "wsdl-file"),
                                         _n("WS-Security Rule", "cmdb/waf/ws-security.rule",
                                            "ws-security",
                                            children=[
                                                _n("Namespace Mapping",
                                                   "cmdb/waf/ws-security.rule/namespace-mapping"),
                                                _n("Element List",
                                                   "cmdb/waf/ws-security.rule/element-list"),
                                            ]),
                                     ])])]),
        _n("JSON Validation", "cmdb/waf/json-validation.policy",
           "json-validation-policy / json-protection", "API Protection",
           children=[_n("JSON Rules", "cmdb/waf/json-validation.policy/input-rule-list",
                        children=[_n("JSON Protection Rule", "cmdb/waf/json-validation.rule",
                                     "input-rule",
                                     children=[
                                         _n("JSON Schema File", "cmdb/waf/json-schema.file", "schema-file"),
                                         _n("JSON Schema Group", "cmdb/waf/json-schema.group",
                                            "schema-group",
                                            children=[_n("Group Members",
                                                         "cmdb/waf/json-schema.group/members",
                                                         children=[_n("Member Schema File",
                                                                      "cmdb/waf/json-schema.file",
                                                                      "member-name")])]),
                                     ])])]),
        _n("OpenAPI Validation", "cmdb/waf/openapi-validation-policy",
           "openapi-validation-policy", "API Protection",
           children=[_n("Schema Files", "cmdb/waf/openapi-validation-policy/schema-file",
                        children=[_n("OpenAPI File", "cmdb/waf/openapi-file", "openapi-file")])]),
        _n("API Management Policy", "cmdb/waf/api-policy", "api-management-policy",
           "API Protection",
           children=[_n("API Rules", "cmdb/waf/api-policy/api-rule-list",
                        children=[_n("API Rule", "cmdb/waf/api-rules", "api-rule-name",
                                     children=[
                                         _n("Attach HTTP Header", "cmdb/waf/api-rules/attach-http-header"),
                                         _n("Match URL Prefixes", "cmdb/waf/api-rules/match-url-prefixes"),
                                         _n("Sub-URL Setting", "cmdb/waf/api-rules/sub-url-setting",
                                            children=[_API_USER_GROUP_REF]),
                                         _API_USER_GROUP_REF,
                                     ])])]),
        _n("Mobile API Protection",
           "cmdb/waf/mobile-api-protection.mobile-api-protection-policy",
           "mobile-api-protection", "API Protection",
           children=[_n("Mobile Rules",
                        "cmdb/waf/mobile-api-protection.mobile-api-protection-policy/rule-list",
                        children=[_n("Mobile API Rule",
                                     "cmdb/waf/mobile-api-protection.mobile-api-protection-rule",
                                     "rule",
                                     children=[_n("Mobile URL List",
                                                  "cmdb/waf/mobile-api-protection.mobile-api-protection-rule/url-list")])])]),
        _n("gRPC Policy", "cmdb/waf/grpc-security.policy", "grpc-policy", "API Protection",
           children=[_n("gRPC Rules", "cmdb/waf/grpc-security.policy/rule-list",
                        children=[_n("gRPC Security Rule", "cmdb/waf/grpc-security.rule", "rule",
                                     children=[_n("gRPC IDL File", "cmdb/waf/grpc-idl.file",
                                                  "idl-file")])])]),
        _n("GraphQL Validation", "cmdb/waf/graphql-validation.policy",
           "graphql-validation-policy", "API Protection",
           children=[_n("GraphQL Rules", "cmdb/waf/graphql-validation.policy/rule-list",
                        children=[_n("GraphQL Validation Rule",
                                     "cmdb/waf/graphql-validation.rule", "rule",
                                     children=[_n("URL List",
                                                  "cmdb/waf/graphql-validation.rule/url-list")])])]),
        # -- IP Protection (Geo IP / IP List / XFF bound to the WPP — the WPP
        #    fields geo-block-list-policy / ip-list-policy / x-forwarded-for-rule,
        #    confirmed live on fw2 7.6.8) ------------------------------------
        _n("Geo IP", "cmdb/waf/geo-block-list", "geo-block-list-policy", "IP Protection",
           children=[_n("Country List", "cmdb/waf/geo-block-list/country-list")]),
        _n("IP List", "cmdb/waf/ip-list", "ip-list-policy", "IP Protection",
           children=[_n("Members", "cmdb/waf/ip-list/members",
                        children=[_IP_GROUP_REF])]),
        _n("X-Forwarded-For", "cmdb/waf/x-forwarded-for", "x-forwarded-for-rule",
           "IP Protection",
           children=[_n("Trusted IP List", "cmdb/waf/x-forwarded-for/ip-list")]),
        # -- Application Delivery -------------------------------------------
        _n("URL Rewriting", "cmdb/waf/url-rewrite.url-rewrite-policy", "url-rewrite-policy",
           "Application Delivery",
           children=[
               _n("Rewrite Rules", "cmdb/waf/url-rewrite.url-rewrite-policy/rule",
                  children=[
                      _n("URL Rewriting Rule", "cmdb/waf/url-rewrite.url-rewrite-rule",
                         "url-rewrite-rule-name",
                         children=[
                             _n("Match Condition",
                                "cmdb/waf/url-rewrite.url-rewrite-rule/match-condition"),
                             _n("Header Insert",
                                "cmdb/waf/url-rewrite.url-rewrite-rule/header-insert"),
                             _n("Header Removal",
                                "cmdb/waf/url-rewrite.url-rewrite-rule/header-removal"),
                             _n("Response Header Insert",
                                "cmdb/waf/url-rewrite.url-rewrite-rule/response-header-insert"),
                             _n("Response Header Removal",
                                "cmdb/waf/url-rewrite.url-rewrite-rule/response-header-removal"),
                         ]),
                  ]),
           ]),
        _n("HTTP Authentication", "cmdb/waf/http-authen.http-authen-policy",
           "http-authen-policy", "Application Delivery",
           children=[_n("Auth Rules", "cmdb/waf/http-authen.http-authen-policy/rule",
                        children=[_n("HTTP Auth Rule", "cmdb/waf/http-authen.http-authen-rule",
                                     "http-authen-rule",
                                     children=[_n("Auth Rule Items",
                                                  "cmdb/waf/http-authen.http-authen-rule/rule")])])]),
        _n("Compression", "cmdb/waf/file-compress-rule", "file-compress-rule",
           "Application Delivery",
           children=[
               _n("Content Types", "cmdb/waf/file-compress-rule/content-types"),
               _n("Compression Exclusion URL", "cmdb/waf/exclude-url", "exclude-url",
                  children=[_n("Exclude Rules", "cmdb/waf/exclude-url/exclude-rules")]),
           ]),
        # Site Publishing (SSO) is a deep WAF subtree the WPP names by the
        # `site-publisher-helper` field (CLI ref; the older `site-publish-helper`
        # spelling is kept as an alternate so the clone matches whichever the live
        # REST payload uses). policy -> rule-list binds a site-publish-helper.rule,
        # which in turn names an authentication-server-pool + a form-based-delegation
        # (both WAF objects). The pool's members reference ldap/radius query objects
        # (User & Auth) and the rule may name a system SAML server — those are
        # cross-section, not carried.
        _n("Site Publishing", "cmdb/waf/site-publish-helper.policy",
           "site-publisher-helper / site-publish-helper", "Application Delivery",
           children=[
               _n("Site Publish Rules", "cmdb/waf/site-publish-helper.policy/rule-list",
                  children=[
                      _n("Site Publish Rule", "cmdb/waf/site-publish-helper.rule", "rule-name",
                         children=[
                             _n("Rule Items", "cmdb/waf/site-publish-helper.rule/rule-list"),
                             _n("Auth Server Pool",
                                "cmdb/waf/site-publish-helper.authentication-server-pool",
                                "auth-server-pool",
                                children=[_n("Pool Members",
                                             "cmdb/waf/site-publish-helper.authentication-server-pool/pserver-list")]),
                             _n("Form-Based Delegation",
                                "cmdb/waf/site-publish-helper.form-based-delegation",
                                "form-based-delegation",
                                children=[_n("Delegation Rules",
                                             "cmdb/waf/site-publish-helper.form-based-delegation/rule-list")]),
                         ]),
                  ]),
           ]),
        # -- Tracking / Other -----------------------------------------------
        _n("User Tracking", "cmdb/waf/user-tracking.policy",
           "user-tracking-policy / custom-tracking-policy", "Tracking",
           children=[_n("Tracking Rules", "cmdb/waf/user-tracking.policy/input-rule-list",
                        children=[_n("User Tracking Rule", "cmdb/waf/user-tracking.rule",
                                     "input-rule",
                                     children=[_n("Match Condition",
                                                  "cmdb/waf/user-tracking.rule/match-condition")])])]),
        _n("Waiting Room", "cmdb/waf/waiting-room-policy", "waiting-room-policy", "Tracking"),
        # The WPP's `custom-response` field — the page the client is served
        # INSTEAD of being bounced to `redirect-url`. UNDOCUMENTED on the 7.6.8
        # CLI reference page for this profile, so the appliance is the only
        # authority: `set custom-response ?` answers `<datasource>`. The table
        # is TWO-LEVEL (`config waf custom-response custom-response-policy`),
        # hence the dot in the REST path; every single-level spelling answers
        # -20001.
        #
        # THE POLICY HAS NO SCALAR FIELDS AT ALL — `name` plus the read-only
        # `sz_rule` counter, and its entire meaning lives in the `rule`
        # sub-table (the same shape as certificate.urlcert). Declared without
        # that sub-table it would land complete and completely inert. `rule` was
        # settled by CREATING a parent and reading the child path: it answers a
        # LIST, while `rule-list`/`rule_list` echo the PARENT object back —
        # which is what an unverified child path does on FortiWeb instead of
        # 404ing, and would re-POST the policy inside itself.
        _n("Custom Response", "cmdb/waf/custom-response.custom-response-policy",
           "custom-response", "Custom Response · served in place of redirect-url",
           children=[
               _n("Response Rules",
                  "cmdb/waf/custom-response.custom-response-policy/rule",
                  children=[
                      _n("Custom Response Rule",
                         "cmdb/waf/custom-response.custom-response-rule",
                         "custom-response-rule-name",
                         note="the response body: url + content (leaf on 7.6.8)"),
                  ]),
           ]),
        _n("Threat Score Profile", "cmdb/server-policy/pattern.threat-score-profile",
           "threat-score-profile", "Tracking"),
    ],
)


# --------------------------------------------------------------------------- #
#  Server Policy — fetch_policy_full() prewarm tasks + section workers         #
# --------------------------------------------------------------------------- #
SERVER_POLICY: DepNode = _n(
    "Server Policy",
    "cmdb/server-policy/policy",
    note="the root the exporter walks (fetch_policy_full)",
    children=[
        _n("Virtual Server", "cmdb/server-policy/vserver", "vserver", "Server Objects",
           children=[
               # The VIP list is a SUB-TABLE of the vserver (one row per VIP); each
               # row's `vip` field names the cmdb/system/vip object (ip/mask). So
               # vip-list has no `via` (by-parent), and "VIP address" is reached via
               # that row field — this is what lets a clone carry the VIP object.
               _n("Virtual IP (VIP list)", "cmdb/server-policy/vserver/vip-list",
                  children=[_n("VIP address", "cmdb/system/vip", "vip",
                               note="ip/mask -> resolved IP")]),
           ]),
        _n("Server Pool", "cmdb/server-policy/server-pool", "server-pool", "Server Objects",
           children=[
               # pserver-list rows are by-parent (deleted with the pool); each row
               # carries ip/domain/port/weight + per-server TLS and may reference a
               # SHARED health check and certificate (certificate/certificate-verify).
               _n("Real Servers (members)", "cmdb/server-policy/server-pool/pserver-list",
                  note="by-parent rows: ip/domain/port/weight, per-server TLS, "
                       "health + certificate refs",
                  children=[
                      # Where the two verify edges ACTUALLY live. They are NOT
                      # interchangeable: on a live appliance `certificate-verify`
                      # accepts a `certificate.verify` and rejects a
                      # `certificate.server-certificate-verify`, and
                      # `server-certificate-verify-policy` accepts exactly the
                      # opposite. Wiring either to the other's collection would
                      # carry an object the row cannot name.
                      _n("Certificate Verify (real server)",
                         "cmdb/system/certificate.verify", "certificate-verify",
                         "System · Certificates · Certificate Verify — real server "
                         "-> how the client certificate this server is offered "
                         "gets verified",
                         children=_CERT_VERIFY_REFS),
                      _n("Server Certificate Verify",
                         "cmdb/system/certificate.server-certificate-verify",
                         "server-certificate-verify-policy",
                         "System · Certificates · Certificate Verify — real server "
                         "-> how the BACK-END server's own certificate gets verified",
                         children=_CERT_VERIFY_REFS),
                  ]),
           ]),
        _n("Persistence Policy", "cmdb/server-policy/persistence-policy", "persistence-policy",
           "Server Objects"),
        _n("Allow List (URL/Host)", "cmdb/server-policy/allow-list", "allow-list",
           "Server Objects · per-policy allow list",
           children=[_n("Allow List Items", "cmdb/server-policy/allow-list/allow-list-items")]),
        _n("Web Acceleration Policy", "cmdb/server-policy/acceleration.policy",
           "acceleration-policy", "Application Delivery",
           children=[
               _n("Acceleration Exception", "cmdb/server-policy/acceleration.exception",
                  "exception",
                  children=[_n("Exception List",
                               "cmdb/server-policy/acceleration.exception/list")]),
           ]),
        _n("Web Scripting", "cmdb/server-policy/scripting", "scripting-list",
           "Application Delivery · custom scripts"),
        _n("Health Check", "cmdb/server-policy/health", "health", "Server Objects",
           children=[_n("Health Check Rules", "cmdb/server-policy/health/health-list")]),
        _n("Protected Hostnames (Allow Hosts)", "cmdb/server-policy/allow-hosts",
           "allow-hosts / http-protected-hostname", "Server Objects",
           children=[_n("Host List", "cmdb/server-policy/allow-hosts/host-list")]),
        # `adfs-certificate-service` rides these same two nodes: it names a
        # SERVICE despite the name. Inert on 7.6.8 in BOTH directions and
        # that is measured: the CLI has no such field even with `ssl
        # enable`, and REST accepts a PUT with 200 and reads the field back
        # as "" — the silent-discard trap.
        _n("Service", "cmdb/server-policy/service.predefined",
           "service / adfs-certificate-service",
           "Server Objects · predefined -> fallback service.custom"),
        _n("Custom Service", "cmdb/server-policy/service.custom",
           "service / adfs-certificate-service",
           "Server Objects · custom service (predefined ones are built-in, not cloned)"),
        _n("Local Certificate", "cmdb/system/certificate.local",
           "certificate / ssl-certificate", "System · Certificates"),
        # 1.5.0: this node used to be `certificate.local` reached `via` a
        # `certificate-verify` field on the SERVER POLICY, and both halves were
        # wrong in a way that hid the other. A Certificate Verify is its own
        # object -- settled by BINDING on fortiweb12 (7.6.8), the only test that
        # distinguishes a datasource from a name that merely looks similar:
        # `set certificate-verify <a real local certificate>` is REJECTED, and
        # the same field accepts a `certificate.verify`. And the field is not a
        # policy field at all (absent from `set ?` on `server-policy policy`,
        # gated or not) -- it lives on the REAL SERVER row, so hung here the
        # edge never fired and the wrong collection never got contradicted.
        # The policy's own client-verify edge is `ssl-client-verify`, which
        # accepts a `certificate.verify` and rejects a
        # `certificate.server-certificate-verify`.
        _n("Certificate Verify", "cmdb/system/certificate.verify", "ssl-client-verify",
           "System · Certificates · Certificate Verify — policy -> how client "
           "certificates are verified",
           children=_CERT_VERIFY_REFS),
        _n("Let's Encrypt Certificate", "cmdb/system/certificate.letsencrypt", "lets-certificate",
           "System · Certificates · ACME",
           children=[_n("SAN List", "cmdb/system/certificate.letsencrypt/san-list")]),
        # The members node is not decoration. Without it the group travelled as
        # an EMPTY SHELL -- the object was created at the destination, its rows
        # never were, and nothing reported the gap. A chain group with no
        # members serves a leaf certificate with no intermediates, which fails
        # verification on exactly the clients that do not cache the issuer.
        # Path verified on 7.6.8 with the discriminator this registry uses
        # everywhere: a real collection answers 200, an invented one 500/-20001.
        _n("Intermediate CA Group", "cmdb/system/certificate.intermediate-certificate-group",
           "intermediate-certificate-group", "System · Certificates",
           children=[_n("Intermediate CA Group Members",
                        "cmdb/system/certificate.intermediate-certificate-group/members")]),
        _n("SSL Ciphers Group", "cmdb/server-policy/ssl-ciphers.predefined",
           "ssl-ciphers-group", "Server Policy · SSL"),
        _n("SSL Ciphers Group (custom)", "cmdb/server-policy/ssl-ciphers.custom",
           "ssl-ciphers-group", "Server Policy · SSL · custom cipher group"),
        # ── Advanced SSL Settings ────────────────────────────────────────────
        # GATED, and the gate is the whole reason these four were missing for as
        # long as they were. On 7.6.8 the fields that name them DO NOT EXIST on a
        # policy whose `ssl` is `disable`: `set hpkp-header ?` answers "Parsing
        # error at 'hpkp-header'", not an empty datasource. Measured on
        # fortiweb12 by flipping `set ssl enable` inside a live edit context and
        # re-running `set ?` — eleven fields appear that were absent one command
        # earlier. An HTTP policy therefore carries no such reference, so no
        # amount of cloning HTTP policies could ever contradict their absence.
        #
        # HTTPS Header Insertion -> the HPKP profile. FLAT: `config ?` inside the
        # object is a parse error, so it has no sub-table, and it names nothing —
        # the pins are base64 SPKI fingerprints, plain strings, not certificate
        # names. (`pin-sha256` IS space-separated with a trailing space, exactly
        # like `scripting-list`; it is deliberately NOT in `_LIST_REF_FIELDS`,
        # because that table is for fields naming OBJECTS and these name none.)
        _n("HPKP Profile", "cmdb/system/certificate.hpkp", "hpkp-header",
           "System · Certificates · HTTPS header insertion (HPKP)"),
        # URL Certificate group — the empty-shell trap in its purest form.
        # `set ?` on the group answers a parse error: it has NO scalar fields at
        # all. `config ?` completes to exactly one sub-table, `list`, whose rows
        # are (url, require). Carried without its rows the group arrives field
        # for field complete and totally inert, and nothing reports the gap.
        _n("URL Certificate Group", "cmdb/system/certificate.urlcert", "urlcert-group",
           "System · Certificates · URL-based client certificate group",
           children=[_n("URL Certificate List",
                        "cmdb/system/certificate.urlcert/list")]),
        # `certificate-group` is gated TWICE — it needs `ssl enable` AND
        # `multi-certificate enable` (measured: setting the group alone answers
        # 200 and reads back EMPTY, and enabling the switch alone answers -56).
        # Its datasource is `certificate.multi-local`, NOT `certificate.local`
        # and not the SNI group. The object is flat (comment + rsa-cert +
        # ecc-cert + dsa-cert) and each of those three is its own `<datasource>`
        # onto `system certificate.local`, so a group that travels alone lands
        # naming up to three certificates the destination has never seen.
        _n("Multi-Certificate Group", "cmdb/system/certificate.multi-local",
           "certificate-group",
           "System · Certificates · multi-certificate (RSA/ECC/DSA)",
           children=[_n("Local Certificate (RSA/ECC/DSA)",
                        "cmdb/system/certificate.local",
                        "rsa-cert / ecc-cert / dsa-cert",
                        note="key material — reported, copied over SSH, never over REST")]),
        # ADFS reuses the SAME collection as `ssl-client-verify`, settled by
        # BINDING rather than by the similarity of the field name: both answer
        # `<datasource>  SSL client certificate verify` on a live appliance.
        _n("ADFS Certificate Verify", "cmdb/system/certificate.verify",
           "adfs-certificate-ssl-client-verify",
           "System · Certificates · Certificate Verify — ADFS client certificates",
           children=_CERT_VERIFY_REFS),
        _n("SNI Policy", "cmdb/system/certificate.sni",
           "sni-policy / sni-certificate / certificate-sni", "System · Certificates",
           children=[_n("SNI Members", "cmdb/system/certificate.sni/members")]),
        _n("Content Routing", "cmdb/server-policy/policy/http-content-routing-list",
           "deployment-mode = http-content-routing", "Server Policy",
           children=[
               _n("HTTP Content Routing Policy", "cmdb/server-policy/http-content-routing-policy",
                  "content-routing-policy-name",  # HTTP CR row names the policy via this field (NOT the urn tail)
                  children=[
                      _n("Match Conditions",
                         "cmdb/server-policy/http-content-routing-policy/content-routing-match-list",
                         children=[
                             _n("Server Pool", "cmdb/server-policy/server-pool", "server-pool",
                                note="per-match backend",
                                children=[_n("Real Servers (members)",
                                             "cmdb/server-policy/server-pool/pserver-list",
                                             note="by-parent backend rows")]),
                             _n("Web Protection Profile",
                                "cmdb/waf/web-protection-profile.inline-protection",
                                "web-protection-profile",
                                note="-> Web Protection Profile tree"),
                             _n("IP Group", "cmdb/server-policy/ip-group", "ip-list",
                                note="match by source IP group",
                                children=[_n("IP Group Members",
                                             "cmdb/server-policy/ip-group/members")]),
                         ]),
                      _n("Default Server Pool", "cmdb/server-policy/server-pool", "server-pool",
                         children=[_n("Real Servers (members)",
                                      "cmdb/server-policy/server-pool/pserver-list",
                                      note="by-parent backend rows")]),
                  ]),
           ]),
        _n("ZTNA Profile", "cmdb/server-policy/ztna-profile", "ztna-profile",
           "Application Delivery · ZTNA"),
        _n("Traffic Mirror Profile", "cmdb/server-policy/traffic-mirror", "traffic-mirror-profile",
           "System · traffic mirroring"),
        _n("V-Zone (Bridge)", "cmdb/system/v-zone", "v-zone",
           "Network · transparent-mode bridge"),
        _n("Replacement Message Group", "cmdb/system/replacemsg", "replacemsg",
           "System · block/error page set (SHARED; pages are a global catalog, "
           "not per-policy — not expanded)"),
        # ── FTP Protection Profile ───────────────────────────────────────
        # Invisible until now for the same reason the Advanced SSL block
        # was: the field is GATED, this time on `protocol`. Measured on
        # fortiweb12 (7.6.8): on a policy whose `protocol` is HTTP the CLI
        # answers "Parsing error at 'ftp-protection-profile'"; on one whose
        # `protocol` is FTP it answers "<datasource>  ftp application
        # protection profile". `protocol` is immutable after creation
        # ("attribute after created. Command fail. Permission denied."), so
        # it cannot be flipped on an existing policy to find out, and a lab
        # of HTTP policies can never produce the reference.
        #
        # The collection is NOT reachable over REST on this firmware — see
        # `_REST_UNREACHABLE` in services/clone.py. The node exists so the
        # reference is NAMED, not so it can be copied.
        _n("FTP Protection Profile", "cmdb/waf/ftp-protection-profile",
           "ftp-protection-profile",
           "FTP Security · gated on `protocol FTP`",
           children=[
               _n("FTP File Security", "cmdb/waf/ftp-file-security",
                  "ftp-file-check"),
               _n("Geo IP Block List", "cmdb/waf/geo-block-list", "ftp-geo-ip"),
               _n("IP List", "cmdb/waf/ip-list", "ftp-ip-check"),
               _n("FTP Command Restriction",
                  "cmdb/waf/ftp-command-restriction-rule",
                  "ftp-restriction-command-type"),
           ]),
        _n("Web Protection Profile", "cmdb/waf/web-protection-profile.inline-protection",
           "web-protection-profile",
           "Web Protection · -> Web Protection Profile tree (its own root below)"),
    ],
)


ROOTS: tuple[DepNode, ...] = (SERVER_POLICY, WEB_PROTECTION_PROFILE)


# --------------------------------------------------------------------------- #
#  Exporter function inventory — answers "where are the functions?"            #
#  Each entry records the role and WHERE it now lives in this repo (or "" if   #
#  still only on the USB script).                                              #
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class ExporterFunc:
    name: str
    role: str
    ported: str = ""  # in-repo location, or "" when not yet ported


EXPORTER_FUNCTIONS: tuple[ExporterFunc, ...] = (
    ExporterFunc("fetch_policy_full(api, policy)",
                 "Master walk: given a Server Policy, fan out and fetch every linked "
                 "object (vserver/VIP, pool+members, health, allow-hosts, cert, content "
                 "routing, service, SSL, SNI, WAF) in parallel.",
                 "app/services/operations.py · FortiWebOps.policy_full"),
    ExporterFunc("fetch_waf_for_object(api, obj)",
                 "Fetch a Web Protection Profile and all ~40 components for any object "
                 "that references one (the policy or a content-routing match).",
                 "app/services/operations.py (composite reads)"),
    ExporterFunc("raw_get / _raw_get_uncached(api, urn, mkey)",
                 "Low-level REST GET by URN, bypassing the SDK marshmallow so missing "
                 "optional fields never crash a read.",
                 "app/clients/versioned.py · call/get_object"),
    ExporterFunc("safe_get(api, module, mkey)",
                 "GET by registry module name with graceful fallback.",
                 "app/clients/versioned.py"),
    ExporterFunc("install_api_get_cache(api) / cache_clear()",
                 "Per-run request memoisation so the parallel fan-out hits cache.",
                 "app/services/cache.py · TTLCache"),
    ExporterFunc("to_dict / to_list / attr / unwrap / clean_dict / is_empty",
                 "Normalisation helpers (dataclass-or-dict access, strip empty/default).",
                 "app/library/inspector.py"),
    ExporterFunc("tree_lines / render_tree / kv_block / section_header / fmt_kv / fmt_section",
                 "Human-readable rendering of a fetched object graph.",
                 "app/library/inspector.py"),
    ExporterFunc("generate_readable_report(report)",
                 "Compose the full per-policy textual report from the fetched graph.",
                 ""),
    ExporterFunc("process_fortiweb(fqdn, user, password)",
                 "Per-device driver: connect, list policies, run fetch_policy_full on each.",
                 "app/services/operations.py + app/ui/pages/workspace_page.py"),
    ExporterFunc("install_api_get_cache / ping / parse_section_selection / prompt_sections",
                 "CLI plumbing (reachability probe, interactive section picker).",
                 ""),
)


# --------------------------------------------------------------------------- #
#  Traversal + rendering                                                       #
# --------------------------------------------------------------------------- #
def iter_nodes(
    roots: Iterable[DepNode] = ROOTS, _depth: int = 0
) -> Iterator[tuple[int, DepNode]]:
    """Yield ``(depth, node)`` pre-order. Roots are depth 0."""
    for node in roots:
        yield _depth, node
        if node.children:
            yield from iter_nodes(node.children, _depth + 1)


def render_tree(roots: Iterable[DepNode] = ROOTS, *, show_urn: bool = True) -> str:
    """Render the tree with ``-->`` arrows, one extra dash per level (depth 1 =
    ``-->``, depth 2 = ``--->`` …). Each line shows the FortiWeb GUI name,
    optionally followed by the REST URN.
    """
    lines: list[str] = []
    for depth, node in iter_nodes(roots):
        prefix = "" if depth == 0 else ("-" * (depth + 1) + "> ")
        line = f"{prefix}{node.fortiweb}"
        if show_urn and node.urn:
            line += f"   ({node.urn})"
        lines.append(line)
    return "\n".join(lines)


def render_tree_box(roots: Iterable[DepNode] = ROOTS, *, show_urn: bool = False) -> str:
    """Render in the **exporter's own box-drawing style** — the way
    ``fortiweb_policy_inspector.py`` prints a policy: ``├── `` / ``└── `` branches
    joined by ``│   `` rails. Each root sits flush-left and its children indent
    under it. :func:`render_tree` is the lighter ``-->`` arrow variant.
    """
    lines: list[str] = []

    def _label(node: DepNode) -> str:
        return f"{node.fortiweb}   ({node.urn})" if show_urn and node.urn else node.fortiweb

    def _walk(nodes: tuple[DepNode, ...], prefix: str) -> None:
        for i, node in enumerate(nodes):
            last = i == len(nodes) - 1
            lines.append(f"{prefix}{'└── ' if last else '├── '}{_label(node)}")
            if node.children:
                _walk(node.children, prefix + ("    " if last else "│   "))

    rts = tuple(roots)
    for idx, root in enumerate(rts):
        lines.append(_label(root))
        _walk(root.children, "")
        if idx != len(rts) - 1:
            lines.append("")
    return "\n".join(lines)


def node_count(roots: Iterable[DepNode] = ROOTS) -> int:
    return sum(1 for _ in iter_nodes(roots))


def dep_node_for_urn(urn: str, roots: Iterable[DepNode] = ROOTS) -> DepNode | None:
    """The richest :class:`DepNode` whose ``urn`` matches, anywhere in ``roots``.

    The same urn can appear more than once (a pool is both a top-level object and
    a per-match backend) — return the occurrence with the MOST descendants so the
    caller gets the complete subtree, not a bare leaf. ``None`` when no node uses
    that urn.
    """
    best: DepNode | None = None
    best_count = -1
    for _depth, node in iter_nodes(tuple(roots)):
        if node.urn == urn:
            count = node_count((node,))
            if count > best_count:
                best, best_count = node, count
    return best


__all__ = [
    "DepNode",
    "ExporterFunc",
    "SERVER_POLICY",
    "WEB_PROTECTION_PROFILE",
    "ROOTS",
    "EXPORTER_FUNCTIONS",
    "iter_nodes",
    "render_tree",
    "render_tree_box",
    "node_count",
    "dep_node_for_urn",
]

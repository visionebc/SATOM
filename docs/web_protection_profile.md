# Web Protection Profile — full reference

> Authoritative, field-level reference for the FortiWeb **Web Protection Profile**
> (WPP) and its entire ~40-sub-policy dependency graph. Source of truth: the team's
> `fortiweb_api` SDK (`cmdb/waf/` marshmallow schemas, FortiWeb OS 7.6 / API `v2.0`,
> **172 schemas**), cross-checked against the in-repo registry
> (`app/registry/data/endpoints.yaml`, **191 `cmdb/waf/*` endpoints**), the
> dependency tree (`app/registry/dependencies.py`, `WEB_PROTECTION_PROFILE`,
> **136 nodes, depth 7**), and the **official FortiWeb 7.6.4 admin guide**
> (docs.fortinet.com — a JS SPA, scraped via the internal Firecrawl,
> [[internal-firecrawl-lan]]) for GUI labels / menu sections / enum choices.
>
> The companion of [`server_policy.md`](server_policy.md). Keep this current when the
> registry, `dependencies.py`, or the WPP specs (`app/ui/pages/wpp_specs.py`) change.

REST convention: a field's wire name is the SDK attribute with `_` → `-`
(`signature_rule` → `signature-rule`). Every **named object's mkey is `name`**;
every sub-table row's mkey is `id`. Sub-tables are **by-parent** (POST/PUT/DELETE
carry the parent's `mkey`); a rule-list row carries only the *name* of a separate
rule object (see §3). The same sub-table READ-scoping quirk as Server Policy applies
— read a by-parent list through the LOGICAL endpoint with `?mkey=<parent>`
(`scoped_rows`), never path-style, or an empty list leaks the whole parent
collection (`docs/server_policy.md` §0).

---

## 1. What a Web Protection Profile is

A WPP (`cmdb/waf/web-protection-profile.inline-protection`, SDK
`WebProtectionProfileInline`; also `.offline-protection`) is the **WAF bundle** a
Server Policy binds through its `web-protection-profile` field. It holds *no nested
objects of its own*: each protection feature is a **string field naming another
`cmdb/waf/*` object** (Signatures, IP List, Bot Mitigation, the API/XML/JSON
rules…). 36 of its fields are such references; the rest are scalars/enums. In the
7.6 GUI it renders as one big form of dropdowns grouped into the menu sections
**Standard Protection / Client-Side Security / Advanced Protection / API
Protection / Application Delivery / Tracking** — which is exactly how
`ui/pages/wpp_view.WppViewDialog` lays it out.

The referenced objects nest their own rule-lists, **up to six levels deep**:

```
Web Protection Profile
└─ API Gateway (api-management-policy → cmdb/waf/api-policy)
   └─ API Gateway Rule (api-rule-list → cmdb/waf/api-rules)
      └─ API User Group (allow-user-group → cmdb/waf/api-user-group)
         └─ API User (user-list → cmdb/waf/api-users)
            └─ IP Access List / HTTP Referer List   (← 6th level)
```

---

## 2. WPP field inventory (~54 fields)

`name` is the mkey. `q_ref` / `q_ref_string` are read-only. **REF** = the field names
another `cmdb/waf/*` object (a dependency edge → §3); the rest are scalars/enums.

### 2.1 Sub-policy references (36 REFs — the dropdowns)

Grouped as the 7.6 GUI menu does (label · `wpp-field` → target object):

- **Standard Protection** — Signatures `signature-rule`→`signature` · HTTP Protocol
  Constraints `http-protocol-parameter-restriction`→`http-protocol-parameter-restriction`
  · X-Forwarded-For `x-forwarded-for-rule`→`x-forwarded-for` · Allow Method
  `allow-method-policy`→`allow-method-policy` · IP List `ip-list-policy`→`ip-list` ·
  Geo IP Block `geo-block-list-policy`→`geo-block-list` · URL Access
  `url-access-policy`→`url-access.url-access-policy` · Custom Access
  `custom-access-policy`→`custom-access.policy` · DoS Protection
  `application-layer-dos-prevention`→`application-layer-dos-prevention` · Bot
  Mitigation `bot-mitigate-policy`→`bot-mitigate-policy` · Syntax-Based Detection
  `syntax-based-attack-detection`→`syntax-based-attack-detection`.
- **Client-Side Security** — HTTP Header Security `http-header-security` · CORS
  `cors-protection-policy` · Cookie Security `cookie-security-policy`→`cookie-security`
  · WebSocket `websocket-security-policy`→`websocket-security.policy` · MITB
  `mitb-protection`→`mitb-policy`.
- **Advanced Protection** — CSRF `csrf-protection` · Padding Oracle `padding-oracle`
  · URL Encryption `url-encryption-policy`→`url-encryption.url-encryption-policy` ·
  Link Cloaking `link-cloaking-policy`→`link-cloaking.link-cloaking-policy` · Hidden
  Fields `hidden-fields-protection` · Parameter Validation
  `parameter-validation-rule` · File Security `file-upload-policy`→`file-upload-restriction-policy`
  · File Security Exception `file-exception-policy` · Web Shell Detection
  `webshell-detection-policy`.
- **API Protection** — XML `xml-validation-policy`→`xml-validation.policy` · JSON
  `json-validation-policy`→`json-validation.policy` · OpenAPI
  `openapi-validation-policy` · API Gateway `api-management-policy`→`api-policy` ·
  Mobile API `mobile-api-protection`→`mobile-api-protection.*` · gRPC
  `grpc-policy`→`grpc-security.policy`.
- **Application Delivery** — URL Rewriting `url-rewrite-policy`→`url-rewrite.url-rewrite-policy`
  · HTTP Authentication `http-authen-policy`→`http-authen.http-authen-policy` ·
  Compression `file-compress-rule`.
- **Tracking** — User Tracking `user-tracking-policy`→`user-tracking.policy` ·
  Threat Scoring `threat-score-profile`.

### 2.2 Scalars / enums (not edges)

`client-management` · `http-session-cookie` · `http-session-timeout` ·
`ip-intelligence` · `mobile-app-identification` · `amf3-protocol-detection` ·
`redirect-url` · `rdt-reason` · `custom-response` · `owasp-api-top10-log-field` ·
`site-publish-helper` · `token-secret` · `token-header` · `comment`. **Quarantine
(FortiGate integration):** `fortigate-quarantined-ips` ·
`quarantined-ip-action` · `quarantined-ip-severity` · `quarantined-ip-trigger`.

---

## 3. Dependency graph — the sub-policy chains

Each sub-policy is its own object; many hang **rule-lists** and **member-lists**
under themselves. Two structural shapes recur:

- **Inline sub-table** (owned rows): the policy directly owns a list of rows
  (IP List → members, Geo → countries, Signatures → main-class-list, Cookie
  Security → exceptions, CSRF → url/page lists…). Rows are by-parent; edited in
  place.
- **Binding rule-list → named rule**: the policy owns a thin list whose each row
  only *names* a **separate top-level rule object**, which in turn owns its own
  sub-tables. e.g. URL Rewriting `policy → rule-list (url-rewrite-rule-name) →
  url-rewrite-rule → {header-insert, header-removal, match-condition, …}`. This is
  how FortiWeb keeps rules reusable across policies, and it is the source of the
  deep nesting.

Sub-policies that use the **binding** shape (`policy` → list-row field → `named
rule`): Signatures-group (`custom-protection-rule`), URL Access
(`url-access-rule-name`), Custom Access (`rule-name`), Syntax/Bot (refs),
Parameter Validation (`input-rule`), File Security (`file-upload-restriction-rule`
→ rule → `file-type` → custom file type), XML/JSON (`input-rule` → rule → schema /
ws-security / schema-group), OpenAPI (`openapi-file`), **API Gateway**
(`api-rule-name` → rule → `allow-user-group` → `api-user-name` → user), Mobile API
(`rule`), gRPC (`rule` → `idl-file`), URL Rewriting (`url-rewrite-rule-name`),
HTTP Auth (`http-authen-rule`), URL Encryption / Link Cloaking / WebSocket / MITB /
CORS (`cors-rule` → rule → `allowed-origins-list`), User Tracking (`input-rule`).

The full graph is the data in `app/registry/dependencies.py` `WEB_PROTECTION_PROFILE`
(136 nodes, all registry-backed, max depth 7) and rendered as the
`├──`/`└──` tree by `render_tree_box`. Highlights of the deepest chains:

| Sub-policy | Named rule(s) it nests | Their sub-tables |
|---|---|---|
| API Gateway (`api-policy`) | `api-rules` → `api-user-group` → `api-users` | match-url-prefixes, attach-http-header, sub-url-setting; user-list; ip-access-list, http-referer-list |
| URL Rewriting (`url-rewrite.url-rewrite-policy`) | `url-rewrite.url-rewrite-rule` | match-condition, header-insert/removal, response-header-insert/removal |
| XML Validation (`xml-validation.policy`) | `xml-validation.rule` → `xml-schema.file`, `xml-wsdl.file`, `ws-security.rule` | ws-security: namespace-mapping, element-list |
| JSON Validation (`json-validation.policy`) | `json-validation.rule` → `json-schema.file`, `json-schema.group` | schema-group members |
| File Security (`file-upload-restriction-policy`) | `file-upload-restriction-rule` → `file-upload-custom-file-type` | file-types, custom-file-types; content-match-rule |
| Bot Mitigation (`bot-mitigate-policy`) | `known-bots`, `bot-deception`, `biometrics-based-detection`, `threshold-based-detection.policy`, `bot-mitigation-exception` | disable-lists, url-lists, exception-element-list |

---

## 4. Enum vocabularies (FortiWeb 7.6.4 GUI)

Editable combos in the app — an unexpected device token always survives. From the
admin guide (per-module action sets vary; this is the union):

- **Action** — `Alert` · `Alert & Deny` · `Deny (no log)` · `Period Block` ·
  `Redirect` · `Send HTTP Response` (+ `Pass`/`Continue` on URL Access; `Remove
  Cookie` on Cookie Security; `Bypass` on Known Bots). XML Validation omits *Deny
  (no log)*.
- **Severity** — `Informative` · `Low` · `Medium` · `High`.
- **URL / Host type** — `Simple String` (`plain`) · `Regular Expression`
  (`regular`).
- **Block Period** — seconds, usually `1–3600` (API Gateway `1–10000`; IP List
  `1–600`).
- **Trigger Policy** — a reference to a `cmdb/log/trigger-policy` (log/alert
  trigger), surfaced as a dropdown (option source `trigger_policies`).
- Feature-specific: Cookie Security `security-mode` = None/Signed/Encrypted ·
  CORS `allowed-credentials` = None/TRUE/FALSE · Compression `compression-type` =
  gzip/brotli/zstd/deflate · WS-Security `direction` = request/response · HTTP Auth
  `authen-type` = basic/digest/ntlm.

---

## 5. Editing model (how the app exposes all of this)

The WPP is edited from **Web Protection** (main sidebar; CONFIG_WRITE + unlock) via
`ui/pages/wpp_view.WppViewDialog` — the FortiWeb-style form. Each sub-policy is a
dropdown with **Edit…** (open the selected object) and **＋** (create a new one).
Every referenced object — and every level below it — is a curated
`objform.ObjectSpec` in `app/ui/pages/wpp_specs.py` (~160 specs), so the shared
`objform.ObjectEditDialog` renders it like FortiWeb's own sub-page:

- **inline sub-tables** → Add / Edit / Delete rows in place;
- **binding rule-lists** → `SubTableSpec.ref_spec_key` gives the row an **Edit
  rule…** button that opens the *named* rule (and its children);
- **reference fields** to an object that has a spec get a **✎** (edit the selected)
  next to the **＋** (create), so existing deep references are reachable, not just
  new ones.

Field names/enums are curated from the SDK + admin guide; the long tail of fields
auto-renders (`show_uncurated`) with an **Edit raw JSON…** escape, so nothing is
ever uneditable. Every write goes through `FortiWebOps` (snapshot + audit +
change-history + dry-run; unlock + confirm on a real write) — never a blind write.
WPP **contents** are read-only from a live Server Policy (the policy form's WPP is a
changeable *dropdown*, "View profile details" opens it read-only); they are edited
here on the Web Protection page or, as desired-state templates, in Settings →
Templates (locked references → clone to edit).

---

## 6. Shared vs owned

A WPP is **usually shared** — many Server Policies bind the same profile, and many
profiles bind the same sub-policy object (one Signatures policy, one Bot Mitigation
policy reused across the fleet). So:

- Deleting a Server Policy never deletes its WPP (it is in the *usually shared*
  class; `docs/server_policy.md` §5).
- A sub-policy object is reusable across WPPs; editing it affects every profile
  that names it. The named rule objects (`url-rewrite-rule`, `api-rules`,
  `xml-validation.rule`…) are likewise shared building blocks.
- **By-parent sub-tables** (members, rule-lists, exception-lists) are owned by
  their parent and deleted with it.
- **Certificates** referenced by WS-Security / XML rules move only over SSH
  (never via REST) — flagged, never carried by a clone.

---

## 7. Where this lives in the repo

| Concern | File |
|---|---|
| WPP dependency tree (this graph, as data) | `app/registry/dependencies.py` (`WEB_PROTECTION_PROFILE`; 136 nodes) |
| Endpoint URNs per API version | `app/registry/data/endpoints.yaml` (191 `cmdb/waf/*`) |
| Curated edit specs (the ~160 forms) | `app/ui/pages/wpp_specs.py` |
| The FortiWeb-style WPP form | `app/ui/pages/wpp_view.py` (`WppViewDialog`) |
| The shared object-edit modal + engine | `app/ui/pages/objform.py` (`ObjectEditDialog`, `SubTableSpec.ref_spec_key`, ref `✎`) |
| Web Protection page (device → WPP → form) | `app/ui/pages/web_protection_page.py` |
| CRUD with snapshot + audit + dry-run | `app/services/operations.py` (`FortiWebOps`) |
| Specs regression guard | `tests/test_wpp_specs.py` |

Vendor SDK (offline ground truth, not committed):
`/Volumes/DEBIAN 12_5/py_scripts/fortiweb_api/.../v2_0/cmdb/waf/` — 172 schemas.

---

## 8. Coverage & cross-validation (2026-06-21)

- **Registry:** every one of the 136 `WEB_PROTECTION_PROFILE` tree nodes resolves to
  an `endpoints.yaml` endpoint (`dependencies.coverage` → 136/136, 0 missing).
- **Specs:** all 36 sub-policies + their named rules + sub-tables + leaf rows are
  curated (`wpp_specs.WPP_SPECS`, ~160 `ObjectSpec`); `tests/test_wpp_specs.py`
  asserts every endpoint / `row_spec_key` / `ref_spec_key` / ref `source` resolves,
  and that the API-Gateway chain is editable **6 levels deep**.
- **SDK:** field/wire names taken verbatim from the marshmallow schemas (191
  registry waf endpoints parsed). 9 registry-only objects have **no SDK schema**
  (`advanced-bot-protection`, `bot-detection-policy`, `client-side-protection`,
  `dlp-policy`, `graphql-validation-policy`, `subresource-integrity`,
  `threat-score-profile`, `waiting-room-policy`, `web-cache-policy`) — added from
  live probes / docs; they auto-render whatever the device returns.
- **Admin guide (7.6.4, Firecrawl):** GUI labels, menu sections and the enum
  choices in §4 were cross-checked against docs.fortinet.com. Notes worth heeding:
  *Threat Score* has **no dedicated config dialog** (it is a per-module "Threat
  Weight" field — modelled as such); *X-Forwarded-For* has no standalone page (its
  Trusted-IP sub-table is modelled). Action/Severity enum *order* and a few defaults
  can shift by minor build — the combos are editable, and a real round-trip on a box
  with live profiles (fw1 7.6.8) is the final check before non-dry-run pushes.

**Not yet live-verified end-to-end:** the deep WRITE path (creating/editing a
named rule + its sub-rows on a real device through the binding endpoints) follows
the same shape proven for Server Policy sub-tables but has not been round-tripped
on a box with rich WPP data. Keep dry-run default; review enums against the target
firmware first.

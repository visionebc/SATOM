# Server Policy — full reference

> Authoritative, field-level reference for the FortiWeb **Server Policy** object and
> its entire dependency graph. Source of truth: the team's `fortiweb_api` SDK
> (`cmdb/` marshmallow schemas, FortiWeb OS 7.6 / API `v2.0`) cross-checked against
> the in-repo registry (`app/registry/data/endpoints.yaml`) and dependency tree
> (`app/registry/dependencies.py`). Built because firecrawl/docs.fortinet.com is a
> JS-rendered SPA that the built-in fetchers can't read — the SDK is more complete
> and exact than the public docs anyway, and it is the same SDK the registry was
> derived from.
>
> Keep this current when the registry or `dependencies.py` change.

REST convention: a field's wire name is the SDK attribute with `_` → `-`
(`web_protection_profile` → `web-protection-profile`). Every named object's **mkey
is `name`**; every sub-table row's mkey is `id`. Sub-tables are **by-parent**
(POST/PUT/DELETE carry the parent's `mkey`), they never have their own reference edge.

> ⚠ **Sub-table READ scoping (FortiWeb quirk, verified live on fw1 7.6.8).** Read a
> by-parent sub-table through the LOGICAL endpoint with `?mkey=<parent>`
> (`get_object`), NOT the path-style `get_raw('/parent/<key>/<sub-list>')`. When the
> sub-table is empty (or the path form doesn't apply) FortiWeb **echoes the whole
> parent collection** — so a path-style read of one pool's `pserver-list` returns
> *every* pool, one vserver's `vip-list` returns *every* vserver, etc. The composite
> readers use `services.clone.scoped_rows` (logical `?mkey=` first, `get_raw`
> fallback) precisely to avoid this leak.

---

## 1. What a Server Policy is

A Server Policy (`cmdb/server-policy/policy`, SDK `ServerPolicy`) is the top object
that ties everything together: it binds a **Virtual Server** (the listener) to a
**Server Pool** (the back-ends), exposes them on an **HTTP/HTTPS Service** (port),
applies a **Web Protection Profile** (the WAF), and layers TLS, certificates,
content-routing, persistence, allow-lists, acceleration and logging on top.

`deployment_mode` decides the shape:

| `deployment-mode` | Meaning |
|---|---|
| `single-server` / `server-pool` | one back-end pool serves all matched traffic |
| `http-content-routing` | route per request to different pools/WPPs via the content-routing list |
| `offline-protection` / others | detection / out-of-line modes |

---

## 2. Server Policy field inventory (~108 fields)

`name` is the mkey. `q_ref` / `q_ref_string` are read-only. The only nested
sub-table is `http_content_routing_list`. **REF** = the field names another cmdb
object (a dependency edge); the rest are scalars/enums/ints.

### 2.1 Identity / deployment
`name` · `deployment_mode` (enum) · `protocol` (enum) · `status` (enable/disable) ·
`comment` · `case_sensitive` · `noparse` (passthrough) · `tags` · `monitor_mode`
(detection-only) · `tlog` (traffic logging) · `ssl` · `implicit_ssl`.

### 2.2 Connectivity (Server Objects) — REFs
| Field | Refers to |
|---|---|
| `vserver` | **REF** → `server-policy/vserver` (Virtual Server) |
| `v_zone` | **REF** → interface / V-zone (transparent mode) — *no registry endpoint* |
| `service` | **REF** → `server-policy/service.predefined` / `.custom` (HTTP port) |
| `https_service` | **REF** → `server-policy/service.*` (HTTPS port) |
| `server_pool` | **REF** → `server-policy/server-pool` |
| `allow_hosts` | **REF** → `server-policy/allow-hosts` (Protected Hostnames) |
| `allow_list` | **REF** → `server-policy/allow-list` (per-policy URL/host allow list) |
| `proxy_protocol` / `use_proxy_protocol_addr` | enum (PROXY protocol) |
| `block_port` | enum |

### 2.3 Protection — REFs
| Field | Refers to |
|---|---|
| `web_protection_profile` | **REF** → `waf/web-protection-profile.inline-protection` (→ §4) |
| `ftp_protection_profile` | **REF** → FTP profile — *no registry endpoint* |
| `acceleration_policy` | **REF** → `server-policy/acceleration.policy` |
| `replacemsg` | **REF** → `system/replacemsg` (block/error pages — SHARED) |
| `web_cache` / `web_cache_storage` | enum/scalar |
| `scripting` / `scripting_list` | `scripting` enum; `scripting_list` **REF** → `server-policy/scripting` |
| `ztna_profile` | **REF** → ZTNA profile — *no registry endpoint* |

### 2.4 TLS / certificates
`certificate_type` (local/letsencrypt/multi) ·
`certificate` **REF** → `system/certificate.local` ·
`multi_certificate` · `certificate_group` / `intermediate_certificate_group` **REF**
(cert group — *no dedicated endpoint*) ·
`lets_certificate` **REF** → `system/certificate.letsencrypt` ·
`ssl_client_verify` **REF** (client-cert CA verify → `certificate.local`) ·
`adfs_certificate_service` / `adfs_certificate_ssl_client_verify` **REF** ·
`urlcert` / `urlcert_group` / `urlcert_hlen` (URL-based cert — *no endpoint*) ·
`client_certificate_forwarding` (+ `_sub_header`, `_cert_header`).

**SNI:** `sni` (enable) · `sni_certificate` **REF** → `system/certificate.sni` · `sni_strict`.

**Ciphers/versions:** `use_ciphers_group` · `ssl_ciphers_group` **REF** →
`server-policy/ssl-ciphers.predefined` / `.custom` · `ssl_cipher` · `ssl_custom_cipher`
· `tls13_custom_cipher` · `tls_v10` / `tls_v11` / `tls_v12` / `tls_v13` · `ssl_noreg` ·
`rfc7919_comply` / `supported_groups` · `ssl_quiet_shutdown` · `ssl_session_timeout`.

### 2.5 HSTS / HPKP / CSP / cookies
`hsts_header` · `hsts_max_age` · `hsts_include_subdomains` · `hsts_preload` ·
`hpkp_header` **REF** (HPKP profile — *no endpoint*) · `content_security_policy_inline`
· `sessioncookie_enforce` · `internal_cookie_httponly` / `_secure` / `_samesite` /
`_samesite_value`.

### 2.6 Retry / timeouts / buffers
`retry_on` · `retry_on_cache_size` · `retry_on_connect_failure` ·
`retry_times_on_connect_failure` · `retry_on_http_layer` · `retry_times_on_http_layer`
· `retry_on_http_response_codes` · `replacemsg_on_connect_failure` ·
`tcp_recv_timeout` · `http_header_timeout` · `tcp_conn_timeout` · `client_timeout` ·
`half_open_threshold` · `send_buffers_number` · `http_parse_max_size` · `http_pipeline`
· `http2` · `chunk_encoding` · `payload_based_content_type`.

### 2.7 Traffic mirror / content routing / misc
`traffic_mirror` (enum) · `traffic_mirror_profile` **REF** (*no endpoint*) ·
`traffic_mirror_type` · `sz_http_content_routing_list` (row count) ·
`http_content_routing_list` (**sub-table** → §3, active when
`deployment_mode = http-content-routing`) · `real_ip_addr` · `client_real_ip` /
`_random_port` · `prefer_current_session` · `reply_100_continue` /
`forward_expect_100_continue` · `transaction_based_persistence` · `syncookie` ·
`http_to_https` · `redirect_naked_domain` · `data_capture_port`.

---

## 3. Dependency graph — linked objects

Every object a Server Policy references, or that hangs under it, in the order the
tree (`dependencies.py SERVER_POLICY`) walks them. **via** = the parent field that
points at the child. ⊂ = by-parent sub-table.

| Object | REST urn | mkey | Sub-tables (⊂) | Reached via |
|---|---|---|---|---|
| Virtual Server | `cmdb/server-policy/vserver` | name | ⊂ `vip-list` | policy `vserver` |
| ↳ VIP list row | `…/vserver/vip-list` | id | — | by-parent; row `vip` **REF** → `system/vip` |
| ↳↳ VIP address | `cmdb/system/vip` | name | — | row field `vip` (ip/mask → IP) |
| Server Pool | `cmdb/server-policy/server-pool` | name | ⊂ `pserver-list` | policy `server-pool` |
| ↳ Real servers | `…/server-pool/pserver-list` | id | — | by-parent; rows carry ip/port/weight + per-server TLS, **health** + **certificate** REFs |
| Persistence Policy | `cmdb/server-policy/persistence-policy` | name | — | pool `persistence` |
| Allow List | `cmdb/server-policy/allow-list` | name | ⊂ `allow-list-items` | policy `allow-list` |
| Web Acceleration | `cmdb/server-policy/acceleration.policy` | name | — | policy `acceleration-policy` |
| ↳ Accel. exception | `cmdb/server-policy/acceleration.exception` | name | ⊂ `list` | accel `exception` |
| Web Scripting | `cmdb/server-policy/scripting` | name | — | policy `scripting-list` |
| Health Check | `cmdb/server-policy/health` | name | ⊂ `health-list` ⚠ | pool `health` |
| Protected Hostnames | `cmdb/server-policy/allow-hosts` | name | ⊂ `host-list` | policy `allow-hosts` |
| Service | `cmdb/server-policy/service.predefined` (→ `.custom`) | name | — | policy `service` / `https-service` |
| Local Certificate | `cmdb/system/certificate.local` | name | — | policy `certificate` / `ssl-client-verify` |
| Let's Encrypt cert | `cmdb/system/certificate.letsencrypt` | name | ⊂ `san-list` | policy `lets-certificate` |
| SSL Ciphers Group | `cmdb/server-policy/ssl-ciphers.predefined` (→ `.custom`) | name | — | policy `ssl-ciphers-group` |
| SNI Policy | `cmdb/system/certificate.sni` | name | ⊂ `members` | policy `sni-certificate` |
| Content Routing | `cmdb/server-policy/policy/http-content-routing-list` | id | — | policy sub-table (deployment-mode) |
| ↳ HTTP CR policy | `cmdb/server-policy/http-content-routing-policy` | name | ⊂ `content-routing-match-list` | row `content-routing-policy-name` |
| ↳↳ Match conditions | `…/content-routing-match-list` | id | — | by-parent → per-match **Server Pool**, **WPP**, **IP Group** (`ip-list`) |
| ↳↳↳ IP Group | `cmdb/server-policy/ip-group` | name | ⊂ `members` | match `ip-list` |
| Replacement Msg Group | `cmdb/system/replacemsg` | name | ⊂ `page-list` | policy `replacemsg` (SHARED) |
| Web Protection Profile | `cmdb/waf/web-protection-profile.inline-protection` | name | references by name | policy `web-protection-profile` → §4 |

⚠ **Health-check sub-table:** the SDK attribute is misspelled `healt_list`, but the
REST wire name is `health-list` — always use `health-list` in calls/clones.

---

## 4. Web Protection Profile — 35 sub-policy references

The inline WPP (`WebProtectionProfileInline`) holds **no nested objects**: each
sub-policy is a **string field naming another `cmdb/waf/*` object**. 35 reference
fields drive the ~40-node `WEB_PROTECTION_PROFILE` tree. Grouped as the 7.6 GUI does:

- **Standard Protection** — `signature_rule`, `http_protocol_parameter_restriction`,
  `x_forwarded_for_rule`, `allow_method_policy`, `ip_list_policy`,
  `geo_block_list_policy`, `url_access_policy`, `custom_access_policy`,
  `application_layer_dos_prevention`, `bot_mitigate_policy`,
  `syntax_based_attack_detection`.
- **Client-Side Security** — `http_header_security`, `cors_protection_policy`,
  `cookie_security_policy`, `websocket_security_policy`, `mitb_protection`
  (+ registry-only: subresource-integrity, client-side-protection).
- **Advanced Protection** — `csrf_protection`, `padding_oracle`,
  `url_encryption_policy`, `link_cloaking_policy`, `hidden_fields_protection`,
  `parameter_validation_rule`, `file_upload_policy`, **`file_exception_policy`**,
  `webshell_detection_policy` (+ registry-only: dlp-policy).
- **API Protection** — `xml_validation_policy`, `json_validation_policy`,
  `openapi_validation_policy`, `api_management_policy`, `mobile_api_protection`,
  `grpc_policy` (+ registry-only: graphql-validation).
- **Application Delivery** — `url_rewrite_policy`, `http_authen_policy`,
  `file_compress_rule`.
- **Tracking** — `user_tracking_policy`, `threat_score_profile` (+ registry-only:
  waiting-room).

Scalars/enums on the WPP (not edges): `client_management`, `http_session_timeout`,
`comment`, `token_secret`, `redirect_url`, `rdt_reason`, `amf3_protocol_detection`,
`quarantined_ip_*`, `ip_intelligence`, `mobile_app_identification`,
`site_publish_helper`, `custom_response`, `owasp_api_top10_log_field`,
`fortigate_quarantined_ips`.

Each referenced policy expands to its own child rule-lists / exception-lists in the
tree (e.g. URL Rewriting → Rewrite Rules → match/header inserts; Signatures →
classes/disabled/filters; Bot Mitigation → known-bots/deception/biometrics/…).

---

## 5. Shared vs owned — the cascade-delete contract

Deleting a Server Policy must **not** blindly delete its dependencies: most are
reusable objects that other policies point at. Classification used by safe cascade:

| Class | Objects | On policy delete |
|---|---|---|
| **By-parent sub-tables** (owned) | vip-list, pserver-list, host-list, health-list, allow-list-items, content-routing-match-list, san-list, ip-group members, page-list | Deleted **with** their parent automatically (no separate call). |
| **Potentially exclusive** (named, but check refcount) | vserver, server-pool, health, allow-hosts, allow-list, persistence-policy, acceleration.policy, scripting, http-content-routing-policy, ip-group | Delete **only if** no other policy references them; else **skip + report**. |
| **Usually shared** | web-protection-profile, certificate.local/.letsencrypt/.sni, ssl-ciphers, service, replacemsg | Delete only on explicit opt-in; default **skip + report**. |
| **Never via REST** | certificates' key material | SSH-only; never carried/deleted. |

Reference counting walks every *other* server policy (and its content-routing
matches) on the box and tallies which named objects they bind. An object with
count 0 outside the target policy is *exclusive* and safe to remove; anything else
is *shared* and is listed but skipped.

---

## 6. Auditing & persistence (who / when / what)

Every mutation is recorded so a change is fully reconstructable:

- **Snapshot before** — `SnapshotStore` writes the object's prior JSON under
  `config_dir/snapshots/` (the rollback net; `operations.restore` pushes one back).
- **Audit row** — `store.audit(username, action, target, detail, result)` →
  `audit_log(ts, username, action, target, detail, result)`. `username` is the
  signed-in manager account (`session.username`); `ts` is ISO-8601 UTC.
- **Change history (v5+)** — richer record capturing `before` + `after` state per
  field for create/update/delete, linked to the snapshot, surfaced in the Audit page.

The device stays the source of truth; the manager DB stores *who changed what, when,
and the before/after* — never appliance secrets (those live in the OS keyring).

---

## 7. Where this lives in the repo

| Concern | File |
|---|---|
| Endpoint URNs per API version | `app/registry/data/endpoints.yaml` |
| Dependency tree (this graph, as data) | `app/registry/dependencies.py` (`SERVER_POLICY`, `WEB_PROTECTION_PROFILE`; 131 nodes) |
| Composite read (walk a policy's whole graph) | `app/services/inspector_report.py`, `app/services/operations.py` (`policy_full`) |
| CRUD with snapshot + audit + dry-run | `app/services/operations.py` (`FortiWebOps`) |
| Versioned REST client | `app/clients/versioned.py` |
| Modify / Delete UI | `app/ui/pages/workspace_page.py` + the structured policy editor |
| Audit storage | `app/db/store.py` (`audit_log`, change history) |

Vendor SDK (offline ground truth, not committed):
`/Volumes/DEBIAN 12_5/py_scripts/fortiweb_api/.../v2_0/cmdb/` — 272 object schemas
(`server_policy/` 33, `waf/` 172, `system/` 27).

---

## 8. Coverage & cross-validation (official docs, 2026-06-20)

The SDK-derived tree was cross-validated against the **official FortiWeb 7.6
admin guide** (docs.fortinet.com — JS SPA, scraped via the internal Firecrawl,
[[internal-firecrawl-lan]]; 559 pages, 163 relevant) and **probed live on fw1
(7.6.8)**. The core graph (§3) is sound. The sweep closed these gaps:

**Added to the registry + tree (confirmed live on fw1, absent from the SDK):**
- `ztna-profile` (policy `ztna-profile`), `traffic-mirror` (policy
  `traffic-mirror-profile`), `certificate.intermediate-certificate-group` (policy
  `intermediate-certificate-group`), `advanced-bot-protection` (WPP
  `advanced-bot-protection`, split from the conflated Bot Mitigation edge).

**Added to the registry only (real on 7.6.8, no clean policy `via` — reachable
via the cert-verify chain or auto-created; surfaced in the API menu):**
- `certificate.ca`, `certificate.ca-group`, `certificate.tsl-ca`,
  `certificate.ocsp-stapling`, `certificate.crl` (the Server Objects →
  Certificates stores beyond local/SNI/LE); `waf/bot-detection-policy` (ML bot,
  Server-Policy ML tab); `waf/web-cache-policy` (auto-created from policy
  `web-cache`).

**WPP DEEP-WIRED (2026-06-20)** — the named *rule/file* objects + their sub-tables
are now nodes under each WPP sub-policy's `*-list` row (via the row's name field),
so the editor walks the full depth. Wired: `json-validation.rule`,
`xml-validation.rule`, `ws-security.rule` (+element/namespace), `xml-schema.file`,
`xml-wsdl.file`, `json-schema.file`/`.group`, `openapi-file`, `grpc-security.rule`,
`grpc-idl.file`, `mobile-api-protection.mobile-api-protection-rule`, `api-rules`
(+ attach-http-header/match-url-prefixes/sub-url-setting), `api-users`,
`api-user-group`, `http-authen.http-authen-rule`, `user-tracking.rule`,
`url-rewrite.url-rewrite-rule`, `exclude-url` (compression), `file-upload-restriction-rule`,
`file-upload-custom-file-type`, `machine-learning.url-replacer-policy`/`-rule`, and the
bot leaf sub-tables (known-bots lists, bot-deception/biometric url-lists,
bot-mitigation-exception element-list, http-constraints-exceptions).

**Documented but NOT present on fw1 7.6.8** (do not add as endpoints — 404 on
probe): `ftp-protection-profile`, `site-publish-helper`/`site-publish.policy`,
`dos-exception-policy`, `ip-reputation` (a `system/global` toggle, not a cmdb
object), `graphql-validation-rule` (only the policy exists), `certificate.ocsp`
(responder) and `certificate.intermediateca` (old name — the
`-certificate-group` form is the live one), `web-anti-defacement` (separate
feature area, not a WPP edge).

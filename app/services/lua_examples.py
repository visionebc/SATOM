"""Lua Studio — a validated catalog of example device scripts.

Grouped by GROUP/SUBGROUP and TARGET (fortiweb / fortiadc). Each example is a
complete, lint-clean Lua snippet the operator can insert into the editor and
adapt. Every token used here is drawn from the curated API dictionaries in
``services.lua_studio`` (``_FORTIWEB_API`` / ``_FORTIADC_API``) plus standard
Lua builtins — so the static analyser recognises every call and never reports
``unknown_calls``. Scripts are written FLAT (no user-defined helper functions),
which is both the natural request-hook style and what keeps analysis green.

These are TEMPLATES for the two platforms' scripting engines:
  * FortiWeb "Web Scripting" — runs per HTTP request, bound to a Server Policy.
  * FortiADC "Scripting" — event blocks (HTTP_REQUEST / HTTP_RESPONSE) bound to a
    Virtual Server.

Pure data — no Flask, no DB. Served as a JSON island to the editor by
``views.lua_studio``. Wire formats for the DEPLOY step are still dry-run only
(the lab fleet is license-locked); these are authoring aids, not verified pushes.

Schema per entry: id, target, group, subgroup, category(==group), title,
name(==title), description, tags, code. ``group``/``category`` and
``title``/``name`` are duplicated so the UI can read either key.
"""
from __future__ import annotations

from typing import Any


def _ex(id, target, group, subgroup, title, description, tags, code):
    """Build one example dict, mirroring group->category and title->name."""
    return {
        "id": id,
        "target": target,
        "group": group,
        "subgroup": subgroup,
        "category": group,      # backward-compat alias
        "title": title,
        "name": title,          # backward-compat alias
        "description": description,
        "tags": tags,
        "code": code,
    }


_EXAMPLES: list[dict[str, Any]] = [

    # ============================================================
    # FortiWeb — Headers / Response headers
    # ============================================================
    _ex(
        "fw_add_security_headers", "fortiweb", "Headers", "Response headers",
        "Add security response headers",
        "Injects HSTS, X-Content-Type-Options, X-Frame-Options and a referrer "
        "policy into every response.",
        ["hsts", "security", "headers", "hardening"],
        """-- Add hardening headers to every response
set_response_header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
set_response_header("X-Content-Type-Options", "nosniff")
set_response_header("X-Frame-Options", "SAMEORIGIN")
set_response_header("Referrer-Policy", "no-referrer-when-downgrade")""",
    ),
    _ex(
        "fw_hide_backend", "fortiweb", "Headers", "Response headers",
        "Hide back-end fingerprint headers",
        "Blanks Server / X-Powered-By / X-AspNet-Version so the response no "
        "longer advertises the back-end stack (FortiWeb has no response-header "
        "delete verb, so we overwrite them).",
        ["fingerprint", "server", "security", "headers"],
        """-- Overwrite fingerprinting headers with empty values
set_response_header("Server", "")
set_response_header("X-Powered-By", "")
set_response_header("X-AspNet-Version", "")""",
    ),
    _ex(
        "fw_no_store_admin", "fortiweb", "Headers", "Response headers",
        "No-store cache headers on /admin",
        "Forces browsers not to cache sensitive admin responses.",
        ["cache-control", "admin", "no-store", "headers"],
        """-- Prevent caching of admin pages
local url = get_request_url()
if string.find(url, "^/admin") then
  set_response_header("Cache-Control", "no-store, max-age=0")
  set_response_header("Pragma", "no-cache")
end""",
    ),
    _ex(
        "fw_csp_header", "fortiweb", "Headers", "Response headers",
        "Set a Content-Security-Policy",
        "Adds a restrictive CSP that only allows same-origin scripts and styles.",
        ["csp", "content-security-policy", "xss", "headers"],
        """-- Restrictive Content-Security-Policy
set_response_header("Content-Security-Policy",
  "default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'")""",
    ),
    _ex(
        "fw_cors_api", "fortiweb", "Headers", "Response headers",
        "CORS headers for the API path",
        "Adds Access-Control-* response headers, but only for requests under "
        "/api so the rest of the site stays same-origin.",
        ["cors", "api", "access-control", "headers"],
        """-- Emit CORS headers only for /api responses
local url = get_request_url()
if string.find(url, "^/api/") then
  set_response_header("Access-Control-Allow-Origin", "https://app.example.com")
  set_response_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
  set_response_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
end""",
    ),
    _ex(
        "fw_permissions_policy", "fortiweb", "Headers", "Response headers",
        "Lock down browser features (Permissions-Policy)",
        "Disables camera, microphone and geolocation for the whole site via the "
        "Permissions-Policy header.",
        ["permissions-policy", "privacy", "security", "headers"],
        """-- Deny powerful browser features site-wide
set_response_header("Permissions-Policy",
  "camera=(), microphone=(), geolocation=(), interest-cohort=()")""",
    ),

    # ============================================================
    # FortiWeb — Headers / Request headers
    # ============================================================
    _ex(
        "fw_forward_real_ip", "fortiweb", "Headers", "Request headers",
        "Forward client IP to back-end",
        "Copies the real client IP into X-Real-IP for the pool member to consume.",
        ["client-ip", "x-real-ip", "upstream", "headers"],
        """-- Pass the true client IP upstream
local ip = get_client_ip()
if ip ~= nil then
  set_request_header("X-Real-IP", ip)
end""",
    ),
    _ex(
        "fw_pass_request_id", "fortiweb", "Headers", "Request headers",
        "Attach a request correlation ID",
        "If the client did not send X-Request-ID, stamp one from the client IP "
        "and timestamp so back-end logs can be correlated.",
        ["correlation-id", "tracing", "x-request-id", "headers"],
        """-- Ensure every request carries a correlation id
local rid = get_request_header("X-Request-ID")
if rid == nil then
  set_request_header("X-Request-ID", tostring(get_client_ip()) .. "-" .. tostring(os.time()))
end""",
    ),
    _ex(
        "fw_strip_inbound_forwarded", "fortiweb", "Headers", "Request headers",
        "Strip client-supplied forwarding headers",
        "Removes any inbound X-Forwarded-For / X-Real-IP the client tried to set, "
        "then re-adds a trusted value, defeating IP spoofing.",
        ["spoofing", "x-forwarded-for", "trust", "headers"],
        """-- Never trust forwarding headers from the client
remove_request_header("X-Forwarded-For")
remove_request_header("X-Real-IP")
local ip = get_client_ip()
if ip ~= nil then
  set_request_header("X-Forwarded-For", ip)
end""",
    ),
    _ex(
        "fw_add_forwarded_proto", "fortiweb", "Headers", "Request headers",
        "Tell the back-end the request was HTTPS",
        "Sets X-Forwarded-Proto so an app behind TLS offload builds correct "
        "absolute URLs.",
        ["x-forwarded-proto", "tls", "offload", "headers"],
        """-- Advertise the original scheme to the pool
set_request_header("X-Forwarded-Proto", "https")""",
    ),

    # ============================================================
    # FortiWeb — Access control / Method & host
    # ============================================================
    _ex(
        "fw_block_methods", "fortiweb", "Access control", "Method & host",
        "Allow only safe HTTP methods",
        "Blocks any HTTP method outside a safe allow-list (stops TRACE, TRACK, "
        "DEBUG and friends).",
        ["methods", "allow-list", "trace", "access-control"],
        """-- Method allow-list
local m = get_request_method()
local ok = { GET = true, POST = true, HEAD = true, OPTIONS = true }
if not ok[m] then
  log("blocked method: " .. tostring(m))
  block()
end""",
    ),
    _ex(
        "fw_block_host_mismatch", "fortiweb", "Access control", "Method & host",
        "Block unexpected Host header",
        "Rejects requests whose Host header is not one you serve — a cheap "
        "defence against host-header injection.",
        ["host-header", "injection", "vhost", "access-control"],
        """-- Only serve known hosts
local host = get_request_header("Host")
if host ~= "www.example.com" and host ~= "example.com" then
  log("bad host: " .. tostring(host))
  block()
end""",
    ),

    # ============================================================
    # FortiWeb — Access control / Client filtering
    # ============================================================
    _ex(
        "fw_block_missing_ua", "fortiweb", "Access control", "Client filtering",
        "Block requests without a User-Agent",
        "A common bot/scanner tell: no User-Agent header. Block it.",
        ["user-agent", "bots", "scanner", "access-control"],
        """-- Block requests that carry no User-Agent
local ua = get_request_header("User-Agent")
if ua == nil or ua == "" then
  log("blocked: empty User-Agent from " .. tostring(get_client_ip()))
  block()
end""",
    ),
    _ex(
        "fw_block_bad_ua", "fortiweb", "Access control", "Client filtering",
        "Block known scanner User-Agents",
        "Blocks requests whose User-Agent matches common attack-tool signatures "
        "(sqlmap, nikto, nmap, masscan).",
        ["user-agent", "sqlmap", "nikto", "access-control"],
        """-- Drop obvious scanner tools by User-Agent
local ua = string.lower(tostring(get_request_header("User-Agent")))
local bad = { "sqlmap", "nikto", "nmap", "masscan", "acunetix" }
for _, sig in ipairs(bad) do
  if string.find(ua, sig, 1, true) then
    log("blocked scanner UA: " .. sig)
    block()
  end
end""",
    ),
    _ex(
        "fw_block_admin_path", "fortiweb", "Access control", "Client filtering",
        "Restrict /admin to one IP",
        "Blocks access to a sensitive path unless the client IP matches an "
        "allow-list.",
        ["admin", "ip-allowlist", "access-control", "client-ip"],
        """-- Only one office IP may reach /admin
local url = get_request_url()
local ip  = get_client_ip()
if string.find(url, "^/admin") then
  if ip ~= "203.0.113.10" then
    log("admin blocked for " .. tostring(ip))
    block()
  end
end""",
    ),
    _ex(
        "fw_require_api_key", "fortiweb", "Access control", "Client filtering",
        "Require an API key header on /api",
        "Blocks API requests that arrive without an X-API-Key header (a coarse "
        "gate in front of the app's own auth).",
        ["api-key", "auth", "api", "access-control"],
        """-- Reject /api calls lacking an API key
local url = get_request_url()
if string.find(url, "^/api/") then
  local key = get_request_header("X-API-Key")
  if key == nil or key == "" then
    log("api call without key from " .. tostring(get_client_ip()))
    block()
  end
end""",
    ),

    # ============================================================
    # FortiWeb — Redirects & rewrites / Redirects
    # ============================================================
    _ex(
        "fw_redirect_legacy_path", "fortiweb", "Redirects & rewrites", "Redirects",
        "Redirect a legacy path to a new host",
        "Redirects an old path prefix to a new location, preserving the tail of "
        "the path.",
        ["redirect", "migration", "legacy", "301"],
        """-- Send /old/* to the new site
local url = get_request_url()
if string.find(url, "^/old/") then
  local dest = string.gsub(url, "^/old/", "/")
  redirect("https://new.example.com" .. dest)
end""",
    ),
    _ex(
        "fw_force_www", "fortiweb", "Redirects & rewrites", "Redirects",
        "Redirect apex to www",
        "Sends bare-domain traffic to the canonical www host over HTTPS, "
        "preserving the path.",
        ["redirect", "www", "canonical", "apex"],
        """-- example.com -> www.example.com
local host = get_request_header("Host")
if host == "example.com" then
  redirect("https://www.example.com" .. get_request_url())
end""",
    ),
    _ex(
        "fw_maintenance_mode", "fortiweb", "Redirects & rewrites", "Redirects",
        "Maintenance mode with an IP bypass",
        "Redirects everyone to a maintenance page, except operators coming from "
        "an allow-listed IP who still reach the site.",
        ["maintenance", "redirect", "bypass", "client-ip"],
        """-- Send all visitors to a status page during maintenance
local ip = get_client_ip()
local url = get_request_url()
if ip ~= "203.0.113.10" and not string.find(url, "^/maintenance") then
  redirect("https://status.example.com/maintenance")
end""",
    ),

    # ============================================================
    # FortiWeb — Redirects & rewrites / Rewrites
    # ============================================================
    _ex(
        "fw_rewrite_api_prefix", "fortiweb", "Redirects & rewrites", "Rewrites",
        "Rewrite /api/v1 to /v1 upstream",
        "Strips a public path prefix before the request reaches the pool.",
        ["rewrite", "api", "prefix", "url"],
        """-- Public /api/v1/... -> upstream /v1/...
local url = get_request_url()
if string.find(url, "^/api/v1/") then
  set_request_url((string.gsub(url, "^/api/v1/", "/v1/")))
end""",
    ),
    _ex(
        "fw_strip_index", "fortiweb", "Redirects & rewrites", "Rewrites",
        "Rewrite /index.html to /",
        "Normalises directory-index URLs to their clean form before they hit the "
        "back-end.",
        ["rewrite", "index", "normalise", "url"],
        """-- Drop a trailing index.html from the path
local url = get_request_url()
if string.find(url, "/index%.html$") then
  set_request_url((string.gsub(url, "/index%.html$", "/")))
end""",
    ),

    # ============================================================
    # FortiWeb — Client IP & geo
    # ============================================================
    _ex(
        "fw_block_ip", "fortiweb", "Client IP & geo", "",
        "Block a bad client IP or prefix",
        "Drops traffic from a specific abusive IP or an entire /24 style prefix "
        "matched on the address string.",
        ["client-ip", "blocklist", "abuse", "access-control"],
        """-- Deny a known-bad address / prefix
local ip = get_client_ip()
if ip == "198.51.100.7" or string.find(tostring(ip), "^192%.0%.2%.") then
  log("blocked bad ip: " .. tostring(ip))
  block()
end""",
    ),
    _ex(
        "fw_tag_internal_ip", "fortiweb", "Client IP & geo", "",
        "Tag internal vs external clients",
        "Stamps an X-Client-Zone request header so the app can tell RFC1918 "
        "internal clients from the public internet.",
        ["client-ip", "rfc1918", "zone", "headers"],
        """-- Label the client's network zone for the back-end
local ip = tostring(get_client_ip())
local zone = "external"
if string.find(ip, "^10%.") or string.find(ip, "^192%.168%.") then
  zone = "internal"
end
set_request_header("X-Client-Zone", zone)""",
    ),

    # ============================================================
    # FortiWeb — Request body & content
    # ============================================================
    _ex(
        "fw_block_sqli_body", "fortiweb", "Request body & content", "",
        "Block SQLi keywords in the request body",
        "A cheap heuristic: inspect the POST body and block obvious SQL-injection "
        "payloads before they reach the app.",
        ["sqli", "body", "waf", "heuristic"],
        """-- Heuristic SQLi check on the request body
local body = get_request_body()
if body ~= nil then
  local low = string.lower(body)
  if string.find(low, "union select", 1, true)
     or string.find(low, "' or '1'='1", 1, true) then
    log("sqli heuristic tripped in body")
    block()
  end
end""",
    ),
    _ex(
        "fw_require_json_api", "fortiweb", "Request body & content", "",
        "Require JSON content-type on API writes",
        "Blocks POST/PUT requests to /api that are not declared as "
        "application/json.",
        ["content-type", "json", "api", "access-control"],
        """-- Enforce application/json on API writes
local url = get_request_url()
local m = get_request_method()
local is_write = m == "POST" or m == "PUT"
if string.find(url, "^/api/") and is_write then
  local ct = tostring(get_request_header("Content-Type"))
  if not string.find(ct, "application/json", 1, true) then
    log("non-json api write rejected: " .. ct)
    block()
  end
end""",
    ),
    _ex(
        "fw_block_upload_ext", "fortiweb", "Request body & content", "",
        "Block dangerous upload extensions",
        "Rejects requests whose URL targets an executable/script extension often "
        "used for web-shell uploads.",
        ["upload", "webshell", "extension", "access-control"],
        """-- Deny risky file extensions in the path
local url = string.lower(get_request_url())
local bad = { "%.php$", "%.jsp$", "%.asp$", "%.aspx$", "%.sh$", "%.exe$" }
for _, pat in ipairs(bad) do
  if string.find(url, pat) then
    log("blocked risky extension: " .. url)
    block()
  end
end""",
    ),

    # ============================================================
    # FortiWeb — Logging & debug
    # ============================================================
    _ex(
        "fw_audit_payment", "fortiweb", "Logging & debug", "",
        "Audit-log payment paths",
        "Writes an audit line whenever a checkout/payment path is hit, and marks "
        "the request for the back-end.",
        ["audit", "payment", "logging", "compliance"],
        """-- Audit payment traffic
local url = get_request_url()
if string.find(url, "^/checkout") or string.find(url, "^/pay") then
  log("payment path hit: " .. url .. " from " .. tostring(get_client_ip()))
  set_request_header("X-Audit", "payment")
end""",
    ),
    _ex(
        "fw_debug_request", "fortiweb", "Logging & debug", "",
        "Log method, URL and User-Agent",
        "A verbose debug line for troubleshooting a policy — logs the request "
        "line and client for every hit.",
        ["debug", "logging", "troubleshoot", "verbose"],
        """-- One log line per request for debugging
local m  = get_request_method()
local u  = get_request_url()
local ua = tostring(get_request_header("User-Agent"))
log(m .. " " .. u .. " ua=" .. ua .. " ip=" .. tostring(get_client_ip()))""",
    ),
    _ex(
        "fw_log_suspicious_path", "fortiweb", "Logging & debug", "",
        "Log probes for common secret files",
        "Logs (without blocking) requests for well-known sensitive paths so you "
        "can watch recon activity before deciding to block.",
        ["recon", "logging", "dotfiles", "monitoring"],
        """-- Watch for recon against sensitive paths
local url = string.lower(get_request_url())
if string.find(url, "/%.git") or string.find(url, "/%.env")
   or string.find(url, "/wp%-login") or string.find(url, "/phpmyadmin") then
  log("recon probe: " .. url .. " from " .. tostring(get_client_ip()))
end""",
    ),

    # ============================================================
    # FortiWeb — Rate/abuse heuristics
    # ============================================================
    _ex(
        "fw_block_long_query", "fortiweb", "Rate/abuse heuristics", "",
        "Block absurdly long query strings",
        "Rejects requests whose URL is longer than a sane limit — a blunt guard "
        "against buffer-stuffing and injection payloads.",
        ["query-string", "length", "dos", "heuristic"],
        """-- Cap the request-line length
local url = get_request_url()
if string.len(url) > 2048 then
  log("blocked oversized URL len=" .. tostring(string.len(url)))
  block()
end""",
    ),
    _ex(
        "fw_block_post_no_referer", "fortiweb", "Rate/abuse heuristics", "",
        "Block cross-site POSTs missing a Referer",
        "A lightweight CSRF heuristic: state-changing POSTs to the app should "
        "carry a same-site Referer; block those that do not.",
        ["csrf", "referer", "post", "heuristic"],
        """-- Require a same-site Referer on POSTs
local m = get_request_method()
if m == "POST" then
  local ref = tostring(get_request_header("Referer"))
  if not string.find(ref, "^https://www%.example%.com/") then
    log("csrf heuristic: bad referer " .. ref)
    block()
  end
end""",
    ),

    # ============================================================
    # FortiADC — Headers / Response headers
    # ============================================================
    _ex(
        "adc_add_headers", "fortiadc", "Headers", "Response headers",
        "Add security response headers",
        "FortiADC HTTP_RESPONSE block that injects hardening headers on the way "
        "out.",
        ["hsts", "nosniff", "security", "headers"],
        """when HTTP_RESPONSE {
  http_header_set("X-Content-Type-Options", "nosniff")
  http_header_set("Strict-Transport-Security", "max-age=31536000")
  http_header_set("X-Frame-Options", "SAMEORIGIN")
}""",
    ),
    _ex(
        "adc_strip_fingerprint", "fortiadc", "Headers", "Response headers",
        "Strip Server / X-Powered-By",
        "FortiADC HTTP_RESPONSE block that removes fingerprinting headers on the "
        "way out.",
        ["fingerprint", "server", "security", "headers"],
        """when HTTP_RESPONSE {
  http_header_remove("Server")
  http_header_remove("X-Powered-By")
}""",
    ),
    _ex(
        "adc_cors", "fortiadc", "Headers", "Response headers",
        "Add CORS headers on responses",
        "Emits Access-Control-* headers so a single-page app on another origin "
        "can call this virtual server.",
        ["cors", "access-control", "spa", "headers"],
        """when HTTP_RESPONSE {
  http_header_set("Access-Control-Allow-Origin", "https://app.example.com")
  http_header_set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
  http_header_set("Access-Control-Allow-Headers", "Content-Type, Authorization")
}""",
    ),

    # ============================================================
    # FortiADC — Headers / Request headers
    # ============================================================
    _ex(
        "adc_forward_ip", "fortiadc", "Headers", "Request headers",
        "Insert X-Forwarded-For",
        "Adds the client IP as X-Forwarded-For on the request.",
        ["client-ip", "x-forwarded-for", "upstream", "headers"],
        """when HTTP_REQUEST {
  local ip = client_ip()
  if ip ~= nil then
    http_header_set("X-Forwarded-For", ip)
  end
}""",
    ),
    _ex(
        "adc_forwarded_proto", "fortiadc", "Headers", "Request headers",
        "Set X-Forwarded-Proto to https",
        "Tells a back-end behind TLS offload that the client connection was "
        "encrypted, so it builds correct absolute URLs.",
        ["x-forwarded-proto", "tls", "offload", "headers"],
        """when HTTP_REQUEST {
  http_header_set("X-Forwarded-Proto", "https")
}""",
    ),

    # ============================================================
    # FortiADC — URI rewrites
    # ============================================================
    _ex(
        "adc_rewrite_api_prefix", "fortiadc", "URI rewrites", "",
        "Rewrite /api/v1 to /v1",
        "Strips a public API prefix from the URI before it reaches the pool.",
        ["rewrite", "uri", "api", "prefix"],
        """when HTTP_REQUEST {
  local uri = http_uri_get()
  if string.find(uri, "^/api/v1/") then
    http_uri_set((string.gsub(uri, "^/api/v1/", "/v1/")))
  end
}""",
    ),
    _ex(
        "adc_rewrite_legacy", "fortiadc", "URI rewrites", "",
        "Rewrite a legacy URI prefix",
        "Silently maps an old path prefix onto its replacement without a visible "
        "redirect.",
        ["rewrite", "uri", "legacy", "migration"],
        """when HTTP_REQUEST {
  local uri = http_uri_get()
  if string.find(uri, "^/legacy/") then
    http_uri_set((string.gsub(uri, "^/legacy/", "/app/")))
  end
}""",
    ),

    # ============================================================
    # FortiADC — Redirects
    # ============================================================
    _ex(
        "adc_redirect_www", "fortiadc", "Redirects", "",
        "Redirect apex to www",
        "Sends bare-domain requests to the www host, preserving the URI.",
        ["redirect", "www", "canonical", "apex"],
        """when HTTP_REQUEST {
  local host = http_header_get("Host")
  if host == "example.com" then
    http_redirect("https://www.example.com" .. http_uri_get())
  end
}""",
    ),
    _ex(
        "adc_redirect_legacy", "fortiadc", "Redirects", "",
        "Redirect a retired path",
        "Issues a visible redirect from a retired path to its new canonical "
        "location.",
        ["redirect", "legacy", "migration", "301"],
        """when HTTP_REQUEST {
  local uri = http_uri_get()
  if string.find(uri, "^/promo2019") then
    http_redirect("https://www.example.com/offers")
  end
}""",
    ),

    # ============================================================
    # FortiADC — Access control
    # ============================================================
    _ex(
        "adc_block_ua", "fortiadc", "Access control", "",
        "Close connection for scanner User-Agent",
        "Drops requests whose User-Agent matches a scanner signature.",
        ["user-agent", "sqlmap", "scanner", "access-control"],
        """when HTTP_REQUEST {
  local ua = http_header_get("User-Agent")
  if ua ~= nil and string.find(string.lower(ua), "sqlmap", 1, true) then
    debug("dropping scanner: " .. ua)
    http_close()
  end
}""",
    ),
    _ex(
        "adc_block_dot_git", "fortiadc", "Access control", "",
        "Close connection on /.git or /.env",
        "Drops probes for exposed VCS/secret files before they reach a pool.",
        ["dotfiles", "git", "env", "access-control"],
        """when HTTP_REQUEST {
  local uri = http_uri_get()
  if string.find(uri, "/%.git") or string.find(uri, "/%.env") then
    debug("blocked secret-file probe: " .. uri)
    http_close()
  end
}""",
    ),
    _ex(
        "adc_block_admin_ip", "fortiadc", "Access control", "",
        "Restrict /admin by client IP",
        "Closes the connection to /admin unless the client IP is on the "
        "allow-list.",
        ["admin", "client-ip", "allowlist", "access-control"],
        """when HTTP_REQUEST {
  local uri = http_uri_get()
  local ip  = client_ip()
  if string.find(uri, "^/admin") and ip ~= "203.0.113.10" then
    debug("admin blocked for " .. tostring(ip))
    http_close()
  end
}""",
    ),
    _ex(
        "adc_block_missing_host", "fortiadc", "Access control", "",
        "Close connection when Host is absent",
        "HTTP/1.1 requests must carry a Host header; drop the ones that do not.",
        ["host-header", "http11", "malformed", "access-control"],
        """when HTTP_REQUEST {
  local host = http_header_get("Host")
  if host == nil or host == "" then
    debug("dropped request with no Host header")
    http_close()
  end
}""",
    ),

    # ============================================================
    # FortiADC — Load-balance routing
    # ============================================================
    _ex(
        "adc_route_by_path", "fortiadc", "Load-balance routing", "",
        "Route /api to a dedicated pool",
        "Sends API traffic to a specific back-end pool, everything else to the "
        "default.",
        ["routing", "pool", "api", "load-balance"],
        """when HTTP_REQUEST {
  local uri = http_uri_get()
  if string.find(uri, "^/api/") then
    lb_pool("pool-api")
  else
    lb_pool("pool-web")
  end
}""",
    ),
    _ex(
        "adc_route_by_header", "fortiadc", "Load-balance routing", "",
        "Canary routing by header",
        "Routes a small canary cohort (by a header flag) to a separate pool for "
        "progressive rollout.",
        ["canary", "routing", "pool", "rollout"],
        """when HTTP_REQUEST {
  local flag = http_header_get("X-Canary")
  if flag == "1" then
    lb_pool("pool-canary")
  else
    lb_pool("pool-stable")
  end
}""",
    ),
    _ex(
        "adc_route_by_host", "fortiadc", "Load-balance routing", "",
        "Route by Host header",
        "Sends each virtual host to its own back-end pool on a shared listener.",
        ["routing", "vhost", "pool", "host-header"],
        """when HTTP_REQUEST {
  local host = http_header_get("Host")
  if host == "shop.example.com" then
    lb_pool("pool-shop")
  elseif host == "api.example.com" then
    lb_pool("pool-api")
  else
    lb_pool("pool-web")
  end
}""",
    ),
    _ex(
        "adc_route_by_ua", "fortiadc", "Load-balance routing", "",
        "Route mobile clients to a mobile pool",
        "Inspects the User-Agent and directs mobile browsers to a pool tuned for "
        "the mobile site.",
        ["routing", "mobile", "user-agent", "pool"],
        """when HTTP_REQUEST {
  local ua = http_header_get("User-Agent")
  if ua ~= nil and string.find(string.lower(ua), "mobile", 1, true) then
    lb_pool("pool-mobile")
  else
    lb_pool("pool-desktop")
  end
}""",
    ),
    _ex(
        "adc_routing_policy", "fortiadc", "Load-balance routing", "",
        "Select a named routing policy",
        "Uses lb_routing_policy to hand the request to a pre-defined content "
        "routing policy instead of a raw pool.",
        ["routing-policy", "content-routing", "load-balance", "policy"],
        """when HTTP_REQUEST {
  local uri = http_uri_get()
  if string.find(uri, "^/video/") then
    lb_routing_policy("rp-media")
  else
    lb_routing_policy("rp-default")
  end
}""",
    ),

    # ============================================================
    # FortiADC — Logging
    # ============================================================
    _ex(
        "adc_debug_request", "fortiadc", "Logging", "",
        "Debug-log the request line",
        "Emits a debug entry with the URI and client IP for every request — "
        "handy while building a policy.",
        ["debug", "logging", "troubleshoot", "uri"],
        """when HTTP_REQUEST {
  local uri = http_uri_get()
  local ip  = client_ip()
  debug("req " .. tostring(uri) .. " from " .. tostring(ip))
}""",
    ),

]


def categories(target: str | None = None) -> list[str]:
    seen: list[str] = []
    for ex in _EXAMPLES:
        if target and ex["target"] != target:
            continue
        if ex["category"] not in seen:
            seen.append(ex["category"])
    return seen


def groups(target: str | None = None) -> list[str]:
    """Alias of categories() using the newer ``group`` key."""
    return categories(target)


def for_target(target: str) -> list[dict[str, Any]]:
    return [e for e in _EXAMPLES if e["target"] == target]


def all_examples() -> list[dict[str, Any]]:
    return _EXAMPLES


def get(example_id: str) -> dict[str, Any] | None:
    for ex in _EXAMPLES:
        if ex["id"] == example_id:
            return ex
    return None

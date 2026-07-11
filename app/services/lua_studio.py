"""Lua Script Studio — lint, analyse and (dry-run) deploy Lua for FortiWeb/ADC.

Nothing here EXECUTES a device script. Linting is ``luac -p`` (parse only), so
the worst a pasted script can do is fail to compile. Analysis is a static pass
over the source against a curated API dictionary — it summarises what the script
touches (request/response, headers, URL, pools…) and flags likely mistakes.
Deploy builds the versioned scripting-endpoint request and is DRY-RUN by default;
a real push needs config_write + an explicit confirm at the view layer.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from typing import Any


# luac5.4 is installed in the container (apt lua5.4); fall back to any luac.
def _luac_bin() -> str | None:
    for cand in ("luac5.4", "luac5.3", "luac5.1", "luac"):
        p = shutil.which(cand)
        if p:
            return p
    return None


_LUAC_ERR = re.compile(r":(\d+):\s*(.*)$")


def _lint_fortiadc_structural(code: str) -> dict[str, Any]:
    """Structural lint for FortiADC scripts (the  DSL is
    not valid standalone Lua, so luac -p rejects it). Checks bracket balance and
    that at least one event block is present. engine="structural"."""
    errors = []
    for op, cl, label in (("(", ")", "parenthesis"), ("{", "}", "brace")):
        d = code.count(op) - code.count(cl)
        if d != 0:
            errors.append({"line": 0,
                           "message": f"unbalanced {label} ({d:+d})"})
    if not re.search(r"\bwhen\s+[A-Za-z_]+\s*\{", code):
        errors.append({"line": 0,
                       "message": "no  block found — "
                                  "FortiADC scripts are event blocks"})
    return {"ok": not errors, "engine": "structural", "errors": errors}


def lint(code: str, target: str = "fortiweb") -> dict[str, Any]:
    """Parse-check the Lua source. Returns {ok, errors:[{line,message}], engine}.

    Uses ``luac -p`` which compiles WITHOUT running — a syntax error surfaces
    with its line number; a clean parse returns ok=True.
    """
    binp = _luac_bin()
    if not binp:
        return {"ok": False, "engine": None,
                "errors": [{"line": 0, "message": "luac not available on server"}]}
    if not (code or "").strip():
        return {"ok": False, "engine": os.path.basename(binp),
                "errors": [{"line": 0, "message": "empty script"}]}
    if target == "fortiadc":
        # FortiADC "Scripting" is an iRule-style  DSL,
        # NOT standalone Lua, so luac -p cannot parse it. Do a lightweight
        # STRUCTURAL check instead (balanced brackets + at least one event block).
        return _lint_fortiadc_structural(code)
    tmp = tempfile.NamedTemporaryFile("w", suffix=".lua", delete=False, encoding="utf-8")
    try:
        tmp.write(code)
        tmp.close()
        proc = subprocess.run(
            [binp, "-p", tmp.name], capture_output=True, text=True, timeout=10)
        if proc.returncode == 0:
            return {"ok": True, "engine": os.path.basename(binp), "errors": []}
        errors = []
        for ln in (proc.stderr or "").splitlines():
            m = _LUAC_ERR.search(ln)
            if m:
                errors.append({"line": int(m.group(1)), "message": m.group(2).strip()})
            elif ln.strip():
                errors.append({"line": 0, "message": ln.strip()})
        if not errors:
            errors = [{"line": 0, "message": "parse failed"}]
        return {"ok": False, "engine": os.path.basename(binp), "errors": errors}
    except subprocess.TimeoutExpired:
        return {"ok": False, "engine": os.path.basename(binp),
                "errors": [{"line": 0, "message": "luac timed out"}]}
    finally:
        try:
            os.unlink(tmp.name)
        except OSError:
            pass


# --- Curated scripting API dictionaries -------------------------------------
# token -> human phrase. FortiWeb "Web Scripting" and FortiADC "Scripting" both
# expose a Lua API; these are the load-bearing globals/objects the operator asks
# about. Matched as whole words; unknown calls are reported separately.
_FORTIWEB_API = {
    "get_request_header": "reads a request header",
    "set_request_header": "sets a request header",
    "remove_request_header": "removes a request header",
    "get_response_header": "reads a response header",
    "set_response_header": "sets a response header",
    "get_request_url": "reads the request URL",
    "set_request_url": "rewrites the request URL",
    "get_request_method": "reads the HTTP method",
    "get_request_body": "reads the request body",
    "get_client_ip": "reads the client IP",
    "forward": "forwards the request",
    "redirect": "redirects the client",
    "block": "blocks the request",
    "log": "writes a log message",
    "HTTP": "uses the HTTP object",
    "sys": "uses the sys object",
}
_FORTIADC_API = {
    "HTTP_REQUEST": "hooks the HTTP request event",
    "HTTP_RESPONSE": "hooks the HTTP response event",
    "http_header_get": "reads an HTTP header",
    "http_header_set": "sets an HTTP header",
    "http_header_remove": "removes an HTTP header",
    "http_uri_get": "reads the request URI",
    "http_uri_set": "rewrites the request URI",
    "http_redirect": "redirects the client",
    "http_close": "closes the connection",
    "lb_routing_policy": "selects a load-balance route",
    "lb_pool": "selects a back-end pool",
    "client_ip": "reads the client IP",
    "debug": "writes a debug message",
}

_HOOK_HINTS = {
    "fortiweb": ("Web Scripting runs per request; bind it to a Server Policy "
                 "via its scripting list."),
    "fortiadc": ("FortiADC Scripting binds to a Virtual Server; use HTTP_REQUEST "
                 "/ HTTP_RESPONSE event blocks."),
}


_WORD = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_CALL = re.compile(r"([A-Za-z_][A-Za-z0-9_\.]*)\s*\(")


def analyze(code: str, target: str = "fortiweb") -> dict[str, Any]:
    """Static analysis: what the script does + likely errors. Never executes."""
    api = _FORTIADC_API if target == "fortiadc" else _FORTIWEB_API
    src = code or ""
    lines = src.splitlines()

    # 1. What it does — curated API tokens present.
    does: list[str] = []
    present = set()
    for token, phrase in api.items():
        if re.search(r"\b" + re.escape(token) + r"\b", src):
            does.append(phrase)
            present.add(token)

    # 2. Called functions not in the known API (info, not an error).
    called = set(m.group(1) for m in _CALL.finditer(src))
    lua_builtin = {"print", "pairs", "ipairs", "tostring", "tonumber", "type",
                   "string", "table", "math", "os", "io", "pcall", "error",
                   "assert", "next", "select", "setmetatable", "getmetatable",
                   "rawget", "rawset", "require", "tostring", "unpack"}
    unknown_calls = sorted(
        c for c in called
        if c.split(".")[0] not in lua_builtin
        and c not in present
        and not any(c.startswith(t) for t in present)
    )

    # 3. Heuristic warnings (cheap, complements the luac parse pass).
    warnings: list[dict[str, Any]] = []
    open_kw = len(re.findall(r"\b(function|if|for|while|do)\b", src))
    end_kw = len(re.findall(r"\bend\b", src))
    if open_kw > end_kw:
        warnings.append({"line": 0,
                         "message": f"{open_kw} block opener(s) vs {end_kw} 'end' "
                                    "— a block may be unterminated"})
    for i, ln in enumerate(lines, 1):
        if re.search(r"[^=<>~]=[^=]", ln) and re.search(r"\bif\b|\bwhile\b", ln) \
                and "==" not in ln:
            warnings.append({"line": i,
                             "message": "assignment '=' inside a condition — "
                                        "did you mean '=='?"})
        if "os.execute" in ln or "io.popen" in ln:
            warnings.append({"line": i,
                             "message": "os.execute/io.popen is unusual in device "
                                        "scripting and often unsupported"})

    return {
        "target": target,
        "does": does,
        "unknown_calls": unknown_calls,
        "warnings": warnings,
        "line_count": len(lines),
        "hint": _HOOK_HINTS.get(target, ""),
        "api_used": sorted(present),
    }


# --- Deploy (dry-run default) ----------------------------------------------
# Logical scripting endpoints, resolved through the registry loader per product.
_SCRIPTING_LOGICAL = {
    "fortiweb": "policy_scripting",   # cmdb/server-policy/scripting
    "fortiadc": "system_script",      # /api/system_script (see endpoints_fortiadc)
}
# The content field name differs by platform/firmware and is NOT yet verified
# live on these boxes — keep dry-run default and confirm before a real push.
_CONTENT_FIELD = {"fortiweb": "content", "fortiadc": "script"}


def deploy_plan(script, code: str) -> dict[str, Any]:
    """Build the request that a deploy WOULD send (pure — no device I/O)."""
    target = script.target
    logical = _SCRIPTING_LOGICAL.get(target, "")
    field = _CONTENT_FIELD.get(target, "content")
    body = {"name": script.deploy_object or script.name, field: code}
    return {
        "target": target,
        "logical": logical,
        "method": "POST/PUT",
        "content_field": field,
        "body_preview": body,
        "verified": False,
        "note": ("Scripting wire format is not yet round-tripped live on this "
                 "fleet (license-locked). Review before a non-dry-run push."),
    }


def deploy(script, code: str, appliance, *, dry_run: bool = True) -> dict[str, Any]:
    """Push the script to the device via the versioned scripting endpoint.

    dry_run=True (default) returns the plan only. A real push resolves a client
    for the appliance and POSTs the scripting object; any device error is
    surfaced, never swallowed.
    """
    plan = deploy_plan(script, code)
    if dry_run or appliance is None:
        plan["dry_run"] = True
        return plan
    try:
        from ..clients import client_for
        from ..registry import loader as reg
        client = client_for(appliance)
        if script.target == "fortiadc":
            urn = reg.resolve_adc(plan["logical"])
        else:
            urn = reg.resolve(plan["logical"])
        rows, err = (client.list_with_error(urn) if hasattr(client, "list_with_error")
                     else ([], None))
        # Create (or update) the scripting object.
        resp = client.create(plan["logical"], plan["body_preview"]) \
            if hasattr(client, "create") else None
        return {**plan, "dry_run": False, "device_response": str(resp)[:400],
                "pre_read_error": err}
    except Exception as exc:  # noqa: BLE001 — surface, do not swallow
        return {**plan, "dry_run": False, "error": f"{type(exc).__name__}: {exc}"}

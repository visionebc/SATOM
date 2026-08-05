#!/usr/bin/env python3
"""Generate acme_providers.yaml from the installed ACME client itself.

WHY: the DNS-01 provider catalog is ~220 entries of (code, env var names).
Curating that by hand is how you ship dead rows — the first hand-written pass
of this file had `rfc2136` (lego renamed it `dnsupdate`, so the row could never
run) and routed EfficientIP through the generic `exec` hook even though lego
has had a native `efficientip` provider since v4.13.

`lego dnshelp` IS the machine-readable source of truth, and it ships with the
binary the app actually executes — so the catalog can never drift from the
client. Re-run this after bumping lego:

    python3 deploy/gen_acme_providers.py --bin /usr/local/bin/lego \
        --out acme_providers.yaml

Hand-curated corrections live in acme_providers.overlay.yaml (see load_overlay).

The output stays an INSERT-ONLY seed: rows already in `acme_dns_providers`
are untouched, operator edits keep winning.
"""
from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys

# An env var holding a credential must never be echoed or put on a command
# line. Name-based, because lego's help text does not mark secrecy.
_SECRET_RE = re.compile(
    r"(KEY|TOKEN|SECRET|PASSWORD|PASSWD|_PASS$|HMAC|CREDENTIAL|PRIVATE|"
    r"AUTH|SIGNATURE|APIKEY|ACCESS_ID|CERT)", re.I)
# ...unless the name is clearly an identifier rather than the secret itself.
_NOT_SECRET_RE = re.compile(r"(KEY_?ID$|KEYTAB_FILE$|_KEY_FILE$|TSIG_FILE$)", re.I)

_ALIAS_RE = re.compile(r"^Alias to ([A-Z0-9_]+)", re.I)


def _run(argv: list[str]) -> str:
    p = subprocess.run(argv, capture_output=True, text=True, timeout=30)
    # lego writes its "not supported" errors to stderr and exits non-zero.
    return (p.stdout or "") + (p.stderr or "")


def codes(bin_: str) -> list[str]:
    txt = _run([bin_, "dnshelp"])
    m = re.search(r"Supported DNS providers:\s*(.+?)\n\s*\n", txt, re.S)
    if not m:
        sys.exit("could not parse the provider list from `lego dnshelp`")
    return [c.strip() for c in m.group(1).replace("\n", " ").split(",") if c.strip()]


def is_secret(env: str) -> bool:
    return bool(_SECRET_RE.search(env)) and not _NOT_SECRET_RE.search(env)


def describe(bin_: str, code: str) -> dict | None:
    txt = _run([bin_, "dnshelp", "-c", code])
    if "is not yet supported" in txt:
        return None
    label = code
    m = re.search(r"^Configuration for (.+?)\.\s*$", txt, re.M)
    if m:
        label = m.group(1).strip()
    doc = ""
    m = re.search(r"^More information:\s*(\S+)", txt, re.M)
    if m:
        doc = m.group(1).strip()

    block = ""
    m = re.search(r"^Credentials:\s*\n(.*?)(?:\n\s*\n|\Z)", txt, re.S | re.M)
    if m:
        block = m.group(1)

    fields, aliases = [], []
    for line in block.splitlines():
        fm = re.match(r'\s*-\s*"([A-Z0-9_]+)":\s*(.*)$', line)
        if not fm:
            continue
        env, help_ = fm.group(1), fm.group(2).strip()
        if _ALIAS_RE.match(help_):
            # Aliases are duplicates of a canonical var — listing both in the
            # form only invites filling the wrong one.
            aliases.append(env)
            continue
        fields.append({"env": env, "label": help_ or env, "secret": is_secret(env)})
    return {"slug": code, "label": label, "flag": code, "doc": doc,
            "fields": fields, "aliases": aliases}


def load_overlay(path: str) -> tuple[dict, dict]:
    """Hand-curated corrections merged on top of the client's own help output.

    `dnshelp` splits variables into "Credentials" and "Additional
    Configuration", and that split is not about secrecy: httpreq's basic-auth
    pair lives under the latter, and `exec` documents EXEC_PATH only on the
    website. The overlay is the ONE file a human edits.
    """
    if not os.path.exists(path):
        return {}, {}
    import yaml
    with open(path, "r", encoding="utf-8") as fh:
        doc = yaml.safe_load(fh) or {}
    return (doc.get("deny") or {}), (doc.get("extend") or {})


def merge(d: dict, extra: list) -> None:
    by_env = {f["env"]: f for f in d["fields"]}
    for f in extra or []:
        env = str(f.get("env") or "").strip()
        if not env:
            continue
        row = dict(f)
        row.setdefault("label", env)
        row.setdefault("secret", is_secret(env))
        if env in by_env:
            by_env[env].update(row)
        else:
            d["fields"].append(row)
            by_env[env] = row


def yq(s: str) -> str:
    return '"' + str(s).replace("\\", "\\\\").replace('"', '\\"') + '"'


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--bin", default="/usr/local/bin/lego")
    ap.add_argument("--out", default="acme_providers.yaml")
    ap.add_argument("--overlay", default="acme_providers.overlay.yaml")
    a = ap.parse_args()

    ver = _run([a.bin, "--version"]).strip()
    deny, extend = load_overlay(a.overlay)
    out, skipped, denied = [], [], []
    for c in codes(a.bin):
        if c in deny:
            denied.append("%s (%s)" % (c, deny[c]))
            continue
        d = describe(a.bin, c)
        if not d:
            skipped.append(c)
            continue
        merge(d, extend.get(c))
        out.append(d)

    lines = [
        "# ACME DNS-01 provider catalog — SEED ONLY (INSERT-ONLY at boot).",
        "#",
        "# GENERATED — do not hand-edit. Source of truth is the ACME client's own",
        "# `lego dnshelp`, so the catalog can never drift from the binary the app",
        "# executes. Regenerate after bumping the client:",
        "#",
        "#   python3 deploy/gen_acme_providers.py --bin /usr/local/bin/lego \\",
        "#       --out acme_providers.yaml",
        "#",
        "# Hand-curated corrections live in acme_providers.overlay.yaml — that is",
        "# the only file a human edits.",
        "#",
        "# Generated from: " + ver,
        "# Providers: %d" % len(out),
        "#",
        "# Seeding is INSERT-ONLY (same contract as endpoints*.yaml): a row that",
        "# already exists is never overwritten, so operator edits always win and",
        "# adding a provider upstream missed is a ROW, not a deploy.",
        "#",
        "# `flag`   -> value handed to the client's DNS selector (lego: --dns <flag>).",
        "# `fields` -> env vars the provider reads; the Settings form is rendered",
        "#             from this list verbatim. `secret: true` => Fernet-encrypted at",
        "#             rest, never returned to the browser, redacted from every log.",
        "#             Not all fields are needed at once: several providers accept",
        "#             either a legacy key pair OR a scoped token — fill the set you",
        "#             have. Aliases accepted by the client are listed in a comment.",
        "version: 1",
        "providers:",
        "",
    ]
    for d in out:
        lines.append("  - slug: %s" % d["slug"])
        lines.append("    label: %s" % yq(d["label"]))
        lines.append("    flag: %s" % d["flag"])
        if d["doc"]:
            lines.append("    doc: %s" % d["doc"])
        if d["aliases"]:
            lines.append("    # accepted aliases: " + ", ".join(d["aliases"]))
        if not d["fields"]:
            lines.append("    fields: []")
        else:
            lines.append("    fields:")
            for f in d["fields"]:
                bits = ["env: %s" % f["env"], "label: %s" % yq(f["label"])]
                if f.get("secret"):
                    bits.append("secret: true")
                if f.get("required"):
                    bits.append("required: true")
                lines.append("      - {%s}" % ", ".join(bits))
        lines.append("")
    with open(a.out, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
    print("%d providers -> %s  (client: %s)" % (len(out), a.out, ver))
    if skipped:
        print("advertised but not introspectable: " + ", ".join(skipped))
    if denied:
        print("excluded by overlay: " + "; ".join(denied))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

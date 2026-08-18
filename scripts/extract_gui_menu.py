#!/usr/bin/env python3
"""Extract one FortiWeb GUI menu section out of the appliance's OWN Angular
bundle (``main.<hash>.js``) — the authoritative menu the box renders.

This is the oracle behind the curated menus in ``app/services/server_objects.py``
and ``app/services/config_sections.py`` (safeguards §102). A curated menu drifts
in silence: nothing fails when an entry is missing, so the only honest way to
change one is to re-extract the tree from the firmware being targeted.

Usage::

    curl -sk https://<fw>/main.<hash>.js -o /tmp/fw_main.js
    python3 scripts/extract_gui_menu.py /tmp/fw_main.js "Server Objects"
    python3 scripts/extract_gui_menu.py /tmp/fw_main.js "Network"

Emits JSON: ``{"name": ..., "items": [{"name":..., "path":..., "items":[...]}]}``

The menu gives ENTRIES and their order. The TABS inside an entry are a second
read of the same file — the route table maps one key to every sub-path of a
page::

    python3 scripts/extract_gui_menu.py /tmp/fw_main.js --routes /root/system/

so ``cert_local_list -> [.../local-cert-menu/local-cert, …]`` and
``cert_multi_list -> [.../local-cert-menu/multi-cert]`` reveal that *Local* is a
page with a *Multi-certificate* tab.
"""
import json
import re
import sys

src = open(sys.argv[1], "rb").read().decode("utf8", "replace")
section = sys.argv[2] if len(sys.argv) > 2 else "Server Objects"

if section == "--routes":
    # Route-table mode: {key:{paths:["/root/…","/root/…"]}} — a key with several
    # paths under one page prefix IS that page's tab set.
    prefix = sys.argv[3] if len(sys.argv) > 3 else "/root/"
    out = {}
    for m in re.finditer(r"(\w+):\{paths:\[([^\]]*)\]\}", src):
        paths = re.findall(r'"([^"]+)"', m.group(2))
        if any(p.startswith(prefix) for p in paths):
            out.setdefault(m.group(1), paths)
    json.dump(out, sys.stdout, indent=1)
    raise SystemExit(0)

start = src.find('{name:"%s",icon:' % section)
if start < 0:
    raise SystemExit("section %r not found" % section)

# Balanced-brace scan, string-aware, from that '{'.
i, depth, in_str, quote = start, 0, False, ""
while i < len(src):
    c = src[i]
    if in_str:
        if c == "\\":
            i += 2
            continue
        if c == quote:
            in_str = False
    elif c in "\"'":
        in_str, quote = True, c
    elif c == "{":
        depth += 1
    elif c == "}":
        depth -= 1
        if depth == 0:
            break
    i += 1
blob = src[start:i + 1]

# Structural token stream: name:"..", path:"..", items:[ , [ , ] , { , }
TOK = re.compile(r'name:"((?:[^"\\]|\\.)*)"|path:"((?:[^"\\]|\\.)*)"|items:\[|\[|\]|\{|\}')


def unesc(s):
    return re.sub(r"\\(.)", r"\1", s)


toks = []
for m in TOK.finditer(blob):
    if m.group(1) is not None:
        toks.append(("name", unesc(m.group(1))))
    elif m.group(2) is not None:
        toks.append(("path", unesc(m.group(2))))
    else:
        toks.append(("p", m.group(0)))

pos = 0


def parse_list():
    """Parse the token stream for an items list; returns list of nodes."""
    global pos
    out, cur, bracket = [], None, 0
    while pos < len(toks):
        kind, val = toks[pos]
        if kind == "name":
            cur = {"name": val}
            out.append(cur)
            pos += 1
        elif kind == "path":
            if cur is not None:
                cur["path"] = val
            pos += 1
        elif val == "items:[":
            pos += 1
            child = parse_list()
            if cur is not None:
                cur["items"] = child
        elif val == "[":
            bracket += 1
            pos += 1
        elif val == "]":
            if bracket == 0:
                pos += 1
                return out
            bracket -= 1
            pos += 1
        else:  # '{' / '}'
            pos += 1
    return out


# skip to this section's own items:[
while pos < len(toks) and toks[pos] != ("p", "items:["):
    pos += 1
pos += 1
tree = {"name": section, "items": parse_list()}
json.dump(tree, sys.stdout, indent=1, ensure_ascii=False)

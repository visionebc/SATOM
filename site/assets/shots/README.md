# Screenshots — SATOM web console captures

The gallery on `index.html` ("See it in action") shows these files. A tile whose
file is missing shows a dashed "screenshot pending" placeholder; a present file
renders with a click-to-zoom lightbox. No HTML edit is needed to replace one.

| Filename            | Caption on the site                                              |
|---------------------|------------------------------------------------------------------|
| `dashboard.png`     | Dashboard — HA nodes, backup server and every ADOM at a glance   |
| `signatures.png`    | Signatures — FortiWeb WAF signatures & guided exceptions         |
| `templates.png`     | Templates — every template against every firmware build          |
| `object-editor.png` | Object editor — the device's GUI layout + CLI-only fields        |
| `metrics.png`       | Metrics — one call per device and collector, 396-day local store |
| `backups.png`       | Backups & HA — every copy of the system and its state            |

How they are made (2026-10-11): captured from a live node at 1600×1000 with a
headless Chromium, ANONYMISED IN THE PAGE before the capture — appliance and
node names, private addresses, host names, serials, MACs and user names are
rewritten to documentation values (`fwb-01`, `198.51.100.x`, `satom.example.com`)
and the rendered text is re-checked against the real identifiers; a capture with
a hit is discarded. The published-docs leak scanner reads text only and cannot
see inside an image, so never drop in a screenshot taken any other way.
They are shown `object-fit: cover` from the top: the top of each screen matters most.

# SATOM site (published as Pages)

Static, multi-page site published verbatim by the prod-sync pipeline:
the `gh-pages` branch is generated from `main:site/` (this directory is the
whole published tree — no build step, no Jekyll; `.nojekyll` disables the
GitHub Pages Jekyll pass on purpose so the internal mirror serves the exact
same files).

Template = shared `assets/site.css`. The nav and footer written in these pages
are REPLACED when the site is assembled: satom-site `deploy/apply_chrome.py` is
the only author of the menu and footer of every published page, so edit them
there, not here. When adding a page, keep all asset/link hrefs RELATIVE
(the site is served both at the domain root and under a repo subpath).

`CNAME` pins the GitHub Pages custom domain (satom.visionebc.com) — do
not delete it; the branch is force-pushed on every sync and GitHub drops the
custom domain if the file disappears.

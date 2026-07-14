# OFortMAut site (published as Pages)

Static, multi-page site published verbatim by the prod-sync pipeline:
the `gh-pages` branch is generated from `main:site/` (this directory is the
whole published tree — no build step, no Jekyll; `.nojekyll` disables the
GitHub Pages Jekyll pass on purpose so the internal mirror serves the exact
same files).

Template = shared `assets/site.css` + the common nav/footer block repeated
in each page. When adding a page: copy the nav/footer from an existing one,
mark the right link `class="active"`, and keep all asset/link hrefs RELATIVE
(the site is served both at the domain root and under a repo subpath).

`CNAME` pins the GitHub Pages custom domain (ofortmaut.example.net) — do
not delete it; the branch is force-pushed on every sync and GitHub drops the
custom domain if the file disappears.

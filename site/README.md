# SATOM site — the product layer of satom.visionebc.com

Static, multi-page tree with no build step and no Jekyll. It is **not** a
GitHub Pages site: Pages is switched off for SATOM, and the GitHub mirror
carries `main` and the release tags only — no `gh-pages` branch
([release pipeline](../docs/release-pipeline.md)). The pages under `docs/`,
`docs.html` and `releases/` are generated from the Markdown by
`deploy/gen_site_docs.py` and `deploy/gen_release_notes.py`; do not hand-edit
them.

How the public site is published: the separate **satom-site** repository
assembles it and deploys it to its own web node (`deploy/deploy.sh`, with
`SATOM_PRODUCT_SRC` pointing at a checkout of this repository). It takes its
own front page (`index.html`) and, from this directory, only the product layer:

| From here | Published as |
|---|---|
| `docs/` | `docs/` |
| `features.html`, `architecture.html` | the same names |
| `docs.html` (the reference hub) | `reference.html` |
| `assets/site.css`, `site.js`, the product marks, `assets/shots/` | the same paths |

Everything else here is not published by that deploy: `index.html`,
`install.html`, `safeguards.html`, `releases.html` and `releases/` (their
content lives in the Documentation Center). This `index.html` is still the
page a SATOM node's own nginx serves at the root of this directory
(`satom-pages.conf`), so keep its facts current.

Every node also serves this tree itself, at `/manual/` (`app/views/manual.py`),
together with `../docs-center/` (the Documentation Center's public build) at
`/manual/docs-center/` — the sign-in page links there, so the manual works
without the public site. Only page assets are served from here (HTML, CSS,
JS, JSON, images, fonts); this README and dotfiles are not.

The nav and footer written in these pages are REPLACED when the site is
assembled: satom-site `deploy/apply_chrome.py` is the only author of the menu
and footer of every published page, so edit them there, not here. When adding
a page, keep all asset/link hrefs RELATIVE (the tree is served both at a domain
root and under a subpath).

`CNAME` (the public host, `satom.visionebc.com`) and `.nojekyll` are
leftovers of the GitHub Pages era; the satom-site deploy does not copy them.

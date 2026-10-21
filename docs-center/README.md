# Documentation Center — public build (generated, do not edit)

This directory is the **public build** of the SATOM Documentation Center
(`build.py --no-internal`). Its source is the `docs-center/` directory of the
**satom-site** repository; nothing here is written by hand, and an edit made
here is overwritten by the next refresh.

Every node serves it at **`/manual/docs-center/`** (`app/views/manual.py`),
next to the generated pages of `site/` at `/manual/`. Its pages link the site
pages as `../index.html`, `../assets/site.css` and so on, which is why the two
trees are served as one URL space. The sign-in page's *Documentation* link and
every in-product `docs_url()` resolve to this copy first
(`app/services/doc_publication.py:local_url`), so the manual works on a node
with no route to the public site.

It is the redacted, leak-scanned output of the build: the build refuses to run
without the site's publication rules and aborts on any leak, and
`tests/test_manual_local.py` scans this tree again.

## Refresh

The release pipeline does it at every cut (step `docs_center`): it builds the
satom-site `origin/master` against the release tree and commits the result
here when it changed. By hand, on the primary, as the `satom` user:

    git -C <satom-site checkout> archive origin/master docs-center | tar x -C /tmp/dcsrc
    venv/bin/python3 /tmp/dcsrc/docs-center/build.py --src /opt/satom --no-internal --out /tmp/dcout
    rsync -a --delete --exclude README.md /tmp/dcout/ /opt/satom/docs-center/

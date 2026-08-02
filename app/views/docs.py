"""Documentation — renders the project's Markdown docs as in-app HTML pages.

The docs live as Markdown files in the repo-root ``docs/`` directory. This
blueprint renders them with python-markdown (fenced code, tables, ToC) so the
whole team can read the project reference, operational rules, and installation
guide from inside the app — no shell access needed.

Security notes:
  * ``login_required`` only — docs are readable by any authenticated user
    regardless of role (no secrets live in them).
  * Path traversal is impossible: the slug is validated against the set of
    ``*.md`` basenames actually present in ``docs/`` and the resolved path is
    re-checked to be inside ``DOCS_DIR``.
  * The rendered HTML is derived from repo-controlled files (not user input);
    it carries no <script> tags and is CSP-safe.
"""
from __future__ import annotations

import pathlib

from flask import Blueprint, abort, render_template
from flask_login import login_required
from markupsafe import Markup

# docs/ lives at the project root — two levels above this file (app/views/).
DOCS_DIR = (pathlib.Path(__file__).resolve().parents[2] / "docs")

# Documents that live OUTSIDE docs/ but belong in the catalog. The changelog
# sits at the repo root because that is where every tool looks for it (Keep a
# Changelog, GitHub, the release pipeline); copying it into docs/ would create
# a second copy that rots. An explicit map keeps the slug allowlist -- and the
# traversal guard -- exact rather than opening docs/ to symlinks.
_EXTRA_SOURCES: dict[str, pathlib.Path] = {
    "CHANGELOG.md": DOCS_DIR.parent / "CHANGELOG.md",
}

# Friendly titles + curated display order. Files present in docs/ but not listed
# here still appear (auto-titled from the filename) after the curated ones.
_TITLES: dict[str, str] = {
    "CHANGELOG.md": "Changelog — Every Release, Every Change",
    "README.md": "Documentation Index & Reading Paths",
    "overview.md": "Project Overview & Operational Rules",
    "management-overview.md": "Management Overview (non-technical)",
    "user-guide.md": "User Guide",
    "INSTALL.md": "Installation & Deployment",
    "safeguards.md": "Safeguards — Protections & Guard Rails",
    "privilege-model.md": "Privilege Model & HA Trust",
    "cli.md": "Operator CLI (satom) — Console Reference",
    "theming.md": "Theming — Appearance, Design Tokens & Brand",
    "git-backup-and-outage.md": "Git Backup & Surviving a Gitea Outage",
    "encryption-and-node-tls.md": "Encryption in Transit & Node TLS",
    "acme-certificate-manager.md": "ACME / Let's Encrypt Certificates",
    "source-of-truth-spec.md": "Source-of-Truth Specification",
    "engineering.md": "Engineering Manual",
    "server_policy.md": "Server Policy Reference",
    "web_protection_profile.md": "Web Protection Profile Reference",
    "wpp_exceptions.md": "WPP Exceptions & Signatures",
    "fortiadc.md": "FortiADC — API Conventions",
    "release_notes.md": "Release Notes & Upgrade Planning",
    "release-pipeline.md": "Release & Publication Pipeline",
    "api_v1.md": "API v1 — Integration Manual",
}

# One-line descriptions for the catalog cards.
_BLURBS: dict[str, str] = {
    "CHANGELOG.md": "What changed in each release and what is still unreleased — the same file published in the repository and on the public site.",
    "README.md": "Start here: every document, which surface to read it on, and the reading path for your role.",
    "overview.md": "What this app is, architecture, deployment, security posture and the operational rules.",
    "management-overview.md": "The same system explained without jargon: what it solves, how mature it is, risks and cost.",
    "user-guide.md": "Day-to-day operation, screen by screen.",
    "INSTALL.md": "How to install, configure and migrate the manager.",
    "safeguards.md": "Every protection in one page: what it prevents, where it lives, and how to verify it is armed.",
    "privilege-model.md": "Which account runs what, the sudo allowlist, the privileged-runner boundary and node-to-node trust.",
    "cli.md": "The console tool for a node whose web UI is down: diagnose, control and rebuild, and the sudo rule to request.",
    "theming.md": "Repainting the console: design tokens, named themes, the value allowlist, the contrast audit and how to get back.",
    "git-backup-and-outage.md": "Surviving a Gitea outage: the anti-reset guard, the unpushed-commit alert and the repository bundles.",
    "encryption-and-node-tls.md": "Service certificate, node-to-node encryption, enforced Postgres SSL, and the Monitoring encryption cards.",
    "acme-certificate-manager.md": "ACME issuance, the DNS-provider catalog, and how credentials reach the signer without leaking.",
    "source-of-truth-spec.md": "The authoritative behavioural specification.",
    "engineering.md": "Internal architecture for developers: layers, registry, device clients, jobs and testing.",
    "server_policy.md": "Field-level reference for the Server Policy object graph.",
    "web_protection_profile.md": "The ~40 sub-policy WAF bundle, field by field.",
    "wpp_exceptions.md": "Authoring and injecting WAF exceptions and signature carve-outs.",
    "fortiadc.md": "REST conventions, object map and current coverage for FortiADC.",
    "release_notes.md": "Known/resolved issues corpus and the upgrade advisor.",
    "release-pipeline.md": "How a release is sanitized, secret-scanned, audited and published.",
    "api_v1.md": "How third parties authenticate and drive /api/v1 with a token.",
}

_MD_EXTENSIONS = ["toc", "fenced_code", "tables", "sane_lists", "nl2br"]

bp = Blueprint("docs", __name__, url_prefix="/docs")


def _catalog() -> list[dict]:
    """Discovered ``*.md`` docs, curated order first, then any extras."""
    try:
        present = {p.name for p in DOCS_DIR.glob("*.md") if p.is_file()}
    except OSError:
        present = set()
    present |= {n for n, src in _EXTRA_SOURCES.items() if src.is_file()}
    ordered = [n for n in _TITLES if n in present]
    extras = sorted(present - set(_TITLES))
    out: list[dict] = []
    for name in ordered + extras:
        out.append({
            "slug": name,
            "title": _TITLES.get(name, name.rsplit(".", 1)[0].replace("_", " ").replace("-", " ").title()),
            "blurb": _BLURBS.get(name, ""),
        })
    return out


@bp.route("/")
@login_required
def index():
    return render_template("docs/index.html", docs=_catalog())


@bp.route("/<slug>")
@login_required
def view(slug: str):
    import markdown as md_lib

    catalog = {d["slug"]: d for d in _catalog()}
    if slug not in catalog:  # allowlist — no traversal possible
        abort(404)
    extra = _EXTRA_SOURCES.get(slug)
    if extra is not None:
        # Not a path built from the slug: a constant chosen at import time.
        path = extra.resolve()
        if not path.is_file():
            abort(404)
    else:
        path = (DOCS_DIR / slug).resolve()
        # Defence in depth: the resolved path must stay inside DOCS_DIR.
        if DOCS_DIR.resolve() not in path.parents or not path.is_file():
            abort(404)
    text = path.read_text(encoding="utf-8")
    html = Markup(md_lib.markdown(text, extensions=_MD_EXTENSIONS, output_format="html5"))
    return render_template(
        "docs/view.html",
        title=catalog[slug]["title"],
        content=html,
        slug=slug,
        docs=_catalog(),
    )


# ---------------------------------------------------------------------------
# PUBLIC API manual — readable WITHOUT login (documentation only, no secrets).
# Linked from the sign-in page so integrators can learn how to use /api/v1
# before they have an account. Rendered in a standalone (no-sidebar) template
# so it needs no authenticated session context.
# ---------------------------------------------------------------------------
_API_DOC = "api_v1.md"


@bp.route("/api")
def api_public():
    import markdown as md_lib

    path = (DOCS_DIR / _API_DOC).resolve()
    if DOCS_DIR.resolve() not in path.parents or not path.is_file():
        abort(404)
    text = path.read_text(encoding="utf-8")
    html = Markup(md_lib.markdown(text, extensions=_MD_EXTENSIONS, output_format="html5"))
    return render_template(
        "docs/public.html",
        title="API v1 — Integration Manual",
        content=html,
    )

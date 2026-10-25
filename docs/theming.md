# Theming the console

Settings → **Appearance** repaints SATOM: the design tokens the stylesheet
exposes, plus an optional brand logo and favicon, saved as named **themes**.

The shipped look is a theme called **SATOM Aurora** — the blue/gold brand
palette, including the brand gradients and glows. It is a built-in and carries
*no* token overrides at all: it *is* the stylesheet, so it can never drift from
it, and a fresh install renders it with no database rows at all.

The palette that shipped before it is still available as the built-in **SATOM
Classic**; unlike Aurora it carries explicit overrides, because it is no longer
what the stylesheet says.

---

## 1. What a theme is

A theme stores only the tokens it actually **changes**. Everything else falls
through to the stylesheet.

That is the whole design decision, and it has a consequence worth stating: when
a future release improves a default — a better border colour, a tighter radius —
that improvement reaches every theme that never opted out of it. A theme that
stored all 34 values would instead freeze a snapshot of an old palette and
quietly diverge from the product.

The token registry is **generated from the stylesheet** by
`deploy/gen_theme_tokens.py`. A hand-maintained list would be a copy, and copies
rot: the first release that adds a `--fw-*` variable would leave the editor
silently missing a control. `tests/test_theme.py` runs the generator with
`--check` and fails the suite on drift.

### Adding a token

Two edits, **in the same commit**:

1. the `--fw-*` variable in `app/static/css/fortiweb.css`;
2. an entry in `META` in `deploy/gen_theme_tokens.py` (group, label, kind, help,
   and optionally `on=` naming the surface it must contrast against).

Then regenerate:

```
python3 deploy/gen_theme_tokens.py
```

Forgetting step 2 fails the suite by design.

---

## 2. Token groups

| Group | Covers |
|---|---|
| Sidebar | Navigation background, text, active marker, section captions |
| Top bar | Header background and text (a per-ADOM banner can still override the background) |
| Surfaces | Page canvas, card surface, muted surface, borders |
| Accent | Primary buttons, links, focus rings, and the selected-row tint |
| Text | Primary and secondary copy |
| Status | Success / danger / warning / info |
| Elevation | Card shadows, resting and hover |
| Layout | Sidebar width, top bar height, corner radii, transition |
| Typography | Interface font stack |

---

## 3. Values are allowlisted, not passed through

A token value ends up inside a `<style>` element that carries the app's own CSP
nonce. Accepting free text there is stored CSS injection: a value containing `}`
closes the rule and opens a new one.

So every value must match a narrow pattern for its **kind**
(`color`, `length`, `shadow`, `transition`, `font`) **and** survive a shared
reject list (`;`, `{`, `}`, `<`, `>`, `url(`, `expression(`, `@import`,
`javascript:`, newlines). Anything else is refused with the token named.

Two details that are easy to get wrong:

* The reject list is not redundant with the per-kind patterns. A colour pattern
  is narrow enough to stop everything on its own, but `shadow` and `font`
  legitimately allow letters, digits, dots and parentheses — `url(evil)` matches
  the shadow character class. The reject list is what stops it.
* **`css_for()` re-validates on the way out**, not just on save. The database is
  not a trust boundary: a row can arrive from a restored backup, a streaming
  replica, or a hand-edited `psql` session.

---

## 4. Contrast

Each text token is paired in the registry with the surface it sits on. Saving a
theme audits those pairs against WCAG 2.1:

* below **4.5:1** — reported as a warning;
* below **3.0:1** — treated as *unreadable*: the save is refused until the
  operator ticks **apply anyway**.

It warns rather than blocks, because an operator may legitimately accept a
low-contrast accent. What must never happen is applying an unreadable palette
*without being told*.

> **Known debt in the shipped palette.** The stylesheet's own accent
> (`#EF5424`) is 3.52:1 on white and the sidebar section caption is 4.0:1 — both
> under AA, both above the unreadable floor. `tests/test_theme.py` pins these
> two so a change that makes either *worse* fails the suite. The two shipped
> alternates, **SATOM Slate** and **SATOM Graphite**, are clean.

---

## 5. Getting back

The realistic accident is picking two dark colours and losing the page that
would fix it. Three ways back, in order of how broken things are:

1. **Settings → Appearance → “Revert to the shipped look.”**
2. Activate any built-in from the theme list.
3. If the console is unusable, from a shell on the node:

   ```
   satom execute reset theme
   ```

Built-in themes **cannot be edited or deleted**, which is what makes them a
reliable escape hatch. Deleting the *active* theme falls back to the built-in
rather than leaving the console with no theme at all.

---

## 6. Logo and favicon

A theme may carry a brand logo and a favicon. While it is active they replace
the top-bar mark in **every** ADOM.

Leave them empty to keep the per-ADOM marks, which are managed separately in
**Settings → ADOMs** and remain the right place for a *per-product* mark. The
theme-level logo is the white-label switch, not a replacement for those.

Uploads are stored under `data/branding/`. That location is deliberate:
`data/` is replicated to the standby by `satom-ha-datasync` and is included in
the system backup bundles, so a custom logo survives a failover and a restore.
(The per-ADOM marks live under `static/img`, which is node-local and outside
both — a difference worth knowing before assuming a logo replicated.)

SVGs are sanitised (script, `foreignObject`, `iframe`/`embed`/`object`, event
handlers in any quoting, `javascript:`, and links other than `#id` or an
embedded image are stripped). The asset route then serves SVG under
`Content-Security-Policy: default-src 'none'; …; sandbox`, so whatever the
sanitiser missed cannot run even when the file is opened directly. Rasters are
re-encoded through Pillow and fitted to 256 px, which is also what rejects a
file that merely claims to be an image. The top bar shows the mark at 28 × 28
px with `object-fit: contain`, so a non-square upload keeps its proportions.

---

## 7. Sharing a theme

**Export** produces portable JSON, schema `satom.ui-theme/2`: the token
overrides plus the logo and favicon (base64), with no ids or node state, so it
imports on any install regardless of its own theme list. Version 1 files
(tokens only, everything exported before v2) still import. **Import** runs the
same validation as the editor and refuses the whole file if any token or asset
fails, rather than importing a partial theme.

**Import from a site…** (next to Import) brings a look in without a file. Both
ways create a new, **inactive** theme; review it in the editor, then Apply.

* **Another SATOM node.** Give its address and an API token minted there with
  the `read` scope (**API Tokens**). This node fetches `GET /api/v1/ui/theme`
  (the active theme, or the one named in *Theme name*) and imports the same v2
  document Export produces, logo and favicon included. The token is used for
  that one request: it is not stored, logged or shown again. A node that uses
  a private CA needs that CA in **Settings → Trust store** first; TLS is always
  verified.
* **A website.** This node reads the page and up to six of its stylesheets and
  builds a theme from what it finds (`app/services/theme_from_site.py`):
  * **Colours.** The brand colour comes from the page's `theme-color`, else a
    brand-named CSS variable (`--primary`, `--brand-*`, `--accent`…), else the
    most used saturated colour. It becomes the accent, sidebar, top bar,
    gradients and glows; a second colour of a different hue becomes the active
    marker and the accent gradient. A dark background on a
    header/nav/sidebar rule becomes the sidebar, so a site with a dark
    navigation keeps it. Every audited pair is pushed to 4.5:1 (the accent is
    darkened if it would be unreadable on white), so an imported palette never
    needs "apply anyway".
  * **Logo.** The top-bar mark is a 28 × 28 px square, so the site's square
    icon wins: apple-touch-icon, then its largest icon, and only then a logo
    image from its header, if it is no wider than 1.6:1. A wide wordmark is
    skipped and said so: squeezed into the square it is unreadable, and it is
    usually drawn dark-on-white for a white header.
  * **Favicon.** Its icon link closest to 64 px, else `/favicon.ico`.
  * **Not taken:** the layout (SATOM's is fixed), the page canvas, text and
    status colours (§8), and the font (a web font is blocked by the console's
    CSP and missing on offline nodes).

  After the import, one line per decision says where each value came from.

**What the node will fetch.** Only `http://` and `https://`, with no
credentials in the URL. Loopback, link-local (169.254.0.0/16, which holds
cloud metadata services), multicast, unspecified and reserved destinations are
refused, by name (`localhost`) and by every address the name resolves to, and
every redirect is checked again. Internal (RFC 1918) addresses are allowed:
a company site or a peer node usually lives on one. Page 2 MB, stylesheet
1.5 MB, image 4 MB, document 12 MB, 10 s per request, 4 redirects; an API token
is sent to the host the operator typed and never to a host a redirect points
at. Both routes are admin-only and rate-limited (20/min).

---

## 8. What a theme cannot repaint

Status badges and a handful of decorative tints still carry literal colours in
the stylesheet. A **dark canvas is therefore not offered yet**: it would leave
those elements light. Light-canvas palettes are fully supported.

Closing that gap means tokenising those literals — a bounded but real change to
the stylesheet, tracked separately. The card, input, table and modal surfaces
were already tokenised (`--fw-surface`, `--fw-surface-alt`) as part of this
work; what remains is the status tints.

### Plugins follow the theme too

Report Studio views and widgets render in a sandboxed iframe that cannot load
`fortiweb.css`. The frame therefore carries the tokens itself: every `--fw-*`
token at its stylesheet default, then the active theme's override block (the
same `css_for()` output, re-validated per kind), then the plugin class kit
(`app/static/css/plugin-kit.css`, inlined) and finally the plugin's own CSS.
Activating a theme reaches every plugin that uses the tokens or the kit
(within the 15 s cache TTL), with no change to the plugin. The status colours in
the kit are the same literals as the console's `.fw-badge-*` block, so the same
"cannot repaint" caveat applies there. What a plugin stylesheet may contain is
in the user guide, Report Studio, *Plugin CSS rules*.


---

## 9. Brand gradients and glows

Five tokens sit in the **Brand** group and behave unlike the rest.

| Token | Kind | What it paints |
|---|---|---|
| `gradient-brand` | `gradient` | Primary buttons, the top-bar hairline, the sign-in page |
| `gradient-accent` | `gradient` | Secondary ramp for call-to-action fills |
| `glow` | `color` | Halo behind the brand mark, hover shadows |
| `glow-accent` | `color` | Warm half of the halo |
| `glow-strength` | `ratio` | `0` disables every glow, `1` is full strength |

Three rules hold, and each has a concrete failure behind it.

**A gradient is paint, not a colour.** `border-color`, `outline-color`,
`text-decoration-color` and `column-rule-color` accept only a colour and
**silently discard** a gradient — the border does not turn the wrong colour, it
disappears. A gradient belongs in `background-image` or `border-image`.
`tests/test_theme.py` greps the stylesheet and fails if one is ever fed to a
property that drops it.

**The contrast auditor cannot judge a ramp.** It composites two flat colours; a
gradient has neither a single foreground nor a single background. Gradient
tokens therefore have no contrast partner, and a test asserts none is ever
added — a report that appeared authoritative about a number it cannot compute
would be worse than no report.

**Every non-default theme must state its own gradients.** A theme stores only
what it changes, so a palette that leaves the gradients alone inherits the
*shipped* blue ramp: an amber console would paint blue-ramped buttons and an
ember one would glow electric blue. The stylesheet default belongs only to the
theme that *is* the stylesheet. A test enforces this for every built-in.

### Built-ins are reconciled, not just seeded

Operator themes are never touched by the seeder. Built-in rows **are**, on every
boot, because they are code: the UI refuses to edit or delete them, so there is
no operator intent to preserve, and a stale one is a live hazard.

The concrete case: an install created before the palette change holds
`satom-classic` with `tokens = {}`. "No overrides" means "whatever the
stylesheet is" — so after the change that row would have rendered the *new*
palette under the *old* name, i.e. the recovery theme handing back the look you
were trying to escape.

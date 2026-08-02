# Theming the console

Settings → **Appearance** repaints SATOM: the design tokens the stylesheet
exposes, plus an optional brand logo and favicon, saved as named **themes**.

The shipped look is a theme called **SATOM Classic**. It is a built-in and
carries *no* token overrides at all — it *is* the stylesheet, so it can never
drift from it.

---

## 1. What a theme is

A theme stores only the tokens it actually **changes**. Everything else falls
through to the stylesheet.

That is the whole design decision, and it has a consequence worth stating: when
a future release improves a default — a better border colour, a tighter radius —
that improvement reaches every theme that never opted out of it. A theme that
stored all 29 values would instead freeze a snapshot of an old palette and
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

SVGs are sanitised (scripts, event handlers and `javascript:` stripped) because
they go into the DOM. Rasters are re-encoded through Pillow and fitted to
256 px, which is also what rejects a file that merely claims to be an image.

---

## 7. Sharing a theme

**Export** produces portable JSON — schema `satom.ui-theme/1`, token overrides
only, no ids or node state — so it imports on any install regardless of its own
theme list. **Import** runs the same validation as the editor and refuses the
whole file if any token fails, rather than importing a partial palette.

---

## 8. What a theme cannot repaint

Status badges and a handful of decorative tints still carry literal colours in
the stylesheet. A **dark canvas is therefore not offered yet**: it would leave
those elements light. Light-canvas palettes are fully supported.

Closing that gap means tokenising those literals — a bounded but real change to
the stylesheet, tracked separately. The card, input, table and modal surfaces
were already tokenised (`--fw-surface`, `--fw-surface-alt`) as part of this
work; what remains is the status tints.

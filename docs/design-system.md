# Design system — how the console looks, and the rules for changing it

`theming.md` explains the **mechanism**: design tokens, named themes, the value
allowlist, the contrast audit and how to get back. This document is the
**rulebook** for anyone who writes a template, a stylesheet, a chart or a
plugin view: which files own which styles, which colours exist, which
components to reuse, and which mistakes have already shipped once.

When a rule here changes, this file changes in the same commit. The values
quoted below are the stylesheet defaults (the built-in theme **SATOM Aurora**);
`app/static/css/fortiweb.css` is the source and wins over this page.

---

## 1. SATOM is a light product

There is one canvas and it is light. There is **no dark mode**: no
`prefers-color-scheme`, no `data-theme`, no body class. A dark canvas is not
offered as a theme either, because the status tints are still literal colours
(`theming.md` §8).

Two things follow, and both have shipped by mistake before:

- **Dark glassmorphism is a grey slab here.** A card painted
  `rgba(30,41,59,.8)` with a `backdrop-filter` on a white page renders as an
  opaque grey block.
- **Dark-theme pastels are unreadable here.** Status pills in `#6ee7b7`,
  `#fcd34d` or `#fca5a5` on a 12 % tint of their own hue measure about
  **1.4:1** — a `crit` badge nobody can read.

The only dark surfaces in the product are the navigation chrome (sidebar and
top bar) and **code** (`.fw-code-block`, the Web Server Manager editor, a
template's source in a viewer). Modals, drawers, pickers and empty states are
light — the audit detail drawer, the device switcher, the baseline template
viewer and the High Availability node cards were dark until 4.12 and were
converted.

**Map canvases are light too.** The Service Diagram fleet map
(`static/js/fleet_map.js`, `templates/architecture/index.html`) and Network
Architecture (`templates/netarch/index.html`, `static/js/netarch.js`) drew on a
dark "neon" canvas until 4.12. They now draw on `#F8FAFE` with a faint grid:
white nodes with a soft shadow, theme text colours, and the 600/700 hues listed in
§3 for lines, states and zones.

### The one exception: the Observability area is dark

Everything under **`/observability/`** wears the Observability theme (operator
decision, 2026-11-17: "everything in the Monitoring menu goes into
/observability — colours, CSS and animations from Observability"). That is the
Observability app's own pages **and** SATOM's Monitoring views, which moved to
`/observability/monitoring/` (Device health, SATOM health, Metrics, Analysis,
Deep monitors, Service Monitor, Service checks, Dashboards, Reports).

- **One theme, not a second palette.** The tokens are the app's
  `app/observability_lab/static/css/theme.css` (`--obs-*`, midnight navy,
  Inter, `data-bs-theme="dark"`) and `observability.css`; SATOM's pages load
  those two files, from the app, after `fortiweb.css`. `base.html` switches on
  `obs_shell` (the request path is under `/observability/` and the account
  holds `observability.access`) and draws the app's top bar and sidebar
  instead of SATOM's (`templates/observability/_shell_*.html`).
- **`static/css/obs_shell.css` is the bridge**, scoped to `html.obs-shell`:
  layout inside the fixed top bar and sidebar, the `--fw-*` tokens theme.css
  does not re-point, and the few light literals `fortiweb.css` hard-codes
  (badges, alerts, card headers, zebra rows). Every colour in it is an
  `--obs-*` token.
- **The Monitoring templates carry `--obs-*` tokens, not light literals.**
  Their style blocks were re-coloured (status `--obs-ok/-stale/-err`, surfaces
  `--obs-surface*`, text `--obs-text*`); inside `<script>` (canvas colours)
  the token's literal value is used, because Chart.js cannot read `var()`.
  `static/js/obs_shell.js` sets Chart.js's axis, grid, legend and tooltip
  defaults to the app's (`--viz-axis`, `--viz-grid`).
  `tests/test_observability_shell.py` fails if a light-theme literal comes back.
- **Motion is the app's**: the live pill's pulse, the skeleton shimmer,
  the sidebar collapse, all honouring `prefers-reduced-motion`. No page adds
  its own entrance animation.
- **Everything outside `/observability/` stays light**, with every rule of this
  page. A SATOM page never opts into the dark theme by itself; living under
  the prefix is what decides it.

---

## 2. Stylesheets — what each file owns

| File | Owns |
|---|---|
| `fortiweb.css` | The base theme: every `--fw-*` token, layout (sidebar, top bar, content), cards, tables, forms, buttons, badges, alerts. Loaded on every page. |
| `analytics.css` | Dashboards (Monitoring) and period reports — Observability tokens (§1, the exception). |
| `obs_shell.css` | The bridge that draws SATOM's pages in the Observability shell (§1, the exception). |
| `service_checks.css` | Monitoring › Service checks: KPI tiles, the web cards with their screenshot, the result strip. |
| `waf.css` | The WAF fleet pages (findings, pills, borrowed settings). |
| `wiki.css` | Operations › Wiki (two-column layout by container query). |
| `wsm.css` | Web Server Manager (Linux ADOM): layout only, on SATOM's own components. |
| `apps_portal.css` | The Apps-only portal: the console's light theme and top bar without the sidebar. |
| `app_design.css` | Plugin Studio app designer: spacing and structure only; colours come from tokens, overridable inside `.sapp` alone. |
| `example_browser.css` | The shared Studio example browser (self-contained light theme). |
| `icon_picker.css` | The icon picker used by Plugin Studio and Report Studio. |
| `plugin-kit.css` | Base look of every plugin view and widget; **inlined** into the sandboxed frame (§9). |

Rules:

- **A self-contained page family gets its own file**, not an append to
  `fortiweb.css`. `fortiweb.css` is the file every feature edits, so appending
  to it is how two concurrent changes collide.
- **A feature stylesheet lays out SATOM's components; it does not restyle
  them.** Colours come from tokens (§3) and statuses from the badge set (§4).
- Stylesheets are served through `asset()` with an mtime cache-buster: a
  static-only change needs no restart.
- **Every third-party browser asset is vendored** under `app/static/vendor/`
  and listed in `vendor/MANIFEST.json` with its hash: Bootstrap 5.3.3,
  Bootstrap Icons 1.11.3, Inter 4.1, Chart.js 4.4.4, Toast UI Editor 3.2.2.
  Nothing loads from another origin, so an offline node on an isolated
  management network renders exactly like an online one
  (`tests/test_offline_assets.py`; procedure in `engineering.md` §9.1).

---

## 3. Tokens

Every colour, radius and shadow that a theme can change is a `--fw-*` custom
property in `:root` of `fortiweb.css`. The theme editor's registry is generated
from it (`deploy/gen_theme_tokens.py`), so a new token is two edits in one
commit — see `theming.md` §1.

### Colour tokens (SATOM Aurora)

| Token | Value | Used for | Contrast |
|---|---|---|---|
| `--fw-content-bg` | `#F3F6FC` | Page canvas | — |
| `--fw-surface` | `#FFFFFF` | Cards, inputs, tables, modals | — |
| `--fw-surface-alt` | `#F8FAFE` | Muted surface (striping, wells) | — |
| `--fw-border` | `#DCE4F3` | Card and control borders | — |
| `--fw-border-light` | `#EAEFF9` | Dividers | — |
| `--fw-text-primary` | `#0C1B33` | Body text | 15.9:1 on canvas |
| `--fw-text-secondary` | `#51607F` | Secondary text | 6.3:1 on white |
| `--fw-accent` | `#0A3F9F` | Links, primary actions, focus | 9.4:1 on white |
| `--fw-accent-hover` | `#041F5A` | Hover / pressed accent | — |
| `--fw-accent-light` | `rgba(10,63,159,.10)` | Selected-row tint | — |
| `--fw-sidebar-bg` | `#0A3F9F` | Navigation background | — |
| `--fw-sidebar-text` | `#C7D6F5` | Navigation text | 6.5:1 on sidebar |
| `--fw-sidebar-section` | `#9FB6E0` | Section captions | 4.6:1 on sidebar |
| `--fw-sidebar-active` | `#F3B52F` | Active marker | 5.2:1 on sidebar |
| `--fw-topbar-bg` | `#041F5A` | Top bar | — |
| `--fw-success` / `--fw-danger` / `--fw-warning` / `--fw-info` | `#28A745` / `#DC3545` / `#F3B52F` / `#17A2B8` | Fills and icons — **not** text on white (use §4) | — |

Brand tokens: `--fw-gradient-brand` (blue ramp `#041F5A → #0A3F9F → #12B8FF →
#39D4FF`), `--fw-gradient-accent` (gold ramp `#C98A11 → #F3B52F → #FFD45A`),
`--fw-glow`, `--fw-glow-accent`, `--fw-glow-strength`. A gradient is paint, not
a colour: only `background-image` or `border-image` (`theming.md` §9).

Layout tokens: `--fw-sidebar-width` 264 px, `--fw-topbar-height` 50 px,
`--fw-radius` 4 px, `--fw-radius-lg` 8 px, `--fw-card-shadow`,
`--fw-card-shadow-hover`, `--fw-transition` 0.2 s, `--fw-font` (Inter, then
the system stack).

### Rules for tokens

- **Use the token, never its value.** A literal `#0A3F9F` in a feature
  stylesheet does not follow the active theme.
- **A fallback inside `var()` must be the current default, or absent.** A
  stale fallback is a second palette hiding in the code (the pre-1.2.3 accent
  `#EF5424` survived this way in several rules).
- **Drawings read the token too.** An SVG presentation attribute
  (`fill="…"`, `stroke="…"`) cannot hold `var()`: put the colour in `style`
  instead (`style="stroke:var(--fw-accent, #0A3F9F)"`). Canvas and Chart.js
  code reads it at run time:
  `getComputedStyle(document.documentElement).getPropertyValue('--fw-accent').trim() || '#0A3F9F'`.
- **Categorical palettes are not the accent.** A palette that tells
  categories apart (ER diagram domains, map zones, chart series after the
  first) keeps its own fixed hues; only the colour that means "the accent"
  (selection, focus, highlight, the first series) comes from the token.
- **Never set `fill` on `#id text`.** In an SVG, a rule like
  `#mapSvg text { fill: … }` outranks every `.class` rule and every `fill`
  attribute set from JavaScript, so per-class text colours silently stop
  working. Put the default on the `<svg>` (`#mapSvg { fill: … }`) and let text
  inherit it; class rules and attributes then win as intended.

### Colours on a light canvas (lines, states, categories)

The bright "500" hues of dark dashboards fall to 2–3:1 on white. On a SATOM
canvas use the 600/700 step of the same hue:

| Meaning | Use | Instead of |
|---|---|---|
| Default line / HTTP / selection | `#1D4ED8` | `#4f8cff`, `#3b82f6` |
| OK, HTTPS, protected | `#15803D` (text `#15692A`) | `#22c55e`, `#10b981` |
| Warning, monitor mode | `#B45309` | `#f59e0b` |
| Down, denied, error | `#B91C1C` | `#ef4444` |
| Pool / segment (violet) | `#7C3AED` | `#8b5cf6`, `#a78bfa` |
| Back-end (teal) | `#0F766E` | `#14b8a6` |
| Off / disabled | `#64748B` | — |

Zone palette (white text on the pill, ≥4.5:1): `#1D4ED8 #7C3AED #0E7490
#047857 #B45309 #B91C1C #BE185D #0F766E #7E22CE #4D7C0F #C2410C #4338CA
#0369A1 #15803D #A16207 #BE123C` — the same list in `fleet_map.js` and the
device picker, so a zone keeps its colour everywhere.
- **Contrast floor: 4.5:1 for text (WCAG 2.1 AA).** The theme editor warns
  under 4.5:1 and refuses under 3.0:1 without "apply anyway";
  `tests/test_theme.py` fails if the shipped palette drops a text pair under
  AA.

### Built-in themes

| Theme | What it is |
|---|---|
| **SATOM Aurora** | The shipped look. Carries no overrides: it *is* the stylesheet. |
| **SATOM Classic** | The palette before 1.2.3 (orange accent `#EF5424`, 3.52:1 on white). |
| **SATOM Slate**, **SATOM Graphite** | Alternate light palettes, AA-clean. |

Built-ins cannot be edited or deleted; they are the way back (`theming.md` §5).

---

## 4. Status colours — the badge set

Status is shown with `.fw-badge-*` and nothing else. The set is calibrated
against white (the final block in `fortiweb.css`):

| Class | Text | Tint | Text contrast on white |
|---|---|---|---|
| `.fw-badge-success` | `#15692A` | `rgba(40,167,69,.16)` | 6.8:1 |
| `.fw-badge-warning` | `#7A5700` | `rgba(255,193,7,.20)` | 6.6:1 |
| `.fw-badge-danger` | `#8B1C2A` | `rgba(220,53,69,.16)` | 9.1:1 |
| `.fw-badge-info` | `#0A5F6C` | `rgba(23,162,184,.16)` | 7.3:1 |
| `.fw-badge-secondary` | `#3D4550` | `rgba(108,117,125,.16)` | 9.7:1 |
| `.fw-badge-primary` | `--fw-accent-hover` | 16 % of `--fw-accent` | follows the theme |

- Add `.fw-badge-nowrap` when a two-word verdict sits in a narrow column: a
  pill is drawn around **one** line.
- The WAF pages use one extra hue, purple `#4C2A85` (`waf.css`), for
  informational findings and borrowed settings.
- **Never invent a status colour.** A new state maps to one of the classes
  above.

---

## 5. Components

Reuse before writing CSS:

| Need | Use |
|---|---|
| A panel | `.fw-card` (surface, border, `--fw-radius-lg`, card shadow) |
| Buttons | Bootstrap `.btn` with `.btn-fw-*` / `.btn-fw-secondary`. **Button labels never wrap.** |
| Messages | `.fw-alert-*` |
| Status | `.fw-badge-*` (§4) |
| Navigation in a page | `.fw-breadcrumb`, `.nav-tabs` |
| Code, CLI output | `.fw-code-block` (the one dark surface) |
| Icons | Bootstrap Icons (`bi bi-*`) |

- Typeface: **Inter** (vendored variable font) through `--fw-font`.
- **Appliances show the hostname only** in lists and combos; address, port
  and classification go in the tooltip.
- Every interface string is English and wrapped for translation (`_()`); the
  console is translated with Babel (de/es/fr/it), default English.

---

## 6. Card grids: collapsed by default, dense mosaic

Pages that list one card per appliance or probe (Monitoring probes, Service
Monitor) follow one pattern, implemented in
`app/templates/monitoring/_probe_page.html`:

- **Collapsed by default.** With a hundred appliances, "everything collapsed"
  is the only usable default.
- **The browser stores the OPEN set**, not the closed one
  (`localStorage` key `satom.probecards.open.<page>`). An empty set means all
  collapsed, with no first-run flag. Never reuse an older key with the
  opposite meaning: it would expand exactly the cards the operator closed.
- **Grid:** `repeat(auto-fill, minmax(258px, 1fr))` with
  `grid-auto-flow: row dense`. An **expanded** card spans the row
  (`grid-column: 1 / -1`): a tall item in a narrow column stretches every tile
  beside it.
- **Collapsed is not hidden:** the header keeps the status badge and a summary
  chip (for example `avg Mbps · N pol`) on one line.

---

## 7. Charts

Chart.js 4.4.4, vendored.

- **Grid lines must be visible on white.** A 7 % slate grid is invisible in a
  white modal; use about 8 % (`rgba(31,41,51,.08)`) or a solid `#E3E8F0`.
- Series colours come from tokens or the badge set, never pastels.
- **A failed query is drawn as an ERROR, never as an empty chart.** The same
  holds for a collector that failed: absence of data is not health.

---

## 8. What the Content-Security-Policy does to markup

The console enforces a nonce-based CSP. It shapes how UI is written:

- **No `on*=` handler attributes**, anywhere, including markup built by
  JavaScript. Use `addEventListener` with `data-*` hooks and delegation.
- Every inline `<script>` and `<style>` carries the page nonce.
- `style="…"` attributes are allowed, but a class is preferred.
- Dynamic UI is built with `createElement`, not HTML strings with handlers.
- A web font or stylesheet from another origin is blocked — another reason
  everything is vendored (§2).

Details and the Turbo nonce re-stamp: `engineering.md` §9.

---

## 9. Plugin and app views

Plugin views (Report Studio views and widgets, Plugin Studio app views) render
in a sandboxed iframe that cannot load `fortiweb.css`. The frame therefore
carries the look itself: every `--fw-*` token at its default, then the active
theme's overrides, then `plugin-kit.css` (inlined), then the plugin's own CSS.
A theme change reaches every plugin that uses the tokens or the kit.

- The frame sandbox is `allow-scripts allow-modals allow-forms`;
  `form-action 'none'` keeps a form from leaving the frame. Without
  `allow-forms` the browser blocks the submit before the bridge sees it
  (`tests/test_studio_view.py` pins it).
- **A plugin view is proven in a real browser**, not by the server render: the
  server render cannot exercise the parent/frame bridge.
- What a plugin stylesheet may contain: user guide, Report Studio,
  *Plugin CSS rules*.

---

## 10. Checklist for a UI change

1. Panels are `.fw-card`, statuses are `.fw-badge-*`, colours are `var(--fw-*)`.
2. No dark surface other than code; no pastels; no glassmorphism.
3. Text contrast measured at 4.5:1 or better on the surface it sits on.
4. New page family → its own stylesheet; new third-party asset → vendored and
   listed in `MANIFEST.json`.
5. No `on*=` attributes; inline blocks carry the nonce.
6. English strings, wrapped for translation.
7. Charts: visible grid, error state for a failed query.
8. Card grids: collapsed by default, open set stored, expanded card spans the
   row.
9. A plugin view is checked in a browser.

---

## 11. Where it is enforced

| Test | Holds |
|---|---|
| `tests/test_theme.py` | Token registry matches the stylesheet; shipped palette AA-clean; built-ins state their own gradients; no gradient fed to a colour-only property |
| `tests/test_offline_assets.py` | Every browser asset is vendored and hashed |
| `tests/test_studio_view.py` | Plugin frame sandbox and CSP |

Related: [Theming the console](theming.md) · [Product rules](product-rules.md) ·
[Engineering manual](engineering.md).

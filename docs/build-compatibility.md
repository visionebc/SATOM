# Build compatibility — will this write fit each appliance's exact build?

> **Audience:** operators who apply templates, profiles, baselines and
> carve-outs to a mixed fleet, and engineers who wire a new write path into the
> check. The model behind it is the [API library](api-library.md) §14; the
> operator walkthrough is in the [User guide](user-guide.md) §30.11.
>
> **Since:** SATOM 2.13.0 (unreleased).

A fleet runs many firmware builds, and two builds that speak the **same REST API
version** still differ in fields. A FortiWeb write answers HTTP 200 for a field
the build does not have and silently drops it. Build compatibility is the check
that runs **before** a write and says, per appliance, what will happen:

> Applies, but on 8.0.6 `token-secret` does not exist in
> `waf/web-protection-profile.inline-protection`: it will be skipped on 3
> appliances (`token-secret`: renamed `jwt-token-secret` on 8.0.6, same CLI id)

The key is always the **exact build** (`8.0.6`), never the API version and never
the firmware line.

---

## 1. What is checked

`services/build_compat.py` reads only the API library, both channels of the
target build: the REST evidence (sweeps, schemas, vendor documentation) and the
CLI schema (`cli_tree`, plus the names `show full-configuration` prints,
`cli_full`), joined by `api_library.channels_at`. It also reads the enum options
and `<lo-hi>` ranges of the build's `tree`, the operator's field-rename maps and
the CLI attribute ids.

Every field of the payload gets **one** finding per target build:

| Finding | Meaning | What the write does |
|---|---|---|
| `missing` | the build has the object but not the field, on either channel | **skip** — the field is stripped from that appliance's payload and listed |
| `cli_only` | only the CLI serves it on that build (`hidden` included) | **warn** — the REST write cannot set it; the [CLI writer](cli-writer.md) can |
| `enum_invalid` | the value is not one of the build's options | **block** |
| `range_invalid` | the value is outside the build's range | **block** |
| `endpoint_absent` | the build's measured CLI schema has no such object (or the box rejected the URN) | **block** |
| `endpoint_absent` (vendor) | only the vendor documentation says the object is not there | **warn** — a claim, not a measurement |
| `unknown` | nothing measured this build, this object or this field | **warn** — "cannot be guaranteed", never ok |

**One verdict per field.** A field the build lacks is **skipped** and that is all
the preview says about it: it is never also told "not shown by the FortiWeb GUI
… SATOM still writes it" (a name that already carries a `missing`, `cli_only`,
`enum_invalid`, `range_invalid` or `endpoint_absent` finding is spoken for). The
GUI note stays for fields that are written as authored. With a single target the
sentences carry no "(1 appliance)" tail; with several they say how many share the
sentence.

Two answers are deliberately not findings:

- **REST bookkeeping** (`id`, `_id`, `seq`, `q_*`, `sz_*`, `can_*`, `*_val`,
  `<NO.>`) is channel `meta` and ignored, unless the build's CLI lists that name
  for the object.
- **CLI with REST unmeasured** — the field is in the build's CLI schema and REST
  was never measured there (an empty table, a build with no sweep). On FortiWeb,
  REST mirrors the `tree` on every served object (0 gaps on 7.6.8 and 8.0.6), so
  such a field is listed as *REST not measured*, not as a risk.

Values are checked only when the caller passes them (template apply, carve-out
push and the object editor do). Without values only the names are checked.

### 1.1 Rename hints

A `missing` field carries a hint when SATOM can name its successor:

- an **operator field map** (`/web/registry/field-map`) whose other side exists
  on the target build — authoritative;
- a **CLI attribute id** candidate: the same id under another name, or in another
  object, on the target build. The id in `name(4246)` was measured stable across
  FortiWeb 7.6.8 → 8.0.6 (4,121 of 4,121 fields kept their id; 18 renames found
  this way). Candidates are shown, never applied.

A hint never makes the write carry the value. A payload that still says
`token-secret` is discarded by a build that only knows `jwt-token-secret`; the
fix is to adapt the template (or map the field), not to trust the hint.

---

## 2. Skip versus block

| Level | Effect on that appliance | Effect on the others |
|---|---|---|
| **ok** | written as authored | — |
| **warn** (skip, CLI only, unknown) | written; skipped fields are removed from **its** payload only and reported again in its job result | none |
| **block** | refused | the gate refuses the whole apply (see below) unless overridden |

A skip is per device. Three appliances on 8.0.6 and two on 7.6.8 receive
different payloads from the same template: each one exactly what its build has.
The job result of a device lists what was stripped (`skipped`), so the operator
reads it twice — at preview and after the write — instead of trusting a 200.

A block uses the gate the firmware check already had. A template apply, a
system-profile apply, a baseline rollout and a carve-out push that would block
on any target are **refused as a whole**, with every blocking line named. A user
holding **Approve templates** (`operations.template_approve`) can proceed with a
written reason; the override is audited (`template.compat.override`,
`exception.compat.override`) with the reason and what it overrode.

---

## 3. Where it runs

| Flow | Preview | Real write |
|---|---|---|
| Template apply (`/templates`) | per-device findings, stripped fields in the preview | fields stripped per device; blocks refuse unless overridden. A target build with no evidence at all (`unmeasured`), or a device that reports no firmware, also blocks a template apply (the template's own firmware check), where the payload check here only warns |
| Template approval with auto-deploy | — | a block **holds** the fleet deploy ("HELD by the firmware check"); adapt the template or apply with an override |
| System profile apply (provisioning) | findings and stripped fields | canary-gated write with per-device skips; blocks refuse unless overridden |
| Baseline apply | one report per composing template, skips merged | per-device skips; any block refuses the rollout |
| Carve-out push (WAF exceptions) | the verdict shows the build findings | a block needs an override reason |
| Object editor (*Save*) | the dry run shows the messages | an invalid value or an absent object is refused (HTTP 409); missing fields are stripped and listed; if every changed field is missing the save is refused |

All of them go through `version_compat.build_check` (many objects × many
appliances) or `version_compat.compare_object(..., values=)` (one object, one
build). One computed view per (product, build) is cached and invalidated when
the product's evidence or rename maps change.

---

## 4. The Build compatibility page

**Where:** sidebar **Build compatibility**, `/web/registry/build-compat/`.
**Permission:** `registry.edit` (the API library pages' gate). Read-only.

1. **Pick a product and builds.** Two to eight. The default is the builds the
   fleet runs plus the newest ones the library knows. The page refuses nonsense
   and says why instead of printing an empty matrix:

   - **one build** — "a comparison needs two builds"; that build's own coverage
     (fields by channel) is shown instead of a diff;
   - **a build the library does not know** (`b=9.9.9`) — an explicit error that
     names the builds it knows (HTTP 400). A matrix column of *not measured*
     would read as "no difference";
   - **more than eight** — the fleet's builds are kept first, then the newest,
     and the ones left out are named; nothing is dropped silently.
2. **Read the matrix.** One row per object and field, one column per build. Each
   cell is one of:

   | Cell | Means |
   |---|---|
   | **both** | REST and the CLI serve it |
   | **CLI only** | the CLI schema has it, REST measured the object and it is not there |
   | **hidden** | only `show full-configuration` prints it |
   | **REST only** | REST serves it, the build's `tree` does not list it |
   | **CLI (REST not measured)** | in the CLI schema; REST never measured that object on that build |
   | **meta** | REST bookkeeping, not configuration (hidden unless you tick the meta filter) |
   | **absent** | measured, not there |
   | **unknown** | nothing measured it on that build |

3. **Filter.** *only differences* (default), *only CLI-only / hidden*, or *all
   fields*; search an endpoint or field name. Filtering and pagination are
   server-side (100 rows a page): a FortiWeb build carries 4–5 thousand fields.
4. **Two-build diff.** Pick *Diff from* and *to*: objects and fields added and
   removed, option, type, range and default changes, **rename candidates** (same
   CLI id), **moves** (a CLI id that left one object and reappears in another)
   and channel moves. A candidate an operator already mapped says *mapped*. A
   field that is the successor of a removed one (`max-setting-initial-window-size`
   → `h2-setting-initial-window-size`, CLI id 7128) is listed once, in the
   *Renamed* column, not again as an unrelated addition and removal. The GUI
   block says how many pages were measured on both builds ("147 of 162 pages
   measured"); the others say on which build no layout exists. A build with
   itself, or with a build the library does not know, is refused with a sentence
   (HTTP 400; with `format=json` the body is `{"ok": false, "error":
   "same_build" | "unknown_build" | "missing_build", "message", "known"}`).
5. **Field history.** Every field links to its history: the builds it was seen
   on, by which channel and source.

### 4.1 Fleet views that put different builds side by side

- **Fleet objects** (`/fleet-objects/`) has a **Build** column (version and
  build as each device prints it, `8.0.8 build0140`) and a **Build** filter. The
  filter cuts the rows on the server, like the other filters, and its options are
  the builds your FortiWeb devices run.
- **Config Compare** (`/compare/`) shows the build of the source and of the
  destination on every line and in the export (`src_build`, `dst_build`,
  `build_note`). When the two run different builds, every field difference the
  build diff explains is marked: *not on 7.6.8*, or *renamed: `max-…` on 7.6.8 =
  `h2-…` on 8.0.8*, and an object the other build does not have says *object not
  on 8.0.6*. A row whose every difference is explained carries a *build only*
  badge. The verdict is not softened: a marked difference still counts as
  *differs*; only a measured absence on the other build explains a field.
- **GUI dialogs drawn from a layout of another build** carry the same library
  answer next to each control: *not on 8.0.8 (renamed to `…`)* (the control is
  disabled) or *not measured on 8.0.8*. This includes the HTTP Protocol
  Constraints table, which the dialog draws by hand: a constraint the build
  lacks is drawn disabled with the note, one row of notes per constraint.
- **API Explorer**: a by-parent sub-table whose parent object is measured absent
  on the build is *absent*; the sub-tables the REST sweep never reads stay
  *unknown* and say so (*by-parent sub-tables not swept*), because "unknown" is
  not "served" and no neighbour build fills it.

---

## 5. From the console

```bash
sudo satom execute apilib compat fortiweb 7.6.8 8.0.6        # two builds, both channels
sudo satom execute apilib channels fortiweb 8.0.6            # one build, fields per channel
```

Both are read-only and run `flask apilib compat` / `flask apilib channels` as
the service account; the global `--json` flag prints the full document. See the
[CLI manual](cli.md) §8.

---

## 6. Limits

- **A build nobody measured is never "compatible".** It reads *not measured —
  cannot be guaranteed*. A build that **serves** an object whose fields nobody
  read (a sweep of an empty table) is the same family: the template matrix, the
  template detail, the list badge and Mass Deploy's *Fit* column say **served,
  fields not measured**, never *fits, warnings*. (The apply gate still treats it
  as a warning, not a block: the object is proven to exist there.) Harvest a box on that build (API Explorer → *Harvest
  CLI schema*, or the [Schema builds](user-guide.md#3012-schema-builds--a-build-nobody-harvested) page), or import a
  knowledge pack.
- **A missing field in a configuration dump proves nothing.** `show
  full-configuration` prints only the fields that apply under the row's current
  settings (204 such fields on FortiWeb 7.6.8, 349 on 8.0.6). The check reads the
  build's `tree`, never one box's dump.
- **REST accepts gated fields and drops them.** A dependent field sent while its
  toggle is off answers 200 and is not applied (measured 17 of 17 cases). Send
  the toggle and its dependent fields in **one** request; the readback is the
  only proof. Build compatibility cannot see this: both fields exist on the
  build.
- **A rename is not discovered, it is proposed.** CLI-id candidates held on one
  pair of FortiWeb builds; the field map stays the only authority.
- **Every schema adapter is verified** against a lab box (FortiADC and
  FortiAnalyzer since 2026-10-13); each answer still names the adapter's
  verification (API library §14.10). On FortiADC a field REST spells
  differently from the CLI and no rule joins reads `unknown`, not `cli_only`.

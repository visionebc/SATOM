# CLI writer — writing the fields only the CLI serves

> **Audience:** operators who edit objects from SATOM, and engineers who add a
> write path. The classification it relies on is the [API library](api-library.md)
> §13.3; the object-editor walkthrough is in the [User guide](user-guide.md) §7.3.
>
> **Since:** SATOM 2.13.0 (unreleased).

SATOM writes configuration through REST. On some builds of some products a
setting exists only in the CLI: the API library classifies it `cli_only` (the
CLI schema has it, REST does not serve it) or `hidden` (only `show
full-configuration` prints it), per **exact build**. The CLI writer is the path
for those fields, and **only** those fields.

It is not a general-purpose console and does not widen the read-only one: the
read-only SSH gate (`ssh_ops.assert_readonly`) is unchanged. Writes go through
the one write-capable SSH class, whose deny-list gate checks every line.

---

## 1. When SATOM writes by CLI

Every write is first **split** by `cli_writer.split_payload(appliance, endpoint,
fields)`, which reads `api_library.channels_at` on the appliance's exact build:

| Field's channel on that build | Sent by |
|---|---|
| `cli_only`, `hidden` | the CLI writer |
| `both`, `rest_only` | REST, through the existing clients |
| `unknown` (nobody measured it), a field the build does not have, an endpoint the library does not know on that build, an appliance whose build is unknown | **refused by the CLI writer**, with the reason |

In the object editor a field the CLI writer refuses keeps its REST path, exactly
as before 2.13, and is listed as *Not known on this build (sent by REST as
before)*; [Build compatibility](build-compatibility.md) has already stripped the
fields the build does not have.

**Measured today:** FortiWeb 7.6.8 and 8.0.6 have **no** CLI-only field — every
field the `tree` lists is served by REST on every object REST serves. On those
builds every field still goes by REST, which is the correct answer, not a gap.
FortiAuthenticator 8.0.3 has 29 CLI-only fields (its small setup CLI: `router
static`, `system dns`, `system global`, `system ha`, `system interface`), but
its CLI dialect is not yet verified for writes (§5).

---

## 2. The transaction

One object's change is one CLI transaction:

```
config server-policy server-pool
  edit "lab-pool"
    set comment "a \"quoted\" value"
    config pserver-list
      edit 0
        set ip 192.0.2.10
      next
    end
  next
end
```

- `config` / `edit` / `set` / `unset` / `next` / `end`; sub-table rows in the same
  transaction; `edit 0` creates the next free row id (the prompt names it).
- Values are quoted and escaped the FortiOS-family way (`"` → `\"`, `\` → `\\`).
  A value the CLI cannot take safely is refused before anything is sent: a
  control character (a newline would be a second command, a tab a completion),
  and `?` where the dialect reads it as a help request even inside quotes.
- The writer stops at the **first error** the box prints and discards the
  pending change with `abort` (a row or a singleton; inside a sub-table it first
  leaves the sub-table with `end`). Nothing is committed: on FortiWeb only the
  top-level `next`/`end` commits.
- After every line it resyncs on the prompt. A row that fails validation fails on
  `next` and the CLI has already left the row, so the prompt is the only reliable
  position.

### 2.1 Error patterns

The first match wins; the result and the audit row carry the pattern id, never
the raw line (which can echo a rejected secret).

| Pattern id | The box printed |
|---|---|
| `node_check_object_fail` | `node_check_object fail` |
| `value_parse_error` | `value parse error` |
| `parse_error` | `Parsing error at …`, `command parse error` |
| `entry_not_found` | `entry '…' not found` |
| `out_of_range` | `out of range`, `value check fail` |
| `must_be_set` | `… MUST be set` |
| `return_code` | a **negative** `Return code` / `error code` (0 is success) |
| `unknown_action` | `Unknown action` |
| `permission_denied` | `permission denied` |
| `in_use` | `The object is in use` |
| `invalid_value` | `Invalid …`, `… is invalid` |
| `command_fail` | `Command fail` |

The SSH console's own error markers count as errors too.

### 2.2 Readback

Every apply is read back in a **new** SSH session with `show
full-configuration <path>` and parsed field by field. Every written field must
read back equal, or the write is failed with the diff. When the object also has a
REST path that serves, REST is read back too.

A new session is not a precaution of style: on the lab box, `show
full-configuration` in the same session right after a write twice printed the
block with no `set` lines at all. A block with no lines is treated as unreadable
and retried, never as "every field is empty".

After a failed write the same readback proves that **nothing was applied** — or
says that the object changed.

### 2.3 Locking and audit

The CLI write runs inside the device-job framework and takes the **same
per-device lock** as a REST write, so a CLI write and a REST write of the same
box never interleave. Every apply writes one audit row, `config.cli_write`, with
the object path, the field names and the outcome (and the error pattern or the
fields whose readback differed) — never a value.

---

## 3. In the object editor

The editor's **Save** stays a dry run by default and needs the same permission as
before (`config_write`).

1. **Preview.** For the fields this build serves only by CLI the preview shows
   the **CLI script** that will run, beside the usual REST request for the rest.
   Secret fields are masked in the script.
2. **Apply.** REST is sent first; the CLI part runs only if REST succeeded (*the
   REST part failed, so the CLI part was not sent*).
3. **Result.** The editor keeps the **Readback (CLI)** and **Readback (REST)**
   tables on screen instead of reloading. A refusal reads *CLI refused: …*, says
   whether the pending change was discarded with `abort`, and whether the
   readback confirms nothing was applied.

A dialect not verified on a box is labelled *dialect not lab-verified* above the
script.

---

## 4. Lab verification (FortiWeb 8.0.6)

Verified end to end on a FortiWeb-KVM 8.0.6 build0116 lab VM, every object
prefixed `lab-` and deleted afterwards, 12 scenarios, 0 unexpected:

| Scenario | Outcome |
|---|---|
| create a server pool with a `pserver-list` row (spaces, enums, `edit 0`) | applied, CLI and REST readback equal |
| create an IP list with a member row | applied |
| invalid enum value mid-script (a valid `set` before it) | refused, aborted, readback: nothing applied |
| invalid row failing on `next` after a valid parent `set` | refused, aborted, nothing applied |
| out-of-range integer on a singleton (valid `set` before it) | refused, aborted, nothing applied |
| singleton change and revert (`system global`) | applied, then restored |
| escaping: quote, apostrophe, backslash, question mark | read back byte-equal |
| `unset` of a field | applied |
| delete a sub-table row, then both objects | gone on CLI and REST |

`show full-configuration` of every touched path was identical before and after
the run.

Measured behaviour of `abort` on that build: inside an `edit` it discards the row
and leaves the table (a nested row returns to its parent row, a top-level row to
the root); inside a singleton `config` it discards and returns to the root; at a
table level with no open row it is a parse error, so the writer closes the table
with `end` first.

---

## 5. Dialects

| Product | `abort` | `?` inside a value | Verified |
|---|---|---|---|
| FortiWeb | yes | allowed (quoted) | **yes** — FortiWeb-KVM 8.0.6 build0116 |
| FortiGate | documented | refused | **no** |
| FortiAuthenticator | documented | refused | **no** |
| FortiADC | documented | refused | **no** |

A product not listed (FortiAnalyzer) has no CLI writer. An unverified dialect is
written to the FortiOS-family documentation and shown as unverified in the
editor; verify it on a lab box before relying on it.

---

## 6. Troubleshooting

| Message | Cause / fix |
|---|---|
| `the running build of this appliance is unknown; run a firmware check first` | SATOM cannot name the build, so it cannot classify a field. Run a firmware check |
| `… is not known on <product> <build> (no evidence for this endpoint on this build)` | The library never measured that object on that build. Harvest the box's schema (API library §13.4) |
| `no source measured this field on … (channel unknown)` | One channel never answered for the field on that build. Harvest, or import a knowledge pack |
| `the library does not name the CLI path of …` | The endpoint has no CLI-tree evidence. Harvest the CLI schema |
| `… is nested in the table …: name its row` | A nested object needs its parent row's key |
| `a value holds a control character …` / `a value holds '?' …` | The value cannot be typed into the CLI safely; it is refused before sending |
| *CLI refused: … — the pending change was discarded with abort; readback confirms nothing was applied* | The box rejected a line; read the pattern (§2.1), fix the value, save again |
| *readback differs for …* | The box accepted the lines but reads back something else (a gated field, a normalised value). The diff names the field; nothing is retried automatically |

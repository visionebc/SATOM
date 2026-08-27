"""One-shot: fold per-department segment rows into one row per NETWORK.

Dry-run unless ``--apply`` is passed. Prints exactly what it would do.

**It refuses to merge rows that disagree.** Two rows sharing a name but not a
CIDR (or with different non-blank gateways/interfaces) are not one network
described twice -- they are two networks with a name collision, and picking a
survivor here would be this script deciding which one production keeps. Those
are REPORTED and left alone; ``save_segments`` will then refuse the next save
of that page until an operator gives them distinct names, which is the correct
place for that decision.
"""
import sys

sys.path.insert(0, "/opt/satom")
from app import create_app                      # noqa: E402
from app.services import settings_store as store  # noqa: E402

APPLY = "--apply" in sys.argv
MERGEABLE = ("cidr", "zone", "line")   # must not disagree
FILLABLE = ("interface", "gateway", "note")


def main():
    app = create_app()
    with app.app_context():
        raw = store.get_json(store.K_SEGMENTS, [])
        print(f"rows in the blob: {len(raw)}")
        groups: dict[str, list[dict]] = {}
        order: list[str] = []
        unnamed: list[dict] = []
        for row in raw:
            if not isinstance(row, dict):
                print("  ! skipping a non-dict row")
                continue
            name = str(row.get("name") or "").strip()
            if not name:
                unnamed.append(row)
                continue
            if name not in groups:
                groups[name] = []
                order.append(name)
            groups[name].append(row)

        out: list[dict] = []
        conflicts: list[str] = []
        merged = 0
        for name in order:
            rows = groups[name]
            base = {f: str(rows[0].get(f, "") or "").strip()
                    for f in store.SEGMENT_STR_FIELDS}
            depts = store.normalize_departments(
                rows[0].get("departments", rows[0].get("department")))
            bad = False
            for extra in rows[1:]:
                disagree = [f for f in MERGEABLE
                            if str(extra.get(f, "") or "").strip() != base[f]]
                clash = [f for f in FILLABLE
                         if str(extra.get(f, "") or "").strip()
                         and base[f]
                         and str(extra.get(f, "") or "").strip() != base[f]]
                if disagree or clash:
                    conflicts.append(
                        f"{name!r}: rows disagree on "
                        f"{', '.join(disagree + clash)} — NOT merged")
                    bad = True
                    break
                for f in FILLABLE:
                    val = str(extra.get(f, "") or "").strip()
                    if val and not base[f]:
                        base[f] = val
                        print(f"  {name!r}: filled blank {f} from the twin -> {val!r}")
                for d in store.normalize_departments(
                        extra.get("departments", extra.get("department"))):
                    if d not in depts:
                        depts.append(d)
                merged += 1
            if bad:
                # keep BOTH rows exactly as they were; nothing is decided here
                for r in rows:
                    keep = {f: str(r.get(f, "") or "").strip()
                            for f in store.SEGMENT_STR_FIELDS}
                    keep["departments"] = store.normalize_departments(
                        r.get("departments", r.get("department")))
                    out.append(keep)
                continue
            base["departments"] = depts
            out.append(base)
            if len(rows) > 1:
                print(f"  MERGED {len(rows)} rows -> {name!r} "
                      f"departments={depts} cidr={base['cidr']!r}")
        for row in unnamed:
            keep = {f: str(row.get(f, "") or "").strip()
                    for f in store.SEGMENT_STR_FIELDS}
            keep["departments"] = store.normalize_departments(
                row.get("departments", row.get("department")))
            out.append(keep)

        print(f"\nrows after: {len(out)}  (merged away: {merged})")
        for r in out:
            print(f"  {r['name']!r:<24} line={r['line']!r:<6} "
                  f"cidr={r['cidr']!r:<18} departments={r['departments']}")
        if conflicts:
            print("\nNOT MERGED (an operator must decide):")
            for c in conflicts:
                print("  !", c)

        if not APPLY:
            print("\nDRY RUN — nothing written. Re-run with --apply.")
            return
        if conflicts:
            print("\nREFUSING to write: unresolved name collisions above.")
            sys.exit(1)
        store.save_segments(out)
        print("\nWRITTEN. Re-read:")
        for r in store.segments():
            print(f"  {r['name']!r:<24} departments={r['departments']}")


main()

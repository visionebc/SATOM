#!/usr/bin/env python3
"""Partition the SATOM test suite into N balanced shards, by FILE.

Two weighting modes:

  * ``ast`` (default, bootstrap) — parses every ``tests/test_*.py`` with
    :mod:`ast` (never imports it, so no side effects and no ``.pyc`` for test
    modules) and weighs each file by its expanded test count: one point per
    ``def test_*`` (module level and inside ``Test*`` classes), multiplied by
    the cardinality of every literal ``@pytest.mark.parametrize`` argvalues
    list stacked on it.

  * ``time`` — reads ``--durations=0`` lines out of previous shard logs and
    weighs each file by MEASURED seconds. This is strictly better and should
    be used as soon as one sharded run exists: the AST proxy counts tests, not
    seconds, so it is blind to sleeps, retry/backoff loops and fsync-heavy
    churn. Files with no measurement fall back to the AST proxy scaled by the
    observed median seconds-per-case, so a newly added file is never silently
    weighed as zero.

Splitting is by file and never within a file, so any intra-file ordering
dependency survives untouched.

The partition is self-checked before anything is written: the union of the
manifests must equal exactly the set of test files on disk, with no file
appearing twice. A partition that quietly drops a file would produce a green
run that never executed those tests — the failure mode this whole tool exists
to avoid.
"""
from __future__ import annotations

import argparse
import ast
import os
import re
import statistics
import sys
from pathlib import Path

REPO_DIR = Path(__file__).resolve().parent.parent

# "0.12s call     tests/test_foo.py::test_bar[param]"
_DURATION_RE = re.compile(
    r"^(?P<secs>\d+\.\d+)s\s+(?:call|setup|teardown)\s+(?P<nodeid>\S+)"
)


def _param_factor(dec: ast.expr) -> int:
    """Return the multiplier a parametrize decorator contributes, or 1."""
    fn = dec.func if isinstance(dec, ast.Call) else dec
    name = ""
    if isinstance(fn, ast.Attribute):
        name = fn.attr
    elif isinstance(fn, ast.Name):
        name = fn.id
    if name != "parametrize":
        return 1
    if not isinstance(dec, ast.Call) or len(dec.args) < 2:
        return 3  # non-literal argvalues: a guess, deliberately not 1
    argvalues = dec.args[1]
    if isinstance(argvalues, (ast.List, ast.Tuple, ast.Set)):
        return len(argvalues.elts) or 1
    return 3


def _walk(body, counts: list[int]) -> None:
    for node in body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if not node.name.startswith("test_"):
                continue
            mult = 1
            for dec in node.decorator_list:
                mult *= _param_factor(dec)
            counts[0] += 1
            counts[1] += mult
        elif isinstance(node, ast.ClassDef) and node.name.startswith("Test"):
            _walk(node.body, counts)


def ast_weights(tests_dir: Path) -> dict[str, int]:
    """{filename: expanded test count}. Never returns 0 for a real file."""
    weights: dict[str, int] = {}
    for path in sorted(tests_dir.glob("test_*.py")):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except SyntaxError as exc:  # keep going, but say so
            sys.stderr.write(f"PARSEFAIL {path.name}: {exc}\n")
            weights[path.name] = 1
            continue
        counts = [0, 0]
        _walk(tree.body, counts)
        raw, cases = counts
        weights[path.name] = cases or raw or 1
    return weights


def measured_weights(
    log_paths: list[Path], proxy: dict[str, int]
) -> tuple[dict[str, float], int]:
    """{filename: measured seconds}, falling back to the scaled AST proxy.

    Returns the weights and how many files actually had a measurement.
    """
    seconds: dict[str, float] = {}
    for log in log_paths:
        for line in log.read_text(encoding="utf-8", errors="replace").splitlines():
            m = _DURATION_RE.match(line.strip())
            if not m:
                continue
            fname = os.path.basename(m.group("nodeid").split("::", 1)[0])
            if fname in proxy:
                seconds[fname] = seconds.get(fname, 0.0) + float(m.group("secs"))

    if not seconds:
        raise SystemExit(
            "FATAL: no '--durations=0' lines found in the given logs. Was the "
            "run launched without --durations=0?"
        )

    # Seconds-per-case of the files we DID measure, used to price the ones we
    # did not. The median, not the mean: one pathological file must not drag
    # every unmeasured file with it.
    rates = [seconds[f] / proxy[f] for f in seconds if proxy.get(f)]
    rate = statistics.median(rates) if rates else 1.0

    weights = {f: seconds.get(f, proxy[f] * rate) for f in proxy}
    return weights, len(seconds)


def partition(weights: dict[str, float], shards: int) -> list[list[str]]:
    """Greedy longest-processing-time-first. Heaviest file placed first."""
    bins: list[list[str]] = [[] for _ in range(shards)]
    loads = [0.0] * shards
    for fname, w in sorted(weights.items(), key=lambda kv: (-kv[1], kv[0])):
        i = loads.index(min(loads))
        bins[i].append(fname)
        loads[i] += w
    return bins


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("-n", "--shards", type=int, default=3)
    ap.add_argument(
        "--tests-dir", type=Path, default=REPO_DIR / "tests",
        help="default: <repo>/tests",
    )
    ap.add_argument(
        "-o", "--out", type=Path, default=None,
        help="manifest directory (default: /var/tmp/satom-shards/n<N>)",
    )
    ap.add_argument(
        "--durations", type=Path, nargs="+", default=None, metavar="LOG",
        help="previous shard logs; weigh by MEASURED seconds instead of the "
             "AST proxy",
    )
    args = ap.parse_args()

    if args.shards < 1:
        ap.error("shard count must be >= 1")
    tests_dir: Path = args.tests_dir
    if not tests_dir.is_dir():
        ap.error(f"no such tests dir: {tests_dir}")

    proxy = ast_weights(tests_dir)
    if not proxy:
        ap.error(f"no test_*.py files under {tests_dir}")

    if args.durations:
        weights, n_measured = measured_weights(args.durations, proxy)
        mode = f"measured seconds ({n_measured}/{len(proxy)} files measured)"
        unit = "s"
    else:
        weights = {k: float(v) for k, v in proxy.items()}
        mode = "AST proxy (expanded test count)"
        unit = " cases"

    bins = partition(weights, args.shards)

    # --- self-check: the partition must be a partition ----------------------
    placed = [f for b in bins for f in b]
    if len(placed) != len(set(placed)):
        dupes = sorted({f for f in placed if placed.count(f) > 1})
        sys.stderr.write(f"FATAL: file placed in more than one shard: {dupes}\n")
        return 2
    if set(placed) != set(proxy):
        missing = sorted(set(proxy) - set(placed))
        extra = sorted(set(placed) - set(proxy))
        sys.stderr.write(f"FATAL: partition is not a partition. "
                         f"missing={missing} extra={extra}\n")
        return 2

    out_dir: Path = args.out or Path("/var/tmp/satom-shards") / f"n{args.shards}"
    out_dir.mkdir(parents=True, exist_ok=True)
    for i, files in enumerate(bins, start=1):
        (out_dir / f"shard{i}.txt").write_text(
            "".join(f"tests/{f}\n" for f in sorted(files)), encoding="utf-8"
        )

    ideal = sum(weights.values()) / args.shards
    print(f"tests dir : {tests_dir}")
    print(f"weighting : {mode}")
    print(f"manifests : {out_dir}")
    print(f"files     : {len(proxy)}   shards: {args.shards}")
    print("-" * 58)
    for i, files in enumerate(bins, start=1):
        load = sum(weights[f] for f in files)
        dev = (load - ideal) / ideal * 100 if ideal else 0.0
        print(f" shard{i}  {len(files):4d} files  {load:10.1f}{unit}  "
              f"{dev:+6.2f}% from ideal")
    print("-" * 58)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

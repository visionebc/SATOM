"""The hook queue's four directories must live under ONE parent.

This guard exists because the correct sandbox broke the queue, silently.

`satom-integrations.service` hardens the runner with `ProtectSystem=strict` plus
`ReadWritePaths=`. systemd implements each `ReadWritePaths=` as its **own
bind-mount**. The runner claims a request with `os.replace()` from the queue
directory into the claim directory - and `rename(2)` across two bind-mounts is
**EXDEV**, errno 18. Proven on a1 with the real unit properties, not inferred.

`process_request_file` catches `OSError` there and returns `None`, because the
expected cause is another runner having claimed the file first. It cannot tell
that apart from EXDEV. So:

* the request was never executed,
* no error was written anywhere,
* the status stayed `queued` forever,
* and because `DirectoryNotEmpty=` is level-triggered, the `.path` unit re-fired
  the service until systemd hit the start limit and gave up.

Every symptom pointed at the runner. The cause was one line of unit file.

Two guards, because either half alone would let it back:
  1. the four directories share a parent (so one mount covers them all);
  2. the unit declares exactly one `ReadWritePaths` and it is that parent.
"""
from __future__ import annotations

import os
import re

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SERVICE = os.path.join(REPO, "deploy", "satom-integrations.service")
PATH_UNIT = os.path.join(REPO, "deploy", "satom-integrations.path")


def _unit(path: str) -> str:
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def _directives(src: str, key: str) -> list[str]:
    """Directive values only - a line that merely mentions the key in a comment
    is prose, and this guard is about what systemd will actually do."""
    out = []
    for line in src.splitlines():
        line = line.strip()
        if line.startswith("#") or "=" not in line:
            continue
        name, _, value = line.partition("=")
        if name.strip() == key:
            out.append(value.strip())
    return out


def test_the_four_queue_directories_share_one_parent():
    from app.services import hook_runner as HR
    from app.services import integration_hooks as IH

    parents = {
        IH.HOOKS_DIR.parent,
        IH.REQ_DIR.parent,
        IH.STATUS_DIR.parent,
        HR.CLAIM_DIR.parent,
    }
    assert len(parents) == 1, (
        f"queue directories are spread across {parents} - a rename between two "
        f"of them is EXDEV under the unit's bind-mounts")


def test_the_unit_grants_exactly_one_writable_tree():
    values = [v.lstrip("-") for v in _directives(_unit(SERVICE), "ReadWritePaths")]
    assert len(values) == 1, (
        f"{len(values)} ReadWritePaths = {len(values)} bind-mounts; the runner's "
        f"claim rename would fail with EXDEV: {values}")


def test_that_one_tree_is_the_queue_parent():
    from app.services import integration_hooks as IH

    value = _directives(_unit(SERVICE), "ReadWritePaths")[0].lstrip("-")
    assert value.rstrip("/") == str(IH.REQ_DIR.parent).rstrip("/"), (
        f"unit grants {value!r} but the queue lives under {IH.REQ_DIR.parent}")


def test_the_writable_tree_is_not_all_of_data():
    """The hook is a child of the runner and inherits its namespace. Granting
    /opt/satom/data would hand every operator-written script `data/sot/` and
    `data/jobs/` - the whole reason the grant is narrow."""
    value = _directives(_unit(SERVICE), "ReadWritePaths")[0].lstrip("-").rstrip("/")
    assert value != "/opt/satom/data"
    assert value.startswith("/opt/satom/data/")


def test_the_path_unit_watches_the_queue_directory():
    from app.services import integration_hooks as IH

    watched = _directives(_unit(PATH_UNIT), "DirectoryNotEmpty")
    assert watched, "the .path unit watches nothing"
    assert watched[0].rstrip("/") == str(IH.REQ_DIR).rstrip("/"), (
        f".path watches {watched[0]!r} but dispatch writes to {IH.REQ_DIR}")


def test_the_claim_directory_is_not_inside_the_watched_one():
    """DirectoryNotEmpty= is level-triggered: a claim file inside the watched
    directory would keep the unit re-firing for as long as a hook runs."""
    from app.services import hook_runner as HR
    from app.services import integration_hooks as IH

    assert IH.REQ_DIR not in HR.CLAIM_DIR.parents
    assert HR.CLAIM_DIR != IH.REQ_DIR


def test_the_unit_explains_the_exdev_trap():
    """A future reader splitting this back into four tidy grants would
    reintroduce a silent, total queue failure. The reason has to travel with
    the directive."""
    src = _unit(SERVICE)
    assert re.search(r"EXDEV", src), "the unit does not record why there is one grant"

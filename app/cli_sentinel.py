"""CLI entry point for the response runner.

A module rather than a console script so the systemd unit runs exactly what the
tests import — a second code path that only production takes is a second code
path that only production can break.
"""
from __future__ import annotations

import json
import sys


def main(argv: list) -> int:
    from wsgi import app                                   # loads .env
    cmd = (argv[1] if len(argv) > 1 else "").replace("_", "-")
    with app.app_context():
        if cmd == "responder-tick":
            from app.services.sentinel import responder
            out = responder.tick()
            print(json.dumps(out, default=str))
            return 0
        if cmd == "responder-status":
            from app.services.sentinel import actions, config
            v, t = actions.verified_count()
            print(json.dumps({"armed": bool(config.get("response_enabled")),
                              "verified_actions": f"{v}/{t}"}))
            return 0
    print("usage: python -m app.cli_sentinel {responder-tick|responder-status}",
          file=sys.stderr)
    return 2


if __name__ == "__main__":                                 # pragma: no cover
    raise SystemExit(main(sys.argv))

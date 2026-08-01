"""SATOM operator CLI.

A single entry point for diagnosing, controlling and rebuilding a SATOM node
from the console — including when the web UI is down, which is the case it
exists for.

Design constraints (all enforced by tests/test_cli.py):

* STDLIB ONLY at module level. A CLI that needs a working venv to tell you the
  venv is broken is useless.
* The command tree is DATA (tree.py). Adding a command is one entry.
* Read-only verbs work at ANY privilege level; state-changing verbs require
  root and refuse with an explanation, never a traceback.
* Installed as a root-owned COPY outside the app tree. It must never execute
  code from a directory the service account can write.
"""
__version__ = "1.0"

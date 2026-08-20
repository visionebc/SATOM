"""SATOM Sentinel — security correlation and (eventually) autonomous response.

Two paths, and the separation is the architecture
--------------------------------------------------
**Hot path (deterministic, sub-second, always runs).** collect → normalize →
enrich → correlate → score → incident → policy. Every step is ordinary Python
with a fixed contract. It never calls a language model, never calls a third
party, and never waits on one. If every AI component in this installation is
down, the hot path still detects, still scores, still explains itself with
measured evidence, and still gates actions.

**Cold path (AI, asynchronous, always optional).** A model reads an incident
that already exists and returns a NARRATIVE plus an opinion drawn from a closed
enum. It has no tools, no network, no credentials and no way to change a score.
Its output lands in one field, stamped with the model name and a prompt hash.

Why not put the model in the middle, where it would obviously "help": because
the thing it would be helping with is the decision to change a production
firewall. A non-deterministic component in that position cannot be reproduced
during a post-mortem, cannot be unit-tested, and fails open in exactly the
situation (a flood, a saturated node) where the hot path must still work.

Module map
----------
``normalize``  device/syslog record  → :class:`SentinelEvent` (raw)
``enrich``     event → geo/ASN/trust/window/vuln context (derived)
``vuln``       the LOCAL CVE mirror + its sync job (never called per-incident)
``baseline``   median/MAD per series per hour-of-week, computed from the TSDB
``correlate``  a trigger → a multi-layer :class:`WindowContext`
``scoring``    context → integer score + per-factor breakdown (deterministic)
``incident``   open / absorb / evidence / timeline / close
``ai``         incident → model opinion (pure function, schema-validated)
``actions``    the closed action catalog + the policy engine
``pipeline``   the sweep that ties the hot path together
"""
from __future__ import annotations

__all__ = ["normalize", "enrich", "vuln", "baseline", "correlate", "scoring",
           "incident", "ai", "actions", "pipeline", "config"]

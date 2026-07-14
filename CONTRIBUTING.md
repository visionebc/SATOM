# Contributing to OFortMAuT

Thanks for your interest! OFortMAuT is source-available under the
[Elastic License 2.0](LICENSE). You are welcome to **use it, modify it, and
adapt it to your own organisation's needs**, including in production. You may
not offer it to third parties as a hosted or managed service — for that,
contact **licensing@visionebc.com**.

## Important: this GitHub repo is a sanitized, read-only mirror
Development happens on a private internal Git server. What you see on GitHub
is produced by an automated **sanitize -> secret-scan -> AI-audit -> publish**
pipeline (see [`docs/release-pipeline.md`](docs/release-pipeline.md)).

Consequences:
- The public `main` branch is **force-updated** on each release. Do not base
  long-lived work on its exact commit SHAs.
- **Pull requests opened here are not merged directly.** We read them, and
  valuable changes are re-applied upstream and flow back out through the
  pipeline (with attribution in the changelog).
- **Issues are very welcome** — bug reports, questions, and feature ideas.
  Issues are not part of git history, so the mirror refresh never wipes them.

## Filing an issue
Use the templates under `.github/ISSUE_TEMPLATE`:
- **Bug report** — version/commit, environment, steps, expected vs actual.
- **Feature request** — the problem you are trying to solve.
- **Security** — do NOT use public issues; see [`SECURITY.md`](SECURITY.md).

## Your responsibility
This software is provided **AS IS, without warranty** (Elastic License 2.0,
*No Liability*). You are responsible for how you deploy and operate it,
including credentials, network exposure, and the appliances it touches. By
contributing you agree your contributions are licensed under the Elastic
License 2.0 and that Vision EBC may license the project, including your
contribution, under other terms.

## Coding notes
- Python 3.11+, Flask app under `app/`, tests under `tests/` (run `pytest`).
- Keep changes minimal and focused; match the surrounding style.
- Never commit secrets, `.env`, or real device data. The pipeline will
  reject a publish that contains them, but do not rely on it.

"""Starter sources for the hook editor.

Why starters and not adapters
-----------------------------
Microsoft Teams wants an Adaptive Card inside an ``attachments`` wrapper,
Telegram wants form-ish JSON on a URL with the bot token *in the path*, Discord
wants ``content``, Opsgenie wants its own alert schema.  Shipping and
maintaining one adapter per vendor is unbounded work whose failure mode is a
silently stale integration after the vendor changes a field.

A starter is the opposite trade: the product ships a *correct, working* example
that the operator owns from the moment they save it.  When Teams changes its
card schema, the operator edits twelve lines of their own Python instead of
waiting for a SATOM release.

Each starter therefore encodes the thing that is *easy to get wrong* and hard
to discover — the Teams attachment envelope, Telegram's parse-mode trap, the
fact that a non-2xx must be reported and not swallowed — because that is the
part an operator cannot reconstruct from the vendor docs in five minutes.

The generic HTTP case is NOT here
---------------------------------
A plain signed POST is a first-class sink (:mod:`app.services.alert_webhook`),
configured on the alert settings page with no Python at all.  A starter that
re-implemented it would be a second, unsigned, un-retried copy of a thing the
product already does properly — and the operator would have no way to tell
which one they were looking at.
"""
from __future__ import annotations

CHANGE_TICKET = '''"""Open a change ticket in our CRM when SATOM requests a change.

Bound to the `change.requested` event. Declare CRM_TOKEN in the secrets field
above and it arrives through ctx.secret() - never write it in this file.
"""


def run(ctx):
    payload = ctx.payload
    resp = ctx.http.post(
        "https://crm.example.com/api/changes",
        json={
            "title": payload["title"],
            "description": payload.get("reason", ""),
            "risk": payload.get("risk", "medium"),
            "starts_at": payload.get("window_start"),
            "ends_at": payload.get("window_end"),
            "assets": payload.get("device_ids", []),
            "external_id": "SATOM-CR-%s" % payload["cr_id"],
        },
        headers={"Authorization": "Bearer " + ctx.secret("CRM_TOKEN")},
    )
    if resp.status_code >= 300:
        # Return the failure rather than raising: the operator needs the CRM's
        # own words, and an exception would only report ours.
        return ctx.result(False, {"detail": "CRM said %s" % resp.status_code})

    ticket = resp.json()
    ctx.log("opened %s" % ticket.get("id"))
    # Keys SATOM understands: crq_ref / crq_url are written back onto the
    # change request, so the ticket is one click away from the CR page.
    return ctx.result(True, {"crq_ref": ticket["id"], "crq_url": ticket.get("url", "")})
'''

TELEGRAM = '''"""Send an alert to a Telegram chat.

Bound to the `alert.fired` event, which fires once per finding that passed the
"Integration hooks" sink filter on the alert settings page. Filter there, not
here: a rule written on that page is visible to whoever is on call.

Declare TELEGRAM_BOT_TOKEN in the secrets field above (talk to @BotFather).
CHAT_ID is not a credential - it is the destination - so it lives here where
you can see which chat this hook talks to.
"""

CHAT_ID = "-1001234567890"

ICON = {"critical": "\\U0001F534", "warning": "\\U0001F7E0", "info": "\\U0001F535"}


def run(ctx):
    a = ctx.payload
    text = "%s SATOM %s - %s\\n%s\\n\\nkey: %s" % (
        ICON.get(a.get("severity"), "\\U0001F535"),
        a.get("node", "?"), a.get("title", ""),
        a.get("detail", ""), a.get("key", ""))

    resp = ctx.http.post(
        "https://api.telegram.org/bot%s/sendMessage" % ctx.secret("TELEGRAM_BOT_TOKEN"),
        # NO parse_mode on purpose. Alert detail carries device names, file
        # paths and version strings full of _ * [ ` - with parse_mode set,
        # Telegram answers 400 "can't parse entities" and the alert is simply
        # gone. Plain text always arrives, and arriving is the whole job.
        json={"chat_id": CHAT_ID, "text": text[:4096],
              "disable_web_page_preview": True},
    )
    if resp.status_code >= 300:
        return ctx.result(False, {"detail": "telegram %s: %s" % (
            resp.status_code, resp.text[:200])})
    return ctx.result(True, {"chat_id": CHAT_ID})
'''

SLACK = '''"""Post an alert to a Slack channel.

Bound to the `alert.fired` event. Declare SLACK_WEBHOOK_URL in the secrets
field above: for Slack incoming webhooks the URL IS the credential - anyone
holding it can post as your app - so it belongs in the vault and never in
this source, which is versioned and readable in the editor.

If all you want is Slack's plain {"text": ...} shape, you do not need a hook
at all: the Webhook sink on the alert settings page emits exactly that, signed
and retried, with no Python to maintain. Use this starter when you want Block
Kit, threading, or per-severity channel routing - things a form cannot express.
"""

COLOR = {"critical": "#8B1C2A", "warning": "#7A5700", "info": "#3D4550"}


def run(ctx):
    a = ctx.payload
    resp = ctx.http.post(
        ctx.secret("SLACK_WEBHOOK_URL"),
        json={
            "text": "SATOM %s: %s" % (a.get("severity", "info"), a.get("title", "")),
            "attachments": [{
                "color": COLOR.get(a.get("severity"), "#3D4550"),
                "fields": [
                    {"title": "Node", "value": a.get("node", "?"), "short": True},
                    {"title": "Family", "value": a.get("family", "?"), "short": True},
                    {"title": "Detail", "value": a.get("detail", "")[:1500],
                     "short": False},
                    {"title": "Key", "value": a.get("key", ""), "short": False},
                ],
            }],
        },
    )
    # Slack answers 200 with the body "ok"; anything else is a body worth
    # reading. A 200 with "invalid_payload" is still a delivery that did not
    # happen, so check the text and not only the status.
    if resp.status_code >= 300 or resp.text.strip() != "ok":
        return ctx.result(False, {"detail": "slack %s: %s" % (
            resp.status_code, resp.text[:200])})
    return ctx.result(True, {})
'''

TEAMS = '''"""Post an alert to a Microsoft Teams channel.

Bound to the `alert.fired` event. Declare TEAMS_WEBHOOK_URL in the secrets
field above - the Workflows URL is a bearer credential.

Teams does NOT accept a bare {"text": ...} and it does NOT accept a bare
Adaptive Card either. The Workflows connector ("Post to a channel when a
webhook request is received") wants the card wrapped in the message/attachments
envelope below, with that exact contentType. Sending the card alone returns 202
- accepted, and nothing is ever posted - which is the worst possible answer,
because every status check says it worked.

The retired Office 365 connector took a MessageCard instead. If you inherited
one of those URLs, it is on borrowed time; migrate to Workflows.
"""

COLOR = {"critical": "attention", "warning": "warning", "info": "accent"}


def run(ctx):
    a = ctx.payload
    card = {
        "type": "AdaptiveCard",
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "version": "1.4",
        "body": [
            {"type": "TextBlock", "size": "Medium", "weight": "Bolder",
             "color": COLOR.get(a.get("severity"), "default"), "wrap": True,
             "text": "SATOM %s - %s" % (a.get("node", "?"), a.get("title", ""))},
            {"type": "TextBlock", "wrap": True, "text": a.get("detail", "")},
            {"type": "FactSet", "facts": [
                {"title": "Severity", "value": a.get("severity", "info")},
                {"title": "Family", "value": a.get("family", "?")},
                {"title": "Key", "value": a.get("key", "")},
                {"title": "Fired at", "value": a.get("fired_at", "")},
            ]},
        ],
    }
    resp = ctx.http.post(
        ctx.secret("TEAMS_WEBHOOK_URL"),
        json={"type": "message", "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive",
            "contentUrl": None,
            "content": card,
        }]},
    )
    if resp.status_code >= 300:
        return ctx.result(False, {"detail": "teams %s: %s" % (
            resp.status_code, resp.text[:200])})
    return ctx.result(True, {})
'''

#: slug -> starter.  ``event`` preselects the editor's binding, ``secrets`` is
#: what the author must declare before the first run: a starter that silently
#: needs an undeclared secret fails at 03:00 with ``ctx.secret()`` raising.
STARTERS: dict[str, dict] = {
    "change-ticket": {
        "label": "CRM change ticket",
        "description": "Open a ticket when a change request is raised.",
        "event": "change.requested",
        "secrets": ["CRM_TOKEN"],
        "source": CHANGE_TICKET,
    },
    "telegram": {
        "label": "Telegram",
        "description": "Send each alert to a Telegram chat via a bot.",
        "event": "alert.fired",
        "secrets": ["TELEGRAM_BOT_TOKEN"],
        "source": TELEGRAM,
    },
    "slack": {
        "label": "Slack",
        "description": "Post each alert to a Slack channel with an attachment.",
        "event": "alert.fired",
        "secrets": ["SLACK_WEBHOOK_URL"],
        "source": SLACK,
    },
    "teams": {
        "label": "Microsoft Teams",
        "description": "Post each alert as an Adaptive Card via a Workflows "
                       "webhook.",
        "event": "alert.fired",
        "secrets": ["TEAMS_WEBHOOK_URL"],
        "source": TEAMS,
    },
}

#: The editor's default when no starter is chosen.  Aliased, never copied: two
#: authors of one string is how the published site lost its Docs link.
DEFAULT_STARTER = "change-ticket"


def get(slug: str) -> dict:
    """The named starter, falling back to the default.

    An unknown slug must not yield a blank editor: a query-string typo would
    then look exactly like "this product has no examples"."""
    return STARTERS.get((slug or "").strip(), STARTERS[DEFAULT_STARTER])


def catalog() -> list[dict]:
    """Render-ready list for the editor's starter picker, source excluded —
    four full hook bodies in a page that only needs four labels."""
    return [{"slug": s, "label": v["label"], "description": v["description"],
             "event": v["event"], "secrets": list(v["secrets"])}
            for s, v in STARTERS.items()]


__all__ = ["STARTERS", "DEFAULT_STARTER", "get", "catalog"]

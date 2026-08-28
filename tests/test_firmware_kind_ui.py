"""The Install/Upgrade split has a client half, and it has to REACH the page.

Both artefact families are accepted server-side (``views/firmware.py``
``IMAGE_KINDS``), but choosing "Install" is only usable if the page's script
runs: it un-hides the hypervisor picker and widens the file input's ``accept``
filter.  From 2026-08-05 to 2026-08-29 that script sat in an orphan
``{% block %}`` and was never emitted -- see tests/test_template_blocks.py.

A template-text scan cannot see this class.  The only check that can is the
rendered response.
"""
from __future__ import annotations

import re

from tests.conftest import admin_user_id, login

#: Unique to the image-kind script.  Anchoring on ``fwKind`` instead looks
#: right and is NOT: the upload interceptor higher up the same page reads that
#: same element, so both assertions below passed against the WRONG <script>
#: and two mutations survived (twelfth substring-assert that matched something
#: else -- see safeguards on assert-by-substring).
ACCEPT = "'.out,.zip,.qcow2,.ova,.ovf,.vmdk,.img,.gz,.tgz'"


def _page(app, client) -> tuple[str, str]:
    login(client, admin_user_id(app))
    resp = client.get("/firmware/")
    assert resp.status_code == 200, resp.status_code
    nonce = re.search(r"'nonce-([^']+)'",
                      resp.headers.get("Content-Security-Policy", ""))
    assert nonce, "firmware page served without a nonce in its CSP"
    return resp.get_data(as_text=True), nonce.group(1)


def _kind_script(html: str) -> str:
    """The <script> that owns ACCEPT, isolated.

    Asserting over the WHOLE page is how a third mutation survived: base.html
    also calls ``classList.toggle('d-none'``, so a page-wide substring check
    stays true no matter what this script says.
    """
    i = html.index(ACCEPT)
    start = html.rindex("<script", 0, i)
    end = html.index("</script>", i)
    return html[start:end]


def test_the_page_offers_both_artefact_families(app, client):
    html, _ = _page(app, client)
    assert 'name="image_kind"' in html, "no image-type control at all"
    assert 'value="upgrade"' in html
    assert 'value="install"' in html


def test_the_image_kind_script_is_actually_emitted(app, client):
    """The defect, named: present in the file, absent from the response."""
    html, _ = _page(app, client)
    assert 'id="fwHypWrap"' in html, "hypervisor field missing from the markup"
    assert ACCEPT in html, (
        "the image-kind script never reached the page -- an orphan {% block %} "
        "silently discards it, so the file dialog still filters to .out and "
        "install media cannot even be selected"
    )
    script = _kind_script(html)
    assert "fwHypWrap" in script, "the script does not reach the hypervisor field"
    assert "classList.toggle('d-none'" in script, (
        "nothing un-hides the hypervisor picker, so an install image can never "
        "be told which hypervisor it is for"
    )


def test_that_script_carries_the_nonce_the_response_actually_served(app, client):
    """Asserting against the template's text would pass while the header and
    the attribute name different nonces."""
    html, nonce = _page(app, client)
    tag = _kind_script(html)
    assert nonce in tag, f"image-kind script is blocked by the CSP: {tag[:90]}"

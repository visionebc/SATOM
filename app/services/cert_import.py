"""Certificate collections REST cmdb CANNOT create — and how SSH does create them.

MEASURED, not assumed. On FortiWeb 7.6.8 (fw12, 2026-08-19) a cmdb POST to each
collection below answers **HTTP 500 / errcode -7721 "This certificate is
invalid."** — and it answers that with a *valid* PEM in the body (ISRG Root X1),
not only with a name-only body. The material is a file upload the cmdb API does
not carry, so a generic "+ New <X>" button on any of these pages can never
succeed, whatever the operator types into it.

The sweep that produced this list probed **all 37 writable Server Objects tabs**
against a live box. Three other rejections look identical in a log and are NOT
the same thing — they are ordinary *missing required field* errors that the
editor's own form supplies, so those pages keep the normal New button:

* ``system/certificate.tsl-ca`` — ``-7721`` with a name alone, but **created**
  with ``type=url`` + ``distribute-url``: a TSL CA is fetched from a URL, never
  uploaded. Blocking it would have taken a working page away.
* ``system/certificate.letsencrypt`` — ``-361`` with a name alone, **created**
  with ``domain``: the appliance's own ACME client, where the key never leaves
  the box.
* ``ocsp-stapling`` / ``hpkp`` / ``service.custom`` /
  ``http-content-routing-policy`` / ``pattern.custom-data-type`` — ``-56``
  "Empty value isn't allowed", i.e. a required field, nothing to do with
  material.

Reading the error code alone would have swept those into the blocked set.

**And reading it alone also MISSED one.** ``system/certificate.ocsp-signing-certs``
is in this list without ever having answered -7721: measured on fw12
(2026-08-19), a cmdb POST carrying a valid PEM answers **HTTP 200**, creates the
row and DISCARDS the certificate. It is worse than a refusal in every way that
matters -- a -7721 stops the caller, a 200 is reported as success -- and it is
invisible on the read back too, because REST prints ``certificate: ""`` for the
empty shell and for a populated entry alike. Only the CLI (``show``) returns the
bytes. Presence over REST is therefore NOT evidence of material in this table.

The lesson generalises past this one row: a sweep that classifies by error code
can only ever find the collections that produce an error.

**One list, both consumers.** :mod:`app.views.objedit` hides the +create-new
affordance on reference dropdowns for these collections, and
:mod:`app.views.server_objects` swaps the page's New button for Generate/Import.
Those two used to be maintained apart — which is exactly how
``certificate.local`` ended up forbidden in the dropdown while its own page
still offered the button.

The CLI field names come from ``set ?`` inside each table on fw12: ``ca`` and
``intermediate-certificate`` take ``certificate`` only (their ``set ?``
completes to that single field), and ``xml-client-certificate`` names its key
``secret-key``, not ``private-key``.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CertImportSpec:
    """How ONE certificate collection is written over the CLI.

    ``key_field`` is ``None`` for the collections that hold no private key (a CA
    and an intermediate CA are public material) — the import form then asks for
    a certificate alone, because offering a key box there would be a lie in the
    other direction.
    """

    collection: str        # bare cmdb collection ("system/certificate.local")
    cli_table: str         # `config system certificate <cli_table>`
    label: str             # human label for the import page
    key_field: str | None = None         # CLI field carrying the private key
    key_label: str = "Private key"
    passphrase_field: str | None = None  # CLI field for an encrypted key's password


#: collection -> spec. THE list; nothing else may enumerate these.
SSH_ONLY_SPECS: dict[str, CertImportSpec] = {
    s.collection: s for s in (
        CertImportSpec("system/certificate.local", "local", "Local Certificate",
                       key_field="private-key", passphrase_field="passwd"),
        CertImportSpec("system/certificate.ca", "ca", "CA Certificate"),
        CertImportSpec("system/certificate.intermediate-certificate",
                       "intermediate-certificate", "Intermediate CA"),
        CertImportSpec("system/certificate.sign-ca", "sign-ca", "Sign CA",
                       key_field="private-key", passphrase_field="passwd"),
        CertImportSpec("system/certificate.xml-server-certificate",
                       "xml-server-certificate", "XML Server Certificate",
                       key_field="private-key", passphrase_field="passwd"),
        CertImportSpec("system/certificate.xml-client-certificate",
                       "xml-client-certificate", "XML Client Certificate",
                       key_field="secret-key", key_label="Secret key"),
        # NOT found by the errcode sweep above -- see the module docstring.
        CertImportSpec("system/certificate.ocsp-signing-certs",
                       "ocsp-signing-certs", "OCSP Signing Certificate"),
    )
}

#: The collections themselves — what the two UI consumers ask.
SSH_ONLY_COLLECTIONS = frozenset(SSH_ONLY_SPECS)

#: Only a Local Certificate is a *managed* certificate: the Certificate Manager
#: generates a CSR, has it signed (ADCS/ACME) and deploys cert+key into
#: ``system/certificate.local``. Offering "Generate" on a CA page would promise
#: a lifecycle that store has no concept of.
GENERATE_COLLECTIONS = frozenset({"system/certificate.local"})


def spec_for(collection: str) -> CertImportSpec | None:
    """The import spec for a collection, or ``None`` if REST can create it."""
    return SSH_ONLY_SPECS.get((collection or "").strip())


def rest_can_create(collection: str) -> bool:
    """``False`` when a cmdb POST to this collection cannot succeed at all."""
    return (collection or "").strip() not in SSH_ONLY_COLLECTIONS


def can_generate(collection: str) -> bool:
    """``True`` when the Certificate Manager can mint an object for it."""
    return (collection or "").strip() in GENERATE_COLLECTIONS


__all__ = [
    "CertImportSpec", "SSH_ONLY_SPECS", "SSH_ONLY_COLLECTIONS",
    "GENERATE_COLLECTIONS", "spec_for", "rest_can_create", "can_generate",
]

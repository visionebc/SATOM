"""Formal Change-Request DOCUMENT (Markdown, English or German).

This renders the paper a customer's change process actually asks for: the
13 numbered sections their template already has, filled from ONE
:class:`~app.models.ChangeRequest` record plus the snapshots handed in by the
caller. It is the printable sibling of
:mod:`app.services.change_requests` (which renders the *client-facing* window
notices); the tone is deliberately the same — say what happens, name what is
missing, never invent a fact the product did not record.

WHY :func:`render` IS A PURE FUNCTION
-------------------------------------
``render`` touches NO database, contacts NO appliance and imports NO Flask
request context. Everything it prints comes from ``cr``, ``devices``,
``policies`` and ``prep``, which the caller read once — when the CR was
created — and froze.

That is not a style preference, it is the contract of the document. The
inventory in a change request is part of what the approver signed: "these
devices, these published services, this firmware". If the printer re-read the
fleet live, the document handed to the CAB before the window and the document
filed after it would describe different systems — a policy added yesterday
would appear in the executed record but not in the approved one, and a device
that went unreachable at print time would silently vanish from a signed page.
The approver signed the FIRST one. So the printer is given the frozen snapshot
and is structurally unable to go and look for a fresher one.

Corollaries enforced here:

* every datetime goes through :func:`app.services.settings_store.to_local` —
  the ONE timezone conversion path in this product — imported lazily so this
  module stays import-side-effect-free and testable with no app context, and
  wrapped so a missing context degrades to an explicit UTC stamp instead of
  raising. A bare ``strftime`` on a naive UTC datetime prints local-looking
  wall-clock time that is not local: a window that reads "22:00" and starts at
  midnight. Every printed timestamp therefore carries its timezone
  abbreviation.
* what a Fortinet firmware upgrade IS gets described as what it is: a full
  firmware image (``.out``) uploaded over the REST API to a target partition
  followed by a reboot into that partition (see
  :func:`app.services.upgrade.push_firmware`). It is NOT operating-system
  package patching, and the German text must never drift into that vocabulary
  ("Installation der neuesten Betriebssystem-Updates", "Aktualisierung
  installierter Pakete", "Anmeldung am Server" …). A document describing work
  that does not happen is worse than no document: the approver signs the wrong
  change, and the rollback plan they approved does not match the failure they
  will get. ``tests/test_cr_document.py`` asserts those phrases are absent.
* ``custom_rest`` promises NOTHING. Its impact is unknown by definition, so
  section 5 says so and section 9 prints the literal method / URN / body out of
  ``cr.params_dict`` for the reviewer to judge. Any invented impact statement
  there would be a guess printed under a signature line.
* missing data prints an explicit placeholder ("— (nicht erfasst)" /
  "— (not recorded)"), never an empty cell that reads as "nothing to report".

The action labels mirrored in :data:`ACTION_PROFILES` are copied verbatim from
:data:`app.services.scheduled_actions.ALL_ACTIONS`; they are NOT imported,
because importing the registry drags in the ORM models and this module must
stay usable (and testable) with nothing loaded. Keep them in sync by hand.
"""
from __future__ import annotations

import json
import re
import unicodedata
from typing import Any

from . import langs

# --------------------------------------------------------------------------- #
#  Languages                                                                    #
# --------------------------------------------------------------------------- #
#: The languages a COMPLETE change document can be produced in — i.e. the ones
#: :data:`ACTION_PROFILES` is authored in.  This is deliberately narrower than
#: :data:`app.services.langs.SUPPORTED`: offering a language whose profiles do
#: not exist would produce a document half in English under a signature line,
#: and nothing would fail.  Widen it only together with the prose.
AUTHORED_LANGS: frozenset = frozenset({"en", "de"})

#: Ordered and labelled BY THE REGISTRY, never re-listed here.  A second author
#: of the language list is how a picker ends up offering a language the
#: renderer cannot produce.  ``langs`` imports nothing, so this does not break
#: the rule above that keeps this module free of the ORM.
DEFAULT_LANG = langs.DEFAULT


def document_langs() -> tuple:
    """``((code, endonym), ...)`` for every language a COMPLETE document can be
    produced in, in the registry's display order.

    There is deliberately no ``LANGS`` constant any more.  A module-level tuple
    could only ever describe the languages authored in Python, so every picker
    that read it was blind to the translated catalogue -- and a second author of
    the language list is exactly how a picker comes to offer a language the
    renderer cannot produce.  This is the ONE answer; it is a function because
    the honest answer depends on data.

    Falls back to the authored set if the catalogue cannot be read (no app
    context, table missing): degrading to English+German is a smaller lie than
    claiming five languages the renderer cannot fill.

    Narrowed once more by what the INSTALL offers
    (:mod:`app.services.lang_policy`): an administrator who withdrew a language
    withdrew it from every picker, not only from the profile.  The source
    language is offered unconditionally there, so this can never return empty.
    """
    try:
        from . import lang_policy
        allowed = set(lang_policy.offered_codes())
    except Exception:  # noqa: BLE001 — an unreadable gate offers everything
        allowed = set(langs.codes())
    return tuple(pair for pair in renderable_langs() if pair[0] in allowed)


def renderable_langs() -> tuple:
    """``((code, endonym), ...)`` for every language a complete document CAN be
    produced in, before the install's availability gate is applied.

    Split out from :func:`document_langs` for exactly one caller: the admin
    console, which has to say "documents are not produced in Italian yet"
    *next to the switch that would enable Italian*.  Asking the gated function
    there would answer "not renderable" for every language the operator has not
    switched on yet -- the answer would depend on the setting being described,
    which is how a page comes to argue with itself.
    """
    try:
        from . import cr_i18n
        ready = set(cr_i18n.cached_ready())
    except Exception:  # noqa: BLE001
        ready = set(AUTHORED_LANGS)
    ready |= set(AUTHORED_LANGS)
    return tuple((code, langs.label(code)) for code in langs.codes()
                 if code in ready)


def _lang_keys() -> tuple:
    return tuple(code for code, _label in document_langs())

#: Every key a per-language action profile MUST define. A half-translated
#: profile is exactly how a German document ships with an English paragraph in
#: the middle of it, so the completeness check is table-driven in the tests.
REQUIRED_PROFILE_KEYS: tuple = (
    "label", "purpose", "justification", "impact", "downtime", "risk",
    "rollback", "work", "validation",
)

#: Key of the fallback profile used for any action not profiled below.
GENERIC_ACTION = "_generic"


def normalize_lang(value) -> str:
    """Coerce anything to a supported language code. Never raises.

    Unknown, blank and ``None`` all fall back to :data:`DEFAULT_LANG`; regional
    tags degrade to their base language ("de-CH" -> "de") and case is ignored,
    so a browser header or a stored preference can be passed straight in.
    """
    key = langs.normalize(value)
    # A supported language is not the same as a renderable one: "es" is a real
    # product language, but until its catalogue is COMPLETE a Spanish document
    # would print English prose under a Spanish heading.  Degrade to the
    # source language, which is at least internally consistent.  Completeness
    # is measured (see cr_i18n.coverage), never declared -- a half-filled
    # catalogue withdraws the language instead of shipping a mixed document.
    return key if key in _lang_keys() else DEFAULT_LANG


# --------------------------------------------------------------------------- #
#  Fixed vocabulary                                                             #
# --------------------------------------------------------------------------- #
SECTION_TITLES: dict = {
    "de": (
        "Allgemeine Informationen",
        "Ziel des Changes",
        "Betroffene Systeme",
        "Begründung",
        "Auswirkungen",
        "Risikoanalyse",
        "Rollback-Plan",
        "Voraussetzungen",
        "Durchzuführende Arbeiten",
        "Validierung nach dem Change",
        "Kommunikationsplan",
        "Freigaben",
        "Ergebnis des Changes",
    ),
    "en": (
        "General information",
        "Purpose of the change",
        "Affected systems",
        "Justification",
        "Impact",
        "Risk analysis",
        "Rollback plan",
        "Prerequisites",
        "Work to be performed",
        "Post-change validation",
        "Communication plan",
        "Approvals",
        "Change outcome",
    ),
}

_T: dict = {
    "de": {
        "doc_kind": "Change-Request-Dokument",
        "placeholder": "— (nicht erfasst)",
        "yes": "ja",
        "no": "nein",
        "unknown": "unbekannt",
        # --- 1 ---
        "col_field": "Feld",
        "col_value": "Wert",
        "f_change_id": "Change-ID",
        "f_title": "Titel",
        "f_status": "Status",
        "f_action": "Auszuführende Aktion",
        "f_requester": "Antragsteller (`requested_by`)",
        "f_owner": "Verantwortlicher",
        "f_window_date": "Datum des Wartungsfensters",
        "f_window_start": "Beginn des Fensters",
        "f_window_end": "Ende des Fensters",
        "f_risk": "Risikoeinstufung",
        "f_crq": "Externe CRQ-Referenz",
        "f_doc_state": "Dokumentstand (letzte Änderung am Datensatz)",
        "owner_note": (
            "Für diesen Change ist kein Verantwortlicher hinterlegt. Das Feld "
            "wird vor der Freigabe handschriftlich ergänzt — es wird hier nicht "
            "aus dem Antragsteller abgeleitet."),
        "tz_note": (
            "Alle Zeitangaben in diesem Dokument sind in der in SATOM "
            "eingestellten Zeitzone angegeben und tragen deren Kürzel."),
        # --- 3 ---
        "d_name": "Gerät",
        "d_kind": "Produkt",
        "d_firmware": "Firmware",
        "d_host": "Host",
        "d_adom": "ADOM / Standort",
        "no_devices": (
            "Im Change Request ist keine Geräte-Stammdatenliste hinterlegt "
            "worden. Erfasste Geräte-IDs: %s. Die Stammdaten sind vor der "
            "Freigabe zu ergänzen."),
        "no_device_ids": "Es sind keine Zielgeräte im Change Request erfasst.",
        "frozen_note": (
            "Diese Aufstellung ist der beim Anlegen des Change Requests "
            "eingefrorene Stand. Sie wird beim Drucken NICHT neu von den "
            "Geräten gelesen: das freigegebene und das ausgeführte Dokument "
            "müssen dieselben Systeme beschreiben."),
        # --- 4 ---
        "reason_head": "Begründung aus dem Change Request",
        "no_reason": (
            "Im Change Request ist keine Begründung erfasst "
            "(— nicht erfasst). Vor der Freigabe nachzutragen."),
        # --- 5 ---
        "downtime_label": "Geschätzte Ausfallzeit",
        "services_count": "Betroffene veröffentlichte Dienste laut Abschnitt 10: %s",
        # --- 6 ---
        "risk_label": "Eingestuftes Risiko",
        # --- 7 ---
        "rollback_own": "Rollback-Beschreibung aus dem Change Request",
        "no_rollback": (
            "Im Change Request ist kein eigener Rollback-Text erfasst "
            "(— nicht erfasst). Es gelten ausschließlich die folgenden "
            "Standardschritte."),
        "rollback_fixed": "Standardschritte für diese Aktion",
        # --- 8 ---
        "prep_from": "Quelle: Vorab-Prüfung (`upgrade.prepare`) für %s, erstellt am %s.",
        "prep_none": (
            "Für diesen Change Request liegt keine maschinelle Vorab-Prüfung "
            "vor (— nicht erfasst). Die folgenden Punkte sind vor Beginn "
            "manuell zu bestätigen und abzuhaken."),
        "p_backup": "Konfigurations-Backup der Ziel-Appliance erstellt und abgelegt",
        "p_health": "Systemzustand vor dem Change aufgenommen",
        "p_services": "Veröffentlichte Dienste vor dem Change geprüft",
        "p_firmware": "Aktueller Firmware-Stand festgehalten: %s",
        "p_permission": "Wartungsberechtigung des verwendeten Kontos geprüft",
        "p_window": "Wartungsfenster freigegeben und Kunden informiert",
        "p_image": "Freigegebenes Firmware-Image (.out) inkl. Prüfsumme bereitgestellt",
        "p_access": "Zugang außerhalb des Datenpfads (Konsole / Out-of-Band) sichergestellt",
        "p_probes": "%d von %d Diensten erreichbar",
        "p_probes_none": "keine Dienste geprüft",
        "p_error": "Fehler",
        # --- 9 ---
        "params_head": "Im Change Request hinterlegte Parameter",
        "params_none": "Es sind keine Parameter hinterlegt (— nicht erfasst).",
        "rest_method": "Methode",
        "rest_endpoint": "Endpunkt (URN)",
        "rest_mkey": "mkey",
        "rest_label": "Bezeichnung",
        "rest_body": "Request-Body (wörtlich aus dem Change Request)",
        "rest_none": (
            "Im Change Request ist kein REST-Aufruf hinterlegt "
            "(— nicht erfasst). Ohne Methode und Endpunkt ist dieser Change "
            "nicht prüfbar und darf nicht freigegeben werden."),
        # --- 10 ---
        "pol_device": "Gerät",
        "pol_policy": "Server-Policy / Virtual Server",
        "pol_vserver": "vServer / Interface",
        "pol_service": "Dienst / Port",
        "pol_status": "Status",
        "pol_head": "Betroffene veröffentlichte Dienste (Stand bei Anlage des Change Requests)",
        "no_policies": (
            "Für die Zielgeräte sind keine veröffentlichten Dienste erfasst "
            "(— nicht erfasst). Das kann korrekt sein (FortiAnalyzer und "
            "FortiAuthenticator veröffentlichen kein entsprechendes Objekt) "
            "oder auf eine fehlgeschlagene Erfassung hindeuten — vor der "
            "Freigabe zu klären."),
        # --- 11 ---
        "comm_recipients": "Empfänger (`notify_to`)",
        "comm_no_recipients": (
            "Im Change Request sind keine Empfänger hinterlegt "
            "(— nicht erfasst). SATOM rät keine Adresse; die Empfänger sind "
            "vor der Freigabe einzutragen."),
        "comm_status": "Status der Vorab-Information",
        "comm_final": "Abschlussmeldung versendet am",
        "comm_steps": "Kommunikationsschritte",
        "comm_1": "Vorab-Information an die betroffenen Kunden vor Beginn des Fensters.",
        "comm_2": "Meldung an den Service Desk bei Beginn der Arbeiten.",
        "comm_3": "Abschlussmeldung nach Ende des Fensters mit dem tatsächlichen Ergebnis.",
        "comm_4": "Bei Rollback: gesonderte Meldung mit dem Grund des Rollbacks.",
        # --- 12 ---
        "ap_role": "Rolle",
        "ap_name": "Name",
        "ap_date": "Datum",
        "ap_sign": "Unterschrift",
        "ap_satom": "Freigabe in SATOM (`approved_by`)",
        "ap_roles": ("Systemadministrator", "Service Owner", "Change Manager",
                     "CAB (Change Advisory Board)"),
        "ap_note": (
            "Nur die ERSTE Zeile ist systemseitig belegt: SATOM erfasst genau "
            "einen Freigebenden (`approved_by` / `approved_at`). Alle weiteren "
            "Zeilen sind bewusst leer und werden handschriftlich gezeichnet — "
            "es werden keine Freigaben gedruckt, die das System nie erfasst hat."),
        "ap_not_approved": "in SATOM nicht freigegeben",
        # --- 13 ---
        "out_completed": "Erfolgreich abgeschlossen",
        "out_failed": "Nicht erfolgreich — Rollback durchgeführt bzw. Zustand unverändert",
        "out_cancelled": "Abgebrochen / nicht durchgeführt",
        "out_open": (
            "Der Change Request ist noch nicht abgeschlossen (Status: %s). "
            "Das Ergebnis wird nach dem Fenster eingetragen."),
        "out_summary": "Ergebnisbeschreibung (`result_summary`)",
        "out_no_summary": "Keine Ergebnisbeschreibung erfasst (— nicht erfasst).",
        "out_sign": "Datum / Unterschrift des Durchführenden",
        "status_labels": {
            "draft": "Entwurf", "approved": "Freigegeben", "scheduled": "Eingeplant",
            "in_progress": "In Durchführung", "completed": "Abgeschlossen",
            "failed": "Fehlgeschlagen", "cancelled": "Abgebrochen",
        },
        "risk_labels": {"low": "Niedrig", "medium": "Mittel", "high": "Hoch"},
        "notify_labels": {"none": "nicht versendet", "drafted": "entworfen",
                          "sent": "versendet"},
    },
    "en": {
        "doc_kind": "Change request document",
        "placeholder": "— (not recorded)",
        "yes": "yes",
        "no": "no",
        "unknown": "unknown",
        "col_field": "Field",
        "col_value": "Value",
        "f_change_id": "Change ID",
        "f_title": "Title",
        "f_status": "Status",
        "f_action": "Action to be executed",
        "f_requester": "Requester (`requested_by`)",
        "f_owner": "Owner",
        "f_window_date": "Maintenance window date",
        "f_window_start": "Window start",
        "f_window_end": "Window end",
        "f_risk": "Risk rating",
        "f_crq": "External CRQ reference",
        "f_doc_state": "Document state (record last changed)",
        "owner_note": (
            "No owner is recorded for this change. The field is filled in by "
            "hand before approval — it is not derived from the requester "
            "here."),
        "tz_note": (
            "Every time in this document is shown in the timezone configured "
            "in SATOM and carries its abbreviation."),
        "d_name": "Device",
        "d_kind": "Product",
        "d_firmware": "Firmware",
        "d_host": "Host",
        "d_adom": "ADOM / site",
        "no_devices": (
            "No device inventory was supplied with this change request. "
            "Recorded device ids: %s. The device details must be filled in "
            "before approval."),
        "no_device_ids": "No target devices are recorded on this change request.",
        "frozen_note": (
            "This inventory is the snapshot frozen when the change request was "
            "created. It is NOT re-read from the devices at print time: the "
            "approved document and the executed document have to describe the "
            "same systems."),
        "reason_head": "Reason recorded on the change request",
        "no_reason": (
            "No reason is recorded on this change request (— not recorded). "
            "It must be added before approval."),
        "downtime_label": "Estimated downtime",
        "services_count": "Published services affected, per section 10: %s",
        "risk_label": "Rated risk",
        "rollback_own": "Rollback description recorded on the change request",
        "no_rollback": (
            "No rollback text is recorded on this change request "
            "(— not recorded). Only the standard steps below apply."),
        "rollback_fixed": "Standard steps for this action",
        "prep_from": "Source: pre-flight check (`upgrade.prepare`) for %s, generated %s.",
        "prep_none": (
            "No machine-recorded pre-flight check is attached to this change "
            "request (— not recorded). The items below must be confirmed and "
            "ticked by hand before work starts."),
        "p_backup": "Configuration backup of the target appliance taken and stored",
        "p_health": "System health baseline captured before the change",
        "p_services": "Published services probed before the change",
        "p_firmware": "Current firmware level recorded: %s",
        "p_permission": "Maintenance permission of the account in use verified",
        "p_window": "Maintenance window approved and customers informed",
        "p_image": "Approved firmware image (.out) and its checksum staged",
        "p_access": "Out-of-band access (console) available independently of the data path",
        "p_probes": "%d of %d services reachable",
        "p_probes_none": "no services probed",
        "p_error": "error",
        "params_head": "Parameters recorded on the change request",
        "params_none": "No parameters are recorded (— not recorded).",
        "rest_method": "Method",
        "rest_endpoint": "Endpoint (URN)",
        "rest_mkey": "mkey",
        "rest_label": "Label",
        "rest_body": "Request body (verbatim from the change request)",
        "rest_none": (
            "No REST call is recorded on this change request (— not "
            "recorded). Without a method and an endpoint this change cannot "
            "be reviewed and must not be approved."),
        "pol_device": "Device",
        "pol_policy": "Server policy / virtual server",
        "pol_vserver": "vServer / interface",
        "pol_service": "Service / port",
        "pol_status": "Status",
        "pol_head": "Published services affected (as recorded when the change request was created)",
        "no_policies": (
            "No published services are recorded for the target devices "
            "(— not recorded). That can be correct (FortiAnalyzer and "
            "FortiAuthenticator publish no equivalent object) or it can mean "
            "the read failed — clarify before approval."),
        "comm_recipients": "Recipients (`notify_to`)",
        "comm_no_recipients": (
            "No recipients are recorded on this change request (— not "
            "recorded). SATOM does not guess an address; they must be entered "
            "before approval."),
        "comm_status": "State of the advance notice",
        "comm_final": "Outcome notice sent at",
        "comm_steps": "Communication steps",
        "comm_1": "Advance notice to the affected customers before the window opens.",
        "comm_2": "Notify the service desk when work starts.",
        "comm_3": "Outcome notice after the window closes, carrying the real result.",
        "comm_4": "On rollback: a separate notice stating why the change was rolled back.",
        "ap_role": "Role",
        "ap_name": "Name",
        "ap_date": "Date",
        "ap_sign": "Signature",
        "ap_satom": "Approval in SATOM (`approved_by`)",
        "ap_roles": ("System administrator", "Service owner", "Change manager",
                     "CAB (Change Advisory Board)"),
        "ap_note": (
            "Only the FIRST row is system-attested: SATOM records exactly one "
            "approver (`approved_by` / `approved_at`). Every other row is left "
            "blank on purpose and is signed by hand — no approval the product "
            "never recorded is printed here."),
        "ap_not_approved": "not approved in SATOM",
        "out_completed": "Completed successfully",
        "out_failed": "Not successful — rolled back, or state left unchanged",
        "out_cancelled": "Cancelled / not carried out",
        "out_open": (
            "This change request is not closed yet (status: %s). The outcome "
            "is entered after the window."),
        "out_summary": "Outcome description (`result_summary`)",
        "out_no_summary": "No outcome description recorded (— not recorded).",
        "out_sign": "Date / signature of the engineer who carried it out",
        "status_labels": {
            "draft": "Draft", "approved": "Approved", "scheduled": "Scheduled",
            "in_progress": "In progress", "completed": "Completed",
            "failed": "Failed", "cancelled": "Cancelled",
        },
        "risk_labels": {"low": "Low", "medium": "Medium", "high": "High"},
        "notify_labels": {"none": "not sent", "drafted": "drafted", "sent": "sent"},
    },
}


# --------------------------------------------------------------------------- #
#  Per-action profiles                                                          #
#                                                                               #
#  Sections 2, 4, 5, 6, 7, 9 and 10 vary per action. The labels are copied      #
#  verbatim from services.scheduled_actions.ALL_ACTIONS.                        #
# --------------------------------------------------------------------------- #
ACTION_PROFILES: dict = {
    # ---------------------------------------------------------------- upgrade
    "upgrade": {
        "de": {
            "label": "Firmware-Upgrade (vollständig — Image + Neustart)",
            "purpose": (
                "Anhebung der Ziel-Appliance auf einen freigegebenen "
                "Firmware-Stand. Ein VOLLSTÄNDIGES Firmware-Image (`.out`) "
                "wird über die REST-API der Appliance hochgeladen (multipart-"
                "POST auf `system/maintenance.firmwareupgradedowngrade` mit "
                "`device`/`active`/`part`), in die Ziel-Partition geschrieben "
                "und anschließend durch einen Neustart in genau diese "
                "Partition aktiviert. Die Firmware der Appliance wird dabei "
                "als Ganzes ersetzt."),
            "justification": (
                "Der Image-Tausch mit anschließendem Neustart unterbricht den "
                "Datenpfad der Appliance und ist deshalb nur in einem "
                "freigegebenen Wartungsfenster, mit vorher erstelltem "
                "Konfigurations-Backup und mit einem definierten Rückweg auf "
                "die vorherige Partition zulässig."),
            "impact": (
                "Während des Uploads bleibt die Appliance in Betrieb. Mit dem "
                "Neustart in die neue Partition fallen ALLE über diese "
                "Appliance veröffentlichten Dienste (Server-Policies bzw. "
                "Virtual Server) aus, bis der Datenpfad wieder aufgenommen "
                "ist. In einem HA-Verbund erfolgt in der Regel ein Failover "
                "auf den Partner; ein Einzelgerät ist für die Dauer des "
                "Neustarts nicht erreichbar. Die Management-Oberfläche ist "
                "ebenfalls nicht erreichbar."),
            "downtime": (
                "ca. 8–15 Minuten je Appliance (Neustart in die neue "
                "Partition inklusive Konfigurations-Migration; der "
                "vorgelagerte Image-Upload ist unterbrechungsfrei)"),
            "risk": (
                "Wesentliche Risiken: die Appliance verweigert einen "
                "ungültigen Upgrade-Pfad zwischen Branches; der Wechsel "
                "zwischen Feature- und Mature-Zweig verlangt einen "
                "Bestätigungs-Handshake; die Konfiguration wird beim ersten "
                "Start der neuen Firmware migriert und kann dabei einzelne "
                "Einstellungen verändern; der Bootvorgang kann sich "
                "verlängern. Kommt die Appliance nicht zurück, ist ein Zugang "
                "über Konsole bzw. Out-of-Band zwingend erforderlich."),
            "rollback": (
                "Neustart in die zuvor aktive Partition — der alte "
                "Firmware-Stand bleibt dort erhalten.",
                "Falls die alte Partition nicht mehr startet: altes "
                "Firmware-Image erneut hochladen und aktivieren.",
                "Konfiguration aus dem in Abschnitt 8 genannten Backup "
                "zurückspielen.",
                "Veröffentlichte Dienste erneut prüfen, bevor das Fenster "
                "geschlossen wird.",
            ),
            "work": (
                "Freigegebenes Firmware-Image (`.out`) inklusive Prüfsumme "
                "bereitstellen und Upgrade-Pfad gegen den aktuellen Stand "
                "prüfen.",
                "Konfigurations-Backup der Appliance erstellen und ablegen.",
                "Ausgangszustand aufnehmen: Firmware-Stand, Systemzustand, "
                "Erreichbarkeit der veröffentlichten Dienste.",
                "Firmware-Image per REST-API auf die Ziel-Partition hochladen "
                "(multipart-POST, `device`/`active`/`part` gesetzt).",
                "Von der Appliance angeforderten Bestätigungs-Handshake "
                "(Maturity- bzw. Downgrade-Bestätigung) beantworten.",
                "Neustart in die neue Partition abwarten und Wiederkehr der "
                "Management-Schnittstelle prüfen.",
                "Firmware-Stand nach dem Neustart auslesen und mit dem "
                "Zielstand vergleichen.",
                "Veröffentlichte Dienste erneut prüfen (Vorher-/Nachher-"
                "Vergleich) und das Ergebnis dokumentieren.",
            ),
            "validation": (
                "Der ausgelesene Firmware-Stand entspricht dem Zielstand.",
                "Die Appliance ist über die Management-Schnittstelle "
                "erreichbar; im HA-Verbund ist der erwartete Rollenzustand "
                "wiederhergestellt.",
                "Alle unten gelisteten veröffentlichten Dienste antworten wie "
                "vor dem Change (Status, Zertifikat, Antwortverhalten).",
                "Im System-Log der Appliance sind keine neuen Fehler nach dem "
                "Neustart verzeichnet.",
            ),
        },
        "en": {
            "label": "Firmware upgrade (FULL - flashes + reboots)",
            "purpose": (
                "Bring the target appliance to an approved firmware level. A "
                "FULL firmware image (`.out`) is uploaded over the appliance "
                "REST API (multipart POST to "
                "`system/maintenance.firmwareupgradedowngrade` with "
                "`device`/`active`/`part`), written to the target partition, "
                "and activated by rebooting into that partition. The "
                "appliance firmware is replaced as a whole."),
            "justification": (
                "Swapping the image and rebooting interrupts the appliance "
                "data path, so it is only permitted inside an approved "
                "maintenance window, with a configuration backup taken "
                "beforehand and a defined way back to the previous "
                "partition."),
            "impact": (
                "The appliance keeps serving during the upload. When it "
                "reboots into the new partition EVERY service published by "
                "this appliance (server policies / virtual servers) is down "
                "until the data path is back. In an HA cluster a failover to "
                "the partner is expected; a standalone box is unreachable for "
                "the duration of the reboot. The management interface is "
                "unreachable as well."),
            "downtime": (
                "approx. 8-15 minutes per appliance (reboot into the new "
                "partition including config migration; the preceding image "
                "upload is non-disruptive)"),
            "risk": (
                "Main risks: the appliance refuses an invalid upgrade path "
                "across branches; crossing the feature/mature boundary "
                "requires a confirmation handshake; the configuration is "
                "migrated on the first boot of the new firmware and may "
                "change individual settings; the boot can take longer than "
                "expected. If the appliance does not come back, console / "
                "out-of-band access is mandatory."),
            "rollback": (
                "Reboot into the previously active partition - the old "
                "firmware is still there.",
                "If the old partition no longer boots: upload and activate "
                "the previous firmware image again.",
                "Restore the configuration from the backup named in "
                "section 8.",
                "Re-probe the published services before closing the window.",
            ),
            "work": (
                "Stage the approved firmware image (`.out`) with its checksum "
                "and verify the upgrade path against the current level.",
                "Take and store a configuration backup of the appliance.",
                "Record the baseline: firmware level, system health, "
                "reachability of the published services.",
                "Upload the firmware image over the REST API to the target "
                "partition (multipart POST with `device`/`active`/`part`).",
                "Answer the confirmation handshake the appliance asks for "
                "(maturity change / downgrade confirmation).",
                "Wait for the reboot into the new partition and check that "
                "the management interface returns.",
                "Read the firmware level after the reboot and compare it with "
                "the target level.",
                "Re-probe the published services (before/after comparison) "
                "and record the result.",
            ),
            "validation": (
                "The firmware level read back matches the target level.",
                "The appliance is reachable on its management interface; in "
                "an HA cluster the expected role state is restored.",
                "Every published service listed below answers as it did "
                "before the change (status, certificate, response).",
                "No new errors in the appliance system log after the reboot.",
            ),
        },
    },
    # ----------------------------------------------------------- upgrade_prep
    "upgrade_prep": {
        "de": {
            "label": "Upgrade-Vorbereitung (Backup + Systemzustand)",
            "purpose": (
                "Aufnahme eines belastbaren Ausgangszustands vor einem "
                "Firmware-Wechsel: Konfigurations-Backup, Systemzustand und "
                "Erreichbarkeit der veröffentlichten Dienste. Es wird KEIN "
                "Firmware-Image übertragen und nichts an der Appliance "
                "verändert."),
            "justification": (
                "Ein Wartungsfenster darf nur von einem dokumentierten, "
                "bekannten Zustand aus starten. Ohne Backup und "
                "Vorher-Messung ist nach dem Change weder ein Rollback noch "
                "der Nachweis möglich, dass die Dienste vorher liefen."),
            "impact": (
                "Keine Auswirkung auf den Datenpfad. Die Aktion liest die "
                "Appliance und erzeugt ein Backup; bestehende Verbindungen "
                "bleiben unberührt."),
            "downtime": "keine — ausschließlich lesende Zugriffe",
            "risk": (
                "Geringes Risiko. Relevante Fehlerbilder sind ein "
                "fehlgeschlagenes Backup, eine nicht erreichbare "
                "SSH-Schnittstelle für die Zustandsabfrage oder nicht "
                "auflösbare Dienst-Ziele. Jeder dieser Fälle ist ein Grund, "
                "den nachfolgenden Change NICHT zu starten."),
            "rollback": (
                "Kein Rollback erforderlich — es wird nichts verändert.",
                "Bei fehlgeschlagenem Backup: Ursache klären und die "
                "Vorbereitung wiederholen, bevor ein Change freigegeben wird.",
            ),
            "work": (
                "Konfigurations-Backup der Appliance erstellen und ablegen.",
                "Systemzustand der Appliance auslesen und sichern.",
                "Veröffentlichte Dienste ermitteln und als Referenz messen.",
                "Ergebnis dem Change Request beilegen (Abschnitt 8).",
            ),
            "validation": (
                "Das Backup ist vorhanden, benannt und lesbar abgelegt.",
                "Der Systemzustand ist dokumentiert.",
                "Die Referenzmessung der veröffentlichten Dienste liegt vor.",
            ),
        },
        "en": {
            "label": "Upgrade preparation (backup + health)",
            "purpose": (
                "Capture a trustworthy baseline before a firmware change: a "
                "configuration backup, the system health and the reachability "
                "of the published services. NO firmware image is transferred "
                "and nothing on the appliance is modified."),
            "justification": (
                "A maintenance window may only start from a documented, known "
                "state. Without a backup and a before-measurement there is "
                "neither a rollback nor any evidence that the services were "
                "working beforehand."),
            "impact": (
                "No impact on the data path. The action reads the appliance "
                "and produces a backup; existing connections are untouched."),
            "downtime": "none - read-only pre-flight",
            "risk": (
                "Low risk. The relevant failure modes are a failed backup, an "
                "unreachable SSH interface for the health read, or service "
                "targets that cannot be resolved. Each of those is a reason "
                "NOT to start the change that follows."),
            "rollback": (
                "No rollback needed - nothing is modified.",
                "If the backup failed: find out why and repeat the "
                "preparation before any change is approved.",
            ),
            "work": (
                "Take and store a configuration backup of the appliance.",
                "Read and keep the appliance system health.",
                "Resolve the published services and measure them as a "
                "reference.",
                "Attach the result to the change request (section 8).",
            ),
            "validation": (
                "The backup exists, is named and is stored readably.",
                "The system health is documented.",
                "The reference measurement of the published services is on "
                "file.",
            ),
        },
    },
    # ----------------------------------------------------------------- reboot
    "reboot": {
        "de": {
            "label": "Neustart der Appliance (destruktiv)",
            "purpose": (
                "Kontrollierter Neustart der Ziel-Appliance über die dafür "
                "verifizierte REST-Schnittstelle des jeweiligen Produkts. Es "
                "wird keine Firmware und keine Konfiguration verändert — die "
                "Appliance startet mit dem bestehenden Stand neu."),
            "justification": (
                "Ein Neustart unterbricht den Datenpfad vollständig und wird "
                "deshalb ausschließlich gebunden an einen freigegebenen "
                "Change Request innerhalb des Wartungsfensters ausgeführt."),
            "impact": (
                "Alle über die Appliance veröffentlichten Dienste sind vom "
                "Auslösen des Neustarts bis zur Wiederaufnahme des "
                "Datenpfads nicht erreichbar. Bestehende Sitzungen werden "
                "beendet. Im HA-Verbund ist mit einem Failover zu rechnen."),
            "downtime": "ca. 3–6 Minuten je Appliance (reiner Neustart)",
            "risk": (
                "Wesentliche Risiken: die Appliance kommt nicht oder nur "
                "verzögert zurück; nicht gespeicherte Konfigurationsteile "
                "gehen verloren; im HA-Verbund entsteht ein ungewollter "
                "Rollenwechsel. Der Neustart-Aufruf wird nur an Produkte "
                "gesendet, für die er gegen ein Gerät desselben Produkts "
                "verifiziert wurde."),
            "rollback": (
                "Ein Neustart ist nicht rückabwickelbar — der Rückweg ist "
                "ausschließlich die Wiederkehr der Appliance.",
                "Kommt die Appliance nicht zurück: Zugang über Konsole bzw. "
                "Out-of-Band aufnehmen und den Startvorgang beobachten.",
                "Im HA-Verbund gegebenenfalls die vorherige Rollenverteilung "
                "wiederherstellen.",
            ),
            "work": (
                "Ausgangszustand aufnehmen: Erreichbarkeit, HA-Rolle, "
                "veröffentlichte Dienste.",
                "Sicherstellen, dass die laufende Konfiguration gespeichert "
                "ist.",
                "Neustart über die für das Produkt verifizierte "
                "REST-Schnittstelle mit hinterlegtem Grund auslösen.",
                "Rückkehr der Appliance abwarten und Management-"
                "Erreichbarkeit prüfen.",
                "Veröffentlichte Dienste erneut prüfen.",
            ),
            "validation": (
                "Die Appliance ist über die Management-Schnittstelle wieder "
                "erreichbar.",
                "Die HA-Rolle entspricht dem erwarteten Zustand.",
                "Alle unten gelisteten veröffentlichten Dienste antworten "
                "wieder.",
                "Die Betriebszeit der Appliance weist den Neustart aus.",
            ),
        },
        "en": {
            "label": "Reboot the appliance (DESTRUCTIVE)",
            "purpose": (
                "Controlled reboot of the target appliance through the REST "
                "endpoint verified for that product. No firmware and no "
                "configuration is changed - the appliance comes back on the "
                "level it already ran."),
            "justification": (
                "A reboot interrupts the data path completely, so it only "
                "runs bound to an approved change request inside its "
                "maintenance window."),
            "impact": (
                "Every service published by the appliance is unreachable from "
                "the moment the reboot is issued until the data path is back. "
                "Existing sessions are dropped. In an HA cluster expect a "
                "failover."),
            "downtime": "approx. 3-6 minutes per appliance (reboot only)",
            "risk": (
                "Main risks: the appliance does not come back, or comes back "
                "late; unsaved configuration is lost; an unintended role "
                "change happens in an HA cluster. The reboot call is only "
                "sent to products where it has been verified against a device "
                "of that same product."),
            "rollback": (
                "A reboot cannot be undone - the only way back is the "
                "appliance returning.",
                "If it does not return: take console / out-of-band access and "
                "watch the boot.",
                "Restore the previous HA role distribution if needed.",
            ),
            "work": (
                "Record the baseline: reachability, HA role, published "
                "services.",
                "Make sure the running configuration is saved.",
                "Issue the reboot through the REST endpoint verified for that "
                "product, carrying the recorded reason.",
                "Wait for the appliance to return and check management "
                "reachability.",
                "Re-probe the published services.",
            ),
            "validation": (
                "The appliance is reachable on its management interface "
                "again.",
                "The HA role matches the expected state.",
                "Every published service listed below answers again.",
                "The appliance uptime shows the reboot.",
            ),
        },
    },
    # ------------------------------------------------------ policy_set_status
    "policy_set_status": {
        "de": {
            "label": "Server-Policy aktivieren / deaktivieren",
            "purpose": (
                "Geplantes Ein- oder Ausschalten einer Server-Policy auf der "
                "Ziel-Appliance — etwa für eine Umschaltung oder eine "
                "geplante Pause eines veröffentlichten Dienstes. Der Schreib"
                "vorgang läuft über den Standard-Schreibpfad mit Snapshot, "
                "Änderungshistorie und Audit-Eintrag."),
            "justification": (
                "Das Deaktivieren einer Server-Policy nimmt den dahinter "
                "liegenden Dienst gezielt aus dem Netz. Das ist kundenwirksam "
                "und gehört deshalb in ein angekündigtes Fenster."),
            "impact": (
                "Betroffen ist genau die in den Parametern benannte "
                "Server-Policy. Beim Deaktivieren ist der veröffentlichte "
                "Dienst ab dem Umschalten nicht mehr erreichbar; bestehende "
                "Sitzungen werden beendet. Andere Policies derselben "
                "Appliance laufen unverändert weiter."),
            "downtime": (
                "Umschaltung unter einer Minute; beim Deaktivieren bleibt der "
                "betroffene Dienst jedoch bis zur Wiederaktivierung "
                "vollständig offline"),
            "risk": (
                "Wesentliche Risiken: die falsche Policy wird benannt; nach "
                "dem Deaktivieren wird die Wiederaktivierung vergessen; "
                "abhängige Dienste oder Health-Checks Dritter schlagen an. "
                "Die Appliance selbst bleibt in Betrieb."),
            "rollback": (
                "Ursprünglichen Status der Server-Policy wiederherstellen "
                "(Umkehrung des gesetzten Werts).",
                "Änderung über die Änderungshistorie der Appliance "
                "nachvollziehen und den Vorher-Zustand bestätigen.",
            ),
            "work": (
                "Vorher-Status der benannten Server-Policy auslesen und "
                "festhalten.",
                "Erreichbarkeit des veröffentlichten Dienstes vor der "
                "Änderung messen.",
                "Status der Server-Policy auf den in den Parametern "
                "hinterlegten Wert setzen.",
                "Ergebnis auslesen und mit dem Zielwert vergleichen.",
            ),
            "validation": (
                "Die Server-Policy trägt den gewünschten Status.",
                "Der veröffentlichte Dienst verhält sich wie beabsichtigt "
                "(erreichbar bzw. bewusst offline).",
                "Die Änderung ist in der Änderungshistorie verzeichnet.",
            ),
        },
        "en": {
            "label": "Enable / disable a server policy",
            "purpose": (
                "Scheduled enable or disable of one server policy on the "
                "target appliance - a cutover, or a planned pause of a "
                "published service. The write goes through the standard write "
                "path with snapshot, change history and audit entry."),
            "justification": (
                "Disabling a server policy deliberately takes the service "
                "behind it off the network. That is customer-visible and "
                "therefore belongs in an announced window."),
            "impact": (
                "Exactly the server policy named in the parameters is "
                "affected. On a disable the published service is unreachable "
                "from the moment it is switched; existing sessions are "
                "dropped. Other policies on the same appliance keep "
                "running."),
            "downtime": (
                "switch-over under one minute; on a disable, however, the "
                "affected service stays fully offline until it is re-enabled"),
            "risk": (
                "Main risks: the wrong policy is named; re-enabling is "
                "forgotten after a disable; dependent services or third-party "
                "health checks fire. The appliance itself keeps running."),
            "rollback": (
                "Restore the original status of the server policy (invert the "
                "value that was set).",
                "Trace the change in the appliance change history and confirm "
                "the previous state.",
            ),
            "work": (
                "Read and record the current status of the named server "
                "policy.",
                "Measure the reachability of the published service before the "
                "change.",
                "Set the server policy status to the value recorded in the "
                "parameters.",
                "Read the result back and compare it with the target value.",
            ),
            "validation": (
                "The server policy carries the intended status.",
                "The published service behaves as intended (reachable, or "
                "deliberately offline).",
                "The change is present in the change history.",
            ),
        },
    },
    # ----------------------------------------------------- backend_set_status
    "backend_set_status": {
        "de": {
            "label": "Backend (Pool-Member) aktivieren / deaktivieren",
            "purpose": (
                "Geplantes Ein- oder Ausschalten eines Real Servers in einem "
                "Server-Pool — typischerweise, um ein Backend für Wartung aus "
                "der Verteilung zu nehmen oder es planmäßig zurückzuholen."),
            "justification": (
                "Das Herausnehmen eines Pool-Members verändert die "
                "verfügbare Kapazität hinter einem veröffentlichten Dienst "
                "und ist damit ein kundenwirksamer Eingriff."),
            "impact": (
                "Der veröffentlichte Dienst bleibt erreichbar, solange "
                "mindestens ein weiteres Backend im Pool aktiv ist. "
                "Bestehende Sitzungen auf dem herausgenommenen Backend werden "
                "beendet; die verbleibenden Backends tragen die volle Last. "
                "Ist es das letzte aktive Member, fällt der Dienst aus."),
            "downtime": (
                "Umschaltung unter einer Minute; kein Dienstausfall, solange "
                "ein weiteres Backend im Pool aktiv bleibt"),
            "risk": (
                "Wesentliche Risiken: das letzte aktive Pool-Member wird "
                "herausgenommen; die verbleibende Kapazität reicht für die "
                "Last nicht aus; das Backend wird nach der Wartung nicht "
                "zurückgeholt."),
            "rollback": (
                "Ursprünglichen Status des Pool-Members wiederherstellen.",
                "Lastverteilung über den Pool erneut prüfen.",
            ),
            "work": (
                "Pool und Member aus den Parametern bestätigen und den "
                "Vorher-Status auslesen.",
                "Aktive Member des Pools zählen und die verbleibende "
                "Kapazität bewerten.",
                "Status des Pool-Members auf den hinterlegten Wert setzen.",
                "Verteilung und Erreichbarkeit des veröffentlichten Dienstes "
                "prüfen.",
            ),
            "validation": (
                "Das Pool-Member trägt den gewünschten Status.",
                "Der veröffentlichte Dienst antwortet weiterhin.",
                "Die Health-Checks der verbleibenden Backends sind grün.",
            ),
        },
        "en": {
            "label": "Enable / disable a backend (pool member)",
            "purpose": (
                "Scheduled enable or disable of one real server in a server "
                "pool - typically to drain a backend for maintenance or to "
                "bring it back on schedule."),
            "justification": (
                "Taking a pool member out changes the capacity available "
                "behind a published service and is therefore a "
                "customer-affecting change."),
            "impact": (
                "The published service stays reachable as long as at least "
                "one other backend in the pool is active. Existing sessions "
                "on the drained backend are dropped and the remaining "
                "backends carry the full load. If it is the last active "
                "member, the service goes down."),
            "downtime": (
                "switch-over under one minute; no service outage as long as "
                "another backend in the pool stays active"),
            "risk": (
                "Main risks: the last active pool member is taken out; the "
                "remaining capacity does not carry the load; the backend is "
                "never brought back after the maintenance."),
            "rollback": (
                "Restore the original status of the pool member.",
                "Re-check load distribution across the pool.",
            ),
            "work": (
                "Confirm pool and member from the parameters and read the "
                "current status.",
                "Count the active members of the pool and assess the "
                "remaining capacity.",
                "Set the pool member status to the recorded value.",
                "Check distribution and reachability of the published "
                "service.",
            ),
            "validation": (
                "The pool member carries the intended status.",
                "The published service still answers.",
                "Health checks of the remaining backends are green.",
            ),
        },
    },
    # ----------------------------------------------------- backend_set_config
    "backend_set_config": {
        "de": {
            "label": "IP / Port eines Backends ändern",
            "purpose": (
                "Geplante Änderung von Adresse und/oder Port eines Real "
                "Servers in einem Server-Pool — ein Repointing des Backends "
                "auf ein anderes Ziel."),
            "justification": (
                "Das Umbiegen eines Backends verändert, wohin der "
                "veröffentlichte Dienst tatsächlich weiterleitet. Ein Fehler "
                "hier leitet Kundenverkehr auf ein falsches Ziel und gehört "
                "deshalb in ein kontrolliertes Fenster."),
            "impact": (
                "Verbindungen zum bisherigen Ziel werden beendet; neue "
                "Verbindungen gehen unmittelbar an das neue Ziel. Ist das "
                "neue Ziel nicht bereit, fällt dieses Backend aus der "
                "Verteilung und der Dienst verliert Kapazität."),
            "downtime": (
                "Umschaltung unter einer Minute; darüber hinaus nur, wenn das "
                "neue Ziel nicht antwortet"),
            "risk": (
                "Wesentliche Risiken: falsche Adresse oder falscher Port; das "
                "neue Ziel ist noch nicht erreichbar oder filtert den "
                "Zugriff; der Health-Check schlägt fehl und das Backend "
                "bleibt außen vor."),
            "rollback": (
                "Ursprüngliche Adresse und ursprünglichen Port des "
                "Pool-Members wiederherstellen.",
                "Health-Check des Pool-Members erneut prüfen.",
            ),
            "work": (
                "Vorher-Werte (Adresse, Port) des Pool-Members auslesen und "
                "festhalten.",
                "Erreichbarkeit des NEUEN Ziels vorab prüfen.",
                "Adresse und/oder Port des Pool-Members auf die hinterlegten "
                "Werte setzen.",
                "Health-Check und Verteilung nach der Änderung prüfen.",
            ),
            "validation": (
                "Das Pool-Member zeigt die neuen Werte.",
                "Der Health-Check des Pool-Members ist grün.",
                "Der veröffentlichte Dienst antwortet unverändert.",
            ),
        },
        "en": {
            "label": "Change a backend's IP / port",
            "purpose": (
                "Scheduled change of a real server's address and/or port in a "
                "server pool - repointing the backend at another target."),
            "justification": (
                "Repointing a backend changes where the published service "
                "actually forwards to. A mistake here sends customer traffic "
                "to the wrong target, so it belongs in a controlled window."),
            "impact": (
                "Connections to the old target are dropped; new connections "
                "go straight to the new one. If the new target is not ready "
                "this backend drops out of the pool and the service loses "
                "capacity."),
            "downtime": (
                "switch-over under one minute; longer only if the new target "
                "does not answer"),
            "risk": (
                "Main risks: wrong address or wrong port; the new target is "
                "not reachable yet or filters the access; the health check "
                "fails and the backend stays out of the pool."),
            "rollback": (
                "Restore the original address and port of the pool member.",
                "Re-check the pool member health check.",
            ),
            "work": (
                "Read and record the current address and port of the pool "
                "member.",
                "Verify the NEW target is reachable beforehand.",
                "Set the pool member address and/or port to the recorded "
                "values.",
                "Check the health check and the distribution after the "
                "change.",
            ),
            "validation": (
                "The pool member shows the new values.",
                "The pool member health check is green.",
                "The published service answers unchanged.",
            ),
        },
    },
    # -------------------------------------------------------- swap_certificate
    "swap_certificate": {
        "de": {
            "label": "Zertifikat einer Server-Policy tauschen",
            "purpose": (
                "Umstellung der an eine Server-Policy gebundenen lokalen "
                "Zertifikats-Referenz auf ein bereits auf der Appliance "
                "vorhandenes Zertifikat — der Bindungswechsel einer "
                "Zertifikatsrotation. Das neue Zertifikat wurde zuvor "
                "ausgestellt und ausgerollt; hier wird ausschließlich die "
                "Bindung umgestellt."),
            "justification": (
                "Der Bindungswechsel bestimmt, welches Zertifikat der Kunde "
                "im TLS-Handshake sieht. Er wird deshalb getrennt vom "
                "Ausstellen durchgeführt und in einem Fenster freigegeben."),
            "impact": (
                "Beim Umschalten werden laufende TLS-Handshakes kurz "
                "abgebrochen; Clients bauen die Verbindung neu auf. Ab dem "
                "Umschalten liefert die Server-Policy das neue Zertifikat "
                "aus. Passt es nicht zum angefragten Namen oder fehlt die "
                "Kette, quittieren Clients den Zugriff mit einem "
                "Zertifikatsfehler."),
            "downtime": (
                "unter einer Minute; kurzzeitiger Abbruch laufender "
                "TLS-Handshakes beim Umschalten"),
            "risk": (
                "Wesentliche Risiken: falsches oder abgelaufenes Zertifikat "
                "gebunden; unvollständige Zwischenzertifikatskette; die "
                "Namen im Zertifikat decken den veröffentlichten Namen nicht "
                "ab; gepinnte Clients lehnen das neue Zertifikat ab."),
            "rollback": (
                "Bisheriges Zertifikat wieder an die Server-Policy binden — "
                "es bleibt auf der Appliance erhalten und wird in diesem "
                "Change nicht gelöscht.",
                "TLS-Verbindung erneut prüfen und die ausgelieferte Kette "
                "bestätigen.",
            ),
            "work": (
                "Aktuell gebundenes Zertifikat der Server-Policy auslesen und "
                "festhalten.",
                "Neues Zertifikat auf der Appliance verifizieren: Namen, "
                "Laufzeit, vollständige Kette.",
                "Zertifikats-Bindung der Server-Policy auf das neue "
                "Zertifikat umstellen.",
                "TLS-Handshake gegen den veröffentlichten Namen prüfen und "
                "die ausgelieferte Kette vergleichen.",
            ),
            "validation": (
                "Die Server-Policy liefert das neue Zertifikat aus.",
                "Die ausgelieferte Zertifikatskette ist vollständig und "
                "gültig.",
                "Der veröffentlichte Dienst antwortet ohne "
                "Zertifikatswarnung.",
            ),
        },
        "en": {
            "label": "Swap a server-policy certificate",
            "purpose": (
                "Move the local certificate bound to a server policy to a "
                "certificate already present on the appliance - the binding "
                "step of a certificate rotation. The new certificate was "
                "issued and deployed earlier; only the binding changes "
                "here."),
            "justification": (
                "The binding decides which certificate the customer sees in "
                "the TLS handshake. It is therefore done separately from "
                "issuance and approved in a window."),
            "impact": (
                "TLS handshakes in flight are cut short at the moment of the "
                "switch; clients reconnect. From then on the server policy "
                "serves the new certificate. If it does not match the "
                "requested name, or the chain is incomplete, clients fail "
                "with a certificate error."),
            "downtime": (
                "under one minute; TLS handshakes in flight are briefly cut "
                "at the switch"),
            "risk": (
                "Main risks: the wrong or an expired certificate is bound; an "
                "incomplete intermediate chain; the names in the certificate "
                "do not cover the published name; pinned clients reject the "
                "new certificate."),
            "rollback": (
                "Bind the previous certificate to the server policy again - "
                "it stays on the appliance and is not deleted by this "
                "change.",
                "Re-check the TLS connection and confirm the served chain.",
            ),
            "work": (
                "Read and record the certificate currently bound to the "
                "server policy.",
                "Verify the new certificate on the appliance: names, "
                "validity, complete chain.",
                "Move the server policy certificate binding to the new "
                "certificate.",
                "Test the TLS handshake against the published name and "
                "compare the served chain.",
            ),
            "validation": (
                "The server policy serves the new certificate.",
                "The served certificate chain is complete and valid.",
                "The published service answers with no certificate warning.",
            ),
        },
    },
    # ---------------------------------------------------------- cert_lifecycle
    "cert_lifecycle": {
        "de": {
            "label": "Zertifikats-Lebenszyklus (Sperren + Aufräumen)",
            "purpose": (
                "Durchsetzung der konfigurierten Zertifikats-Lebenszyklus"
                "richtlinie: abgelöste Zertifikate nach Ablauf der Karenzzeit "
                "an der CA sperren und gesperrtes, abgelöstes oder "
                "abgelaufenes und NICHT gebundenes Zertifikatsmaterial von "
                "der Appliance entfernen."),
            "justification": (
                "Abgelöstes Schlüsselmaterial, das auf der Appliance liegen "
                "bleibt, bleibt verwendbar. Die Bereinigung ist Teil der "
                "Aufbewahrungsvorgabe und wird nachvollziehbar in einem "
                "Fenster ausgeführt."),
            "impact": (
                "Es werden ausschließlich Zertifikate angefasst, die zum "
                "Zeitpunkt der Ausführung nachweislich an KEINE Server-Policy "
                "gebunden sind; die Bindungsprüfung erfolgt unmittelbar vor "
                "dem Löschen und ist fail-closed. Aktiv genutzte Zertifikate "
                "bleiben unberührt, veröffentlichte Dienste laufen weiter. "
                "Eine Sperrung an der CA ist jedoch nicht rückholbar."),
            "downtime": (
                "keine geplante Unterbrechung — gebundene Zertifikate werden "
                "nicht angefasst"),
            "risk": (
                "Wesentliches Risiko: ein noch benötigtes Zertifikat wird "
                "gesperrt, weil eine Bindung außerhalb der Appliance besteht "
                "(externe Systeme, Client-Authentisierung). Eine Sperrung ist "
                "nicht rückgängig zu machen — betroffene Gegenstellen "
                "benötigen dann ein neu ausgestelltes Zertifikat."),
            "rollback": (
                "Gelöschtes Zertifikatsmaterial aus dem Konfigurations-Backup "
                "der Appliance wiederherstellen.",
                "Eine an der CA ausgesprochene Sperrung ist NICHT "
                "rückabwickelbar: betroffene Zertifikate müssen neu "
                "ausgestellt und ausgerollt werden.",
            ),
            "work": (
                "Lebenszyklus-Lauf im Berichtsmodus ausführen und die "
                "vorgeschlagene Liste prüfen.",
                "Bindungen der betroffenen Zertifikate live gegenprüfen.",
                "Sperrungen an der CA für abgelöste Zertifikate nach Ablauf "
                "der Karenzzeit ausführen.",
                "Nicht gebundenes gesperrtes, abgelöstes bzw. abgelaufenes "
                "Material von der Appliance entfernen.",
                "Ergebnisliste dem Change Request beilegen.",
            ),
            "validation": (
                "Alle veröffentlichten Dienste antworten unverändert mit "
                "gültigem Zertifikat.",
                "Kein aktiv gebundenes Zertifikat wurde gesperrt oder "
                "gelöscht.",
                "Die Ergebnisliste ist dokumentiert und stimmt mit dem "
                "Berichtslauf überein.",
            ),
        },
        "en": {
            "label": "Cert Manager - lifecycle sweep (revoke + cleanup)",
            "purpose": (
                "Enforce the configured certificate lifecycle policy: revoke "
                "superseded certificates at the CA once past the grace "
                "window, and delete revoked, superseded or expired "
                "certificate material that is NOT bound from the appliance."),
            "justification": (
                "Superseded key material left on the appliance stays usable. "
                "Cleaning it up is part of the retention contract and is done "
                "traceably inside a window."),
            "impact": (
                "Only certificates proven to be bound to NO server policy at "
                "execution time are touched; the binding check runs "
                "immediately before the delete and is fail-closed. "
                "Certificates in use are untouched and published services "
                "keep running. A revocation at the CA, however, cannot be "
                "taken back."),
            "downtime": (
                "no planned interruption - bound certificates are not "
                "touched"),
            "risk": (
                "Main risk: a certificate that is still needed gets revoked "
                "because it is bound somewhere outside the appliance "
                "(external systems, client authentication). A revocation "
                "cannot be undone - the affected peers then need a newly "
                "issued certificate."),
            "rollback": (
                "Restore deleted certificate material from the appliance "
                "configuration backup.",
                "A revocation issued at the CA can NOT be undone: affected "
                "certificates have to be re-issued and re-deployed.",
            ),
            "work": (
                "Run the lifecycle sweep in report-only mode and review the "
                "proposed list.",
                "Re-verify the bindings of the affected certificates live.",
                "Revoke superseded certificates at the CA once past the grace "
                "window.",
                "Delete unbound revoked / superseded / expired material from "
                "the appliance.",
                "Attach the result list to the change request.",
            ),
            "validation": (
                "All published services still answer with a valid "
                "certificate.",
                "No actively bound certificate was revoked or deleted.",
                "The result list is documented and matches the report run.",
            ),
        },
    },
    # -------------------------------------------------------------- custom_rest
    "custom_rest": {
        "de": {
            "label": "Freier REST-Aufruf",
            "purpose": (
                "Ausführung eines im Change Request frei definierten "
                "REST-Aufrufs gegen die Zielgeräte. WAS dieser Change "
                "bewirkt, ergibt sich ausschließlich aus dem in Abschnitt 9 "
                "wörtlich abgedruckten Aufruf — SATOM kann daraus keine "
                "fachliche Absicht ableiten und behauptet hier keine."),
            "justification": (
                "Der Aufruf ist frei definiert und damit nicht durch einen "
                "geprüften Standardablauf abgedeckt. Genau deshalb wird er "
                "einzeln freigegeben: der Prüfer bewertet den konkreten "
                "Aufruf, nicht eine Kategorie."),
            "impact": (
                "Die Auswirkung ist per Definition UNBEKANNT. Ein lesender "
                "Aufruf (GET) verändert nichts; ein schreibender Aufruf "
                "(POST/PUT/DELETE) verändert die Konfiguration der Zielgeräte "
                "in einem Umfang, der sich nur aus Endpunkt und Body ergibt. "
                "SATOM gibt hier bewusst KEINE Ausfallzeit an, weil jede "
                "Angabe geraten wäre. Der Prüfer muss den Aufruf in "
                "Abschnitt 9 selbst bewerten und die erwartete Auswirkung "
                "vor der Freigabe schriftlich ergänzen."),
            "downtime": (
                "unbekannt — nicht abschätzbar; vom Prüfer anhand des "
                "Aufrufs in Abschnitt 9 zu bestimmen"),
            "risk": (
                "Das Risiko ergibt sich vollständig aus dem konkreten "
                "Aufruf. Schreibende Aufrufe laufen über den "
                "Standard-Schreibpfad mit Snapshot, Änderungshistorie und "
                "Audit-Eintrag; die Neustart-URN ist ausdrücklich gesperrt. "
                "Ein Aufruf ohne erkennbaren Endpunkt ist nicht prüfbar und "
                "darf nicht freigegeben werden."),
            "rollback": (
                "Bei einem lesenden Aufruf ist kein Rollback erforderlich.",
                "Bei einem schreibenden Aufruf: den vor dem Schreiben "
                "erstellten Snapshot der betroffenen Objekte zurückschreiben.",
                "Änderungshistorie der Appliance auf den Vorher-Zustand "
                "prüfen; ersatzweise Konfiguration aus dem Backup "
                "wiederherstellen.",
            ),
            "work": (
                "Den unten wörtlich abgedruckten Aufruf gegen die Zielgeräte "
                "prüfen und bestätigen.",
                "Bei schreibendem Aufruf zuerst als Trockenlauf ausführen und "
                "das Ergebnis bewerten.",
                "Aufruf gegen jedes Zielgerät ausführen (Snapshot, "
                "Änderungshistorie und Audit-Eintrag werden dabei "
                "geschrieben).",
                "Antwort je Gerät festhalten und dem Change Request "
                "beilegen.",
            ),
            "validation": (
                "Die Antwort je Gerät entspricht der im Change Request "
                "beschriebenen Erwartung.",
                "Bei schreibendem Aufruf: die veränderten Objekte werden "
                "erneut ausgelesen und dokumentiert.",
                "Alle unten gelisteten veröffentlichten Dienste antworten wie "
                "vor dem Change.",
            ),
        },
        "en": {
            "label": "Custom REST call",
            "purpose": (
                "Execute a REST call defined freely on the change request "
                "against the target devices. WHAT this change does follows "
                "only from the call printed verbatim in section 9 - SATOM "
                "cannot derive an intent from it and does not claim one "
                "here."),
            "justification": (
                "The call is freely defined and therefore not covered by a "
                "reviewed standard procedure. That is exactly why it is "
                "approved individually: the reviewer judges the concrete "
                "call, not a category."),
            "impact": (
                "The impact is UNKNOWN by definition. A read call (GET) "
                "changes nothing; a write call (POST/PUT/DELETE) changes the "
                "configuration of the target devices to an extent that "
                "follows only from the endpoint and the body. SATOM "
                "deliberately states NO downtime here, because any figure "
                "would be a guess. The reviewer must assess the call in "
                "section 9 and write down the expected impact before "
                "approving."),
            "downtime": (
                "unknown - cannot be estimated; to be determined by the "
                "reviewer from the call in section 9"),
            "risk": (
                "The risk follows entirely from the concrete call. Write "
                "calls go through the standard write path with snapshot, "
                "change history and audit entry; the reboot URN is refused "
                "outright. A call with no recognisable endpoint cannot be "
                "reviewed and must not be approved."),
            "rollback": (
                "For a read call no rollback is needed.",
                "For a write call: restore the snapshot of the affected "
                "objects taken before the write.",
                "Check the appliance change history against the previous "
                "state; failing that, restore the configuration from the "
                "backup.",
            ),
            "work": (
                "Review and confirm the call printed verbatim below against "
                "the target devices.",
                "For a write call, run it as a dry run first and assess the "
                "result.",
                "Execute the call against each target device (snapshot, "
                "change history and audit entry are written).",
                "Record the response per device and attach it to the change "
                "request.",
            ),
            "validation": (
                "The response per device matches the expectation described on "
                "the change request.",
                "For a write call: the changed objects are read back and "
                "documented.",
                "Every published service listed below answers as it did "
                "before the change.",
            ),
        },
    },
    # ---------------------------------------------------------------- generic
    GENERIC_ACTION: {
        "de": {
            "label": "Nicht profilierte Aktion",
            "purpose": (
                "Für diese Aktion liegt in SATOM kein eigener Textbaustein "
                "vor. Ziel und Umfang des Changes sind vom Antragsteller vor "
                "der Freigabe schriftlich zu ergänzen; die im Change Request "
                "hinterlegten Parameter stehen in Abschnitt 9."),
            "justification": (
                "Der Change wird über SATOM gesteuert und ist damit "
                "protokolliert, an ein Wartungsfenster gebunden und "
                "freigabepflichtig. Die fachliche Begründung ergibt sich aus "
                "dem Text des Antragstellers in diesem Abschnitt."),
            "impact": (
                "Die Auswirkung ist für diese Aktion nicht hinterlegt "
                "(— nicht erfasst) und wird nicht geraten. Sie ist vor der "
                "Freigabe zu ergänzen; die betroffenen veröffentlichten "
                "Dienste sind in Abschnitt 10 aufgeführt."),
            "downtime": (
                "nicht erfasst — vom Antragsteller vor der Freigabe zu "
                "ergänzen"),
            "risk": (
                "Für diese Aktion ist keine Risikobetrachtung hinterlegt "
                "(— nicht erfasst). Es gilt die im Change Request "
                "eingetragene Einstufung; die konkreten Fehlerbilder sind vor "
                "der Freigabe zu beschreiben."),
            "rollback": (
                "Vor Beginn ein Konfigurations-Backup der Zielgeräte "
                "erstellen.",
                "Im Fehlerfall den Vorher-Zustand aus Snapshot bzw. "
                "Änderungshistorie wiederherstellen.",
                "Veröffentlichte Dienste erneut prüfen, bevor das Fenster "
                "geschlossen wird.",
            ),
            "work": (
                "Konfigurations-Backup der Zielgeräte erstellen.",
                "Ausgangszustand der betroffenen Objekte festhalten.",
                "Aktion mit den unten aufgeführten Parametern ausführen.",
                "Ergebnis auslesen und dokumentieren.",
            ),
            "validation": (
                "Die veränderten Objekte tragen den beabsichtigten Zustand.",
                "Alle unten gelisteten veröffentlichten Dienste antworten wie "
                "vor dem Change.",
                "Die Änderung ist in der Änderungshistorie verzeichnet.",
            ),
        },
        "en": {
            "label": "Action without a profile",
            "purpose": (
                "SATOM has no dedicated text for this action. The purpose and "
                "scope of the change must be written down by the requester "
                "before approval; the parameters recorded on the change "
                "request are in section 9."),
            "justification": (
                "The change is driven through SATOM and is therefore logged, "
                "bound to a maintenance window and subject to approval. The "
                "business justification is the requester's text in this "
                "section."),
            "impact": (
                "No impact statement is recorded for this action (— not "
                "recorded) and none is guessed. It must be added before "
                "approval; the affected published services are listed in "
                "section 10."),
            "downtime": (
                "not recorded - to be supplied by the requester before "
                "approval"),
            "risk": (
                "No risk assessment is recorded for this action (— not "
                "recorded). The rating entered on the change request applies; "
                "the concrete failure modes must be described before "
                "approval."),
            "rollback": (
                "Take a configuration backup of the target devices before "
                "starting.",
                "On failure restore the previous state from the snapshot or "
                "the change history.",
                "Re-probe the published services before closing the window.",
            ),
            "work": (
                "Take a configuration backup of the target devices.",
                "Record the baseline of the affected objects.",
                "Execute the action with the parameters listed below.",
                "Read back and document the result.",
            ),
            "validation": (
                "The changed objects carry the intended state.",
                "Every published service listed below answers as it did "
                "before the change.",
                "The change is present in the change history.",
            ),
        },
    },
}


# --------------------------------------------------------------------------- #
#  Translated languages                                                         #
# --------------------------------------------------------------------------- #
class _Localized(dict):
    """An authored ``{lang: ...}`` block that can also answer for a TRANSLATED
    language, by overlaying the catalogue onto the English structure.

    ``__missing__`` rather than an explicit lookup at each of the twenty call
    sites: twenty edits is twenty chances to miss one, and the one that is
    missed does not fail -- it quietly prints English inside an otherwise
    Spanish document.  The shape (str vs tuple) always comes from the authored
    English, so a translation can change the words and never the structure.
    """

    __slots__ = ("_prefix",)

    def __init__(self, mapping, prefix: str):
        super().__init__(mapping)
        self._prefix = prefix

    def __missing__(self, lang):
        from . import cr_i18n
        table = cr_i18n.cached_texts(lang)
        if not table:
            raise KeyError(lang)
        built = cr_i18n.overlay(self[langs.DEFAULT], self._prefix, table)
        return built


def _localize_all() -> None:
    """Wrap the authored blocks once, after their literals are defined."""
    global SECTION_TITLES, _T, _DRAFT, ACTION_PROFILES
    SECTION_TITLES = _Localized(SECTION_TITLES, "titles")
    _T = _Localized(_T, "t")
    _DRAFT = _Localized(_DRAFT, "draft")
    ACTION_PROFILES = {key: _Localized(block, f"profile.{key}")
                       for key, block in ACTION_PROFILES.items()}


def profile_for(action) -> dict:
    """The per-language profile for ``action``.

    Falls back to the generic profile for an unknown/blank key and never
    raises: a new action key added to the registry must still print a
    document, and an incomplete one is better than a KeyError in front of an
    approver waiting for paper.
    """
    try:
        key = str(action or "").strip()
    except Exception:  # noqa: BLE001
        key = ""
    profile = ACTION_PROFILES.get(key)
    if not isinstance(profile, dict):
        return ACTION_PROFILES[GENERIC_ACTION]
    return profile


def _lang_block(profile, lang: str) -> dict:
    """One language out of a :class:`_Localized` block, overlay included.

    Subscription, never ``.get()``.  ``dict.get`` does NOT call
    ``__missing__``, so asking a ``_Localized`` block for a TRANSLATED
    language with ``.get()`` answers ``None`` no matter how complete the
    catalogue is -- the overlay that exists to build that language is never
    reached.  The failure is silent while the language is gated (the block
    degrades to English) and becomes a ``KeyError`` in front of an approver
    the moment the catalogue completes, which is exactly the wrong order to
    learn about it.
    """
    try:
        block = profile[lang]
    except (KeyError, TypeError):
        # No catalogue for this language.  Degrade to the AUTHORED English,
        # never to a blank: an empty profile does not print an empty section,
        # it raises on the first key the renderer reads.  The gate upstream
        # means this branch should be unreachable in production — which is
        # exactly why it must not be the branch that turns a gate bug into a
        # 500 in front of an approver.
        try:
            block = profile[langs.DEFAULT]
        except (KeyError, TypeError):
            return {}
    return block if isinstance(block, dict) else {}


def _profile_text(action, lang: str) -> dict:
    """The profile of ``action`` in ``lang``, degrading to the generic one."""
    block = _lang_block(profile_for(action), lang)
    if not block:
        block = _lang_block(ACTION_PROFILES[GENERIC_ACTION], lang)
    return block


# --------------------------------------------------------------------------- #
#  Identity + filename                                                          #
# --------------------------------------------------------------------------- #
def change_ref(cr) -> str:
    """The human change reference, e.g. ``CR-2026-0042``.

    Uses ``cr.ref`` when the record carries one (some installs mirror an
    external reference there); otherwise it is derived from the creation year
    and the zero-padded id. A record with no creation timestamp gets year
    ``0000`` rather than this year's — an invented year on a change reference
    is a filing error waiting to happen.
    """
    explicit = str(getattr(cr, "ref", "") or "").strip()
    if explicit:
        return explicit
    created = getattr(cr, "created_at", None) or getattr(cr, "window_start", None)
    year = getattr(created, "year", None)
    try:
        year_txt = "%04d" % int(year)
    except (TypeError, ValueError):
        year_txt = "0000"
    try:
        num = int(getattr(cr, "id", 0) or 0)
    except (TypeError, ValueError):
        num = 0
    return f"CR-{year_txt}-{num:04d}"


def _ascii_slug(value: str) -> str:
    """ASCII, filesystem-safe, no spaces. Umlauts transliterate, everything
    else outside ``[A-Za-z0-9._-]`` collapses to a single dash."""
    text = str(value or "")
    for src, dst in (("ä", "ae"), ("ö", "oe"), ("ü", "ue"), ("Ä", "Ae"),
                     ("Ö", "Oe"), ("Ü", "Ue"), ("ß", "ss")):
        text = text.replace(src, dst)
    text = unicodedata.normalize("NFKD", text)
    text = text.encode("ascii", "ignore").decode("ascii")
    text = re.sub(r"[^A-Za-z0-9._-]+", "-", text)
    text = re.sub(r"-{2,}", "-", text).strip("-._")
    return text


def filename(cr, lang) -> str:
    """A safe ASCII filename for the rendered document, e.g.
    ``CR-2026-0042-de.md``.

    The reference is sanitised because ``cr.ref`` is free text: a reference
    pasted in as ``CR/2026 #42`` must not turn into a path separator when the
    document is written to disk or offered as a download.
    """
    code = normalize_lang(lang)
    ref = _ascii_slug(change_ref(cr)) or "CR-0000-0000"
    return f"{ref}-{code}.md"


# --------------------------------------------------------------------------- #
#  Formatting helpers (no DB, no request context)                               #
# --------------------------------------------------------------------------- #
_TZ_TOKEN = re.compile(r"(?:[A-Za-z]{2,6}|[+-]\d{2}:?\d{2})$")


def _has_tz(text: str) -> bool:
    return bool(_TZ_TOKEN.search((text or "").strip()))


def _utc_fallback(value, fmt: str) -> str:
    """Last-resort stamp that STILL names its timezone.

    Reached when :func:`settings_store.to_local` cannot reach the settings row
    (no app context, e.g. a CLI export or a test). The stored datetimes in this
    product are naive UTC, so they are labelled UTC — never printed bare, which
    would read as local time and misstate a window by the offset.
    """
    base = fmt.replace("%Z", "").replace("%z", "").rstrip()
    try:
        if hasattr(value, "strftime"):
            text = value.strftime(base).strip()
            tz = ""
            try:
                tz = (value.strftime("%Z") or "").strip()
            except Exception:  # noqa: BLE001
                tz = ""
            return f"{text} {tz or 'UTC'}".strip()
    except Exception:  # noqa: BLE001
        pass
    text = str(value).strip()
    return text if _has_tz(text) else f"{text} UTC"


def _stamp(value, lang: str, fmt: str = "%Y-%m-%d %H:%M %Z") -> str:
    """Format one datetime through the product's ONE conversion path.

    :func:`app.services.settings_store.to_local` is imported LAZILY so this
    module keeps importing with no app context and no DB. Any failure (or a
    result that lost its timezone abbreviation, which is what a naive
    ``strftime`` fallback inside ``to_local`` produces) degrades to an explicit
    UTC stamp instead of a bare wall-clock time.
    """
    if value in (None, ""):
        return _T[lang]["placeholder"]
    text = ""
    try:
        try:
            from . import settings_store          # in-package (house style)
        except ImportError:  # pragma: no cover - flat/scratch layouts
            from app.services import settings_store  # type: ignore
        text = str(settings_store.to_local(value, fmt) or "").strip()
    except Exception:  # noqa: BLE001 - printing must not depend on a context
        text = ""
    if text and text != "—" and _has_tz(text):
        return text
    return _utc_fallback(value, fmt)


def _val(value, lang: str) -> str:
    """A single-line value, or the explicit placeholder for anything empty."""
    if value is None:
        return _T[lang]["placeholder"]
    text = str(value).strip()
    if not text:
        return _T[lang]["placeholder"]
    return text


def _cell(value, lang: str) -> str:
    """A value safe to drop into a GitHub-style table cell."""
    text = _val(value, lang)
    return text.replace("|", r"\|").replace("\n", " ").replace("\r", " ")


def _json_list(raw) -> list:
    try:
        value = json.loads(raw or "[]")
        return value if isinstance(value, list) else []
    except (ValueError, TypeError):
        return []


def _cr_policies(cr) -> list:
    """The CR's OWN frozen policy snapshot (``ChangeRequest.policies``)."""
    return [row for row in _json_list(getattr(cr, "policies", "[]"))
            if isinstance(row, dict)]


def _cr_device_ids(cr) -> list:
    ids = getattr(cr, "device_ids_list", None)
    if isinstance(ids, list):
        return ids
    return _json_list(getattr(cr, "device_ids", "[]"))


def _cr_params(cr) -> dict:
    params = getattr(cr, "params_dict", None)
    if isinstance(params, dict):
        return params
    try:
        value = json.loads(getattr(cr, "params", "") or "{}")
        return value if isinstance(value, dict) else {}
    except (ValueError, TypeError):
        return {}


def _recipients(cr) -> list:
    """``notify_to`` split the way the mailer splits it — locally, because
    ``email_service.parse_recipients`` reads settings and this must not."""
    raw = str(getattr(cr, "notify_to", "") or "")
    parts = re.split(r"[,;\s]+", raw)
    return [p.strip() for p in parts if p.strip()]


def _table(header: tuple, rows: list) -> list:
    """A GitHub-style table that still reads as plain text in an email."""
    out = ["| " + " | ".join(header) + " |",
           "|" + "|".join([" --- "] * len(header)) + "|"]
    for row in rows:
        out.append("| " + " | ".join(row) + " |")
    return out


def _checkbox(done: bool, text: str) -> str:
    return f"- [{'x' if done else ' '}] {text}"


def _numbered(items) -> list:
    return [f"{i}. {text}" for i, text in enumerate(items, start=1)]


def _bullets(items) -> list:
    return [f"- {text}" for text in items]


# --------------------------------------------------------------------------- #
#  Renderer                                                                     #
# --------------------------------------------------------------------------- #
def render(cr, *, lang: str = "en", devices=None, policies=None,
           prep=None, profile=None) -> str:
    """Render the 13-section change-request document as Markdown.

    PURE: no DB access, no device call, no Flask request context, no live
    read of any kind. Everything printed comes from the arguments — see the
    module docstring for why that is a correctness property of the document
    and not a preference.

    :param cr: a :class:`~app.models.ChangeRequest` (or anything exposing the
        same attributes — nothing here requires the ORM).
    :param lang: ``"en"`` or ``"de"``; anything else falls back to
        :data:`DEFAULT_LANG`.
    :param devices: the FROZEN device inventory: objects with ``.name``,
        ``.kind``, ``.host`` and optionally ``.firmware`` / ``.adom``. ``None``
        prints the recorded device ids and says the inventory was not supplied.
    :param policies: the FROZEN published-service inventory, rows shaped
        ``{device, device_id, policy, vserver, service, status}``. ``None``
        falls back to the CR's own stored snapshot (``cr.policies``), which is
        equally frozen; ``[]`` means "explicitly none".
    :param prep: the dict returned by
        :func:`app.services.upgrade.prepare`, or ``None``.
    :param profile: the change-type prose to print, already resolved by the
        caller (:func:`app.services.cr_types.profile_text`, or the snapshot
        frozen on the record at approval). ``None`` means "use the wording
        compiled into this module". It is a PARAMETER and not a lookup because
        this module must not read the database: a document that queried at
        print time would print today's wording under yesterday's signature.
        Missing keys fall back to the compiled profile, so a partial override
        can never blank a section.
    """
    lang = normalize_lang(lang)
    t = _T[lang]
    titles = SECTION_TITLES[lang]
    action = str(getattr(cr, "action", "") or "").strip()
    p = dict(_profile_text(action, lang))
    if isinstance(profile, dict):
        # Overlay, never replace: a caller handing in one corrected paragraph
        # must not cost the document the other eleven.
        for _k, _v in profile.items():
            if _v not in (None, "", (), []):
                p[_k] = _v
    ph = t["placeholder"]

    devices = list(devices) if devices is not None else None
    rows = list(policies) if policies is not None else _cr_policies(cr)
    out: list[str] = []

    def head(index: int) -> None:
        out.append("")
        out.append(f"## {index}. {titles[index - 1]}")
        out.append("")

    # ---- document head ----------------------------------------------------
    ref = change_ref(cr)
    title = _val(getattr(cr, "title", ""), lang)
    out.append(f"# {ref} — {title}")
    out.append("")
    status_raw = str(getattr(cr, "status", "") or "").strip()
    status_txt = t["status_labels"].get(status_raw, status_raw or ph)
    out.append(f"*SATOM — {t['doc_kind']} · {p['label']} · {status_txt}*")
    out.append("")
    out.append(t["tz_note"])

    # ---- 1. General information -------------------------------------------
    head(1)
    action_cell = f"{p['label']} (`{action}`)" if action else ph
    info_rows = [
        (t["f_change_id"], f"**{_cell(ref, lang)}**"),
        (t["f_title"], _cell(getattr(cr, "title", ""), lang)),
        (t["f_status"], _cell(status_txt, lang)),
        (t["f_action"], _cell(action_cell, lang)),
        (t["f_requester"], _cell(getattr(cr, "requested_by", ""), lang)),
        (t["f_owner"], _cell(getattr(cr, "owner", ""), lang)),
        (t["f_window_date"],
         _cell(_stamp(getattr(cr, "window_start", None), lang, "%Y-%m-%d %Z"), lang)),
        (t["f_window_start"],
         _cell(_stamp(getattr(cr, "window_start", None), lang), lang)),
        (t["f_window_end"],
         _cell(_stamp(getattr(cr, "window_end", None), lang), lang)),
    ]
    risk_raw = str(getattr(cr, "risk", "") or "").strip().lower()
    risk_txt = t["risk_labels"].get(risk_raw)
    risk_cell = risk_txt if risk_txt else (f"{ph} (`{risk_raw}`)" if risk_raw else ph)
    info_rows.append((t["f_risk"], _cell(risk_cell, lang)))
    crq = str(getattr(cr, "crq_ref", "") or "").strip()
    crq_url = str(getattr(cr, "crq_url", "") or "").strip()
    info_rows.append((t["f_crq"],
                      _cell(f"{crq} ({crq_url})" if crq and crq_url else (crq or ph), lang)))
    info_rows.append((t["f_doc_state"],
                      _cell(_stamp(getattr(cr, "updated_at", None), lang), lang)))
    out += _table((t["col_field"], t["col_value"]),
                  [(a, b) for a, b in info_rows])
    out.append("")
    # The footnote explains an ABSENCE. Printing it next to a filled-in owner
    # would tell the reader the field is unreliable when it is not.
    if not str(getattr(cr, "owner", "") or "").strip():
        out.append(t["owner_note"])

    # ---- 2. Purpose --------------------------------------------------------
    head(2)
    out.append(p["purpose"])

    # ---- 3. Affected systems ----------------------------------------------
    head(3)
    if devices:
        drows = []
        for d in devices:
            drows.append((
                _cell(getattr(d, "name", ""), lang),
                _cell(getattr(d, "kind", ""), lang),
                _cell(getattr(d, "firmware", "") or "", lang),
                _cell(getattr(d, "host", ""), lang),
                _cell(getattr(d, "adom", "") or getattr(d, "site", "") or "", lang),
            ))
        out += _table((t["d_name"], t["d_kind"], t["d_firmware"], t["d_host"],
                       t["d_adom"]), drows)
    else:
        ids = _cr_device_ids(cr)
        if ids:
            out.append(t["no_devices"] % ", ".join(str(i) for i in ids))
        else:
            out.append(t["no_device_ids"])
    out.append("")
    out.append(t["frozen_note"])

    # ---- 4. Justification --------------------------------------------------
    head(4)
    reason = str(getattr(cr, "reason", "") or "").strip()
    out.append(f"**{t['reason_head']}:**")
    out.append("")
    out.append(f"> {reason}" if reason else t["no_reason"])
    out.append("")
    out.append(p["justification"])

    # ---- 5. Impact ---------------------------------------------------------
    head(5)
    out.append(p["impact"])
    out.append("")
    out.append(f"**{t['downtime_label']}:** {p['downtime']}")
    out.append("")
    out.append(t["services_count"] % (len(rows) if rows else ph))

    # ---- 6. Risk analysis --------------------------------------------------
    head(6)
    out.append(f"**{t['risk_label']}:** {risk_cell}")
    out.append("")
    out.append(p["risk"])

    # ---- 7. Rollback plan --------------------------------------------------
    head(7)
    rollback = str(getattr(cr, "rollback", "") or "").strip()
    out.append(f"**{t['rollback_own']}:**")
    out.append("")
    out.append(f"> {rollback}" if rollback else t["no_rollback"])
    out.append("")
    out.append(f"**{t['rollback_fixed']}:**")
    out.append("")
    out += _numbered(p["rollback"])

    # ---- 8. Prerequisites --------------------------------------------------
    head(8)
    out += _prerequisites(cr, lang, prep, action)

    # ---- 9. Work to be performed ------------------------------------------
    head(9)
    out += _numbered(p["work"])
    out.append("")
    out += _work_params(cr, lang, action)

    # ---- 10. Post-change validation ---------------------------------------
    head(10)
    out += _numbered(p["validation"])
    out.append("")
    out.append(f"**{t['pol_head']}:**")
    out.append("")
    if rows:
        prows = []
        for row in rows:
            row = row if isinstance(row, dict) else {}
            prows.append((
                _cell(row.get("device", ""), lang),
                _cell(row.get("policy", ""), lang),
                _cell(row.get("vserver", ""), lang),
                _cell(row.get("service", ""), lang),
                _cell(row.get("status", ""), lang),
            ))
        out += _table((t["pol_device"], t["pol_policy"], t["pol_vserver"],
                       t["pol_service"], t["pol_status"]), prows)
    else:
        out.append(t["no_policies"])

    # ---- 11. Communication plan -------------------------------------------
    head(11)
    recipients = _recipients(cr)
    if recipients:
        out.append(f"**{t['comm_recipients']}:** " + ", ".join(recipients))
    else:
        out.append(t["comm_no_recipients"])
    out.append("")
    notify_raw = str(getattr(cr, "notify_status", "") or "").strip().lower()
    notify_txt = t["notify_labels"].get(notify_raw, notify_raw or ph)
    out.append(f"**{t['comm_status']}:** {notify_txt}")
    out.append("")
    out.append(f"**{t['comm_final']}:** "
               f"{_stamp(getattr(cr, 'final_notified_at', None), lang)}")
    out.append("")
    out.append(f"**{t['comm_steps']}:**")
    out.append("")
    out += _numbered((t["comm_1"], t["comm_2"], t["comm_3"], t["comm_4"]))

    # ---- 12. Approvals -----------------------------------------------------
    head(12)
    out += _approvals(cr, lang)

    # ---- 13. Change outcome ------------------------------------------------
    head(13)
    out += _outcome(cr, lang, status_raw)

    out.append("")
    return "\n".join(out).rstrip() + "\n"


# --------------------------------------------------------------------------- #
#  Section builders                                                             #
# --------------------------------------------------------------------------- #
def _probe_counts(services) -> tuple:
    """``(ok, total)`` over ``prep['services']['probes']`` — the pre-upgrade
    published-service baseline (``service_probe.probe_targets`` shape)."""
    probes = services.get("probes") if isinstance(services, dict) else None
    if not isinstance(probes, list):
        return 0, 0
    total = len(probes)
    ok = 0
    for probe in probes:
        result = probe.get("result") if isinstance(probe, dict) else None
        if isinstance(result, dict) and result.get("ok"):
            ok += 1
    return ok, total


def _prerequisites(cr, lang: str, prep, action: str) -> list:
    """Section 8, driven by the pre-upgrade evidence when there is any.

    With a ``prep`` dict the boxes are ticked from what was actually measured
    (backup ok? health ok? N of M services reachable?) and a failure prints its
    error. Without one, every box is UNTICKED — an unticked box is a true
    statement about missing evidence; a ticked one would be a fabricated
    pre-flight.
    """
    t = _T[lang]
    out: list[str] = []
    prep = prep if isinstance(prep, dict) else None
    if not prep:
        out.append(t["prep_none"])
        out.append("")
        out.append(_checkbox(False, t["p_backup"]))
        out.append(_checkbox(False, t["p_health"]))
        out.append(_checkbox(False, t["p_services"]))
        out.append(_checkbox(False, t["p_permission"]))
        out.append(_checkbox(False, t["p_window"]))
        if action == "upgrade":
            out.append(_checkbox(False, t["p_image"]))
            out.append(_checkbox(False, t["p_access"]))
        return out

    appliance = _val(prep.get("appliance"), lang)
    generated = _stamp(prep.get("generated_at"), lang)
    out.append(t["prep_from"] % (appliance, generated))
    out.append("")

    backup = prep.get("backup") if isinstance(prep.get("backup"), dict) else None
    if backup is None:
        out.append(_checkbox(False, f"{t['p_backup']} — {t['placeholder']}"))
    elif backup.get("ok"):
        name = _val(backup.get("name"), lang)
        out.append(_checkbox(True, f"{t['p_backup']}: `{name}`"))
    else:
        err = _val(backup.get("error"), lang)
        out.append(_checkbox(False, f"{t['p_backup']} — {t['p_error']}: {err}"))

    health = prep.get("health") if isinstance(prep.get("health"), dict) else None
    if health is None:
        out.append(_checkbox(False, f"{t['p_health']} — {t['placeholder']}"))
    elif health.get("ok"):
        out.append(_checkbox(True, t["p_health"]))
    else:
        err = _val(health.get("error"), lang)
        out.append(_checkbox(False, f"{t['p_health']} — {t['p_error']}: {err}"))

    services = prep.get("services") if isinstance(prep.get("services"), dict) else None
    if services is None:
        out.append(_checkbox(False, f"{t['p_services']} — {t['placeholder']}"))
    elif services.get("ok"):
        ok, total = _probe_counts(services)
        detail = (t["p_probes"] % (ok, total)) if total else t["p_probes_none"]
        out.append(_checkbox(bool(total), f"{t['p_services']}: {detail}"))
    else:
        err = _val(services.get("error"), lang)
        out.append(_checkbox(False, f"{t['p_services']} — {t['p_error']}: {err}"))

    firmware = prep.get("firmware")
    out.append(_checkbox(bool(firmware),
                         t["p_firmware"] % _val(firmware, lang)))

    permission = prep.get("permission")
    if permission is None:
        out.append(_checkbox(False, f"{t['p_permission']} — {t['unknown']}"))
    else:
        out.append(_checkbox(bool(permission), t["p_permission"]))

    # Never evidenced by the machine: these stay for a human to tick.
    out.append(_checkbox(False, t["p_window"]))
    if action == "upgrade":
        out.append(_checkbox(False, t["p_image"]))
        out.append(_checkbox(False, t["p_access"]))
    return out


def _work_params(cr, lang: str, action: str) -> list:
    """The parameter block that closes section 9.

    For ``custom_rest`` this prints the LITERAL method, endpoint and body out
    of ``cr.params_dict``, because that call is the only description of what
    the change does — paraphrasing it would hide the very thing the reviewer
    has to judge.
    """
    t = _T[lang]
    params = _cr_params(cr)
    out: list[str] = []

    if action == "custom_rest":
        method = str(params.get("method") or "").strip()
        endpoint = str(params.get("endpoint") or "").strip()
        mkey = str(params.get("mkey") or "").strip()
        label = str(params.get("label") or "").strip()
        body = params.get("body")
        if not method and not endpoint:
            out.append(t["rest_none"])
            return out
        out += _table((t["col_field"], t["col_value"]), [
            (t["rest_method"], _cell(method.upper() if method else "", lang)),
            (t["rest_endpoint"], _cell(f"`{endpoint}`" if endpoint else "", lang)),
            (t["rest_mkey"], _cell(f"`{mkey}`" if mkey else "", lang)),
            (t["rest_label"], _cell(label, lang)),
        ])
        out.append("")
        out.append(f"**{t['rest_body']}:**")
        out.append("")
        out.append("```json")
        if body in (None, "", {}):
            out.append("null")
        elif isinstance(body, str):
            out.append(body)
        else:
            try:
                out.append(json.dumps(body, indent=2, ensure_ascii=False,
                                      sort_keys=True))
            except (TypeError, ValueError):
                out.append(str(body))
        out.append("```")
        return out

    out.append(f"**{t['params_head']}:**")
    out.append("")
    if not params:
        out.append(t["params_none"])
        return out
    out += _table((t["col_field"], t["col_value"]),
                  [(f"`{_cell(k, lang)}`", _cell(_render_param(v), lang))
                   for k, v in sorted(params.items(), key=lambda kv: str(kv[0]))])
    return out


def _render_param(value) -> str:
    if isinstance(value, (dict, list)):
        try:
            return json.dumps(value, ensure_ascii=False, sort_keys=True)
        except (TypeError, ValueError):
            return str(value)
    return str(value)


def _approvals(cr, lang: str) -> list:
    """Section 12. SATOM records exactly ONE approver, so exactly one row is
    filled from the record and the rest are blank signature lines."""
    t = _T[lang]
    ph = t["placeholder"]
    approved_by = str(getattr(cr, "approved_by", "") or "").strip()
    approved_at = getattr(cr, "approved_at", None)
    if approved_by:
        first = (t["ap_satom"], _cell(approved_by, lang),
                 _cell(_stamp(approved_at, lang), lang), "*(SATOM)*")
    else:
        first = (t["ap_satom"], ph, ph, f"*({t['ap_not_approved']})*")
    rows = [first]
    for role in t["ap_roles"]:
        rows.append((role, ph, ph, " "))
    out = _table((t["ap_role"], t["ap_name"], t["ap_date"], t["ap_sign"]), rows)
    out.append("")
    out.append(t["ap_note"])
    return out


def _outcome(cr, lang: str, status: str) -> list:
    """Section 13. Exactly one box is ticked, and only for a terminal CR."""
    t = _T[lang]
    out: list[str] = []
    terminal = ("completed", "failed", "cancelled")
    out.append(_checkbox(status == "completed", t["out_completed"]))
    out.append(_checkbox(status == "failed", t["out_failed"]))
    out.append(_checkbox(status == "cancelled", t["out_cancelled"]))
    out.append("")
    if status not in terminal:
        out.append(t["out_open"] % (t["status_labels"].get(status, status or "—")))
        out.append("")
    summary = str(getattr(cr, "result_summary", "") or "").strip()
    out.append(f"**{t['out_summary']}:**")
    out.append("")
    out.append(f"> {summary}" if summary else t["out_no_summary"])
    out.append("")
    out.append(f"{t['out_sign']}: ______________________________")
    return out


# --------------------------------------------------------------------------- #
#  Draft prefill for a NEW change request                                       #
# --------------------------------------------------------------------------- #
#: Token the caller substitutes with the live device selection. The sentences
#: below are authored HERE, in both languages, and the form only replaces this
#: token - a phrase with two authors drifts, and the drifted copy is the one an
#: approver ends up signing.
DEVICES_TOKEN = "{devices}"

#: The fields :func:`draft_fields` proposes. NOT the whole form: the devices and
#: the maintenance window are decisions, not defaults, and are never guessed.
DRAFT_FIELDS: tuple = ("title", "reason", "rollback")

#: Why these sentences do NOT reuse the action profile's prose: the rendered
#: document already prints the standard justification (section 4) and the
#: standard rollback steps (section 7) from :data:`ACTION_PROFILES`, and prints
#: the change's OWN ``reason``/``rollback`` next to them. Copying the profile
#: text into those fields would print the same paragraph twice and, worse, make
#: the operator's statement indistinguishable from boilerplate. So the proposal
#: is built from what is true of THIS change - the action, the devices, and the
#: pre-flight run it rests on.
_DRAFT: dict = {
    "de": {
        "devices_none": "(noch keine Geräte gewählt)",
        "choose_action": "— Art der Änderung wählen —",
        "title": "{action} — {devices}",
        "reason": (
            "Geplante Durchführung von „{action}“ auf {devices}. Die Aktion ist "
            "änderungspflichtig und läuft ausschliesslich innerhalb des unten "
            "festgelegten, freigegebenen Wartungsfensters."),
        "reason_prep": (
            "Geplante Durchführung von „{action}“ auf {devices}. Nachweis: "
            "Pre-Flight-Lauf #{prep_id} vom {prep_at} — Ergebnis {verdict}, "
            "{services} veröffentlichte Dienste erfasst{firmware}{backup}. Die "
            "Aktion läuft ausschliesslich innerhalb des unten festgelegten, "
            "freigegebenen Wartungsfensters."),
        "verdict_ok": "bestanden",
        "verdict_bad": "NICHT sauber",
        "firmware": ", Firmware-Stand zum Zeitpunkt der Prüfung {firmware}",
        "backup": ", Konfigurations-Backup {backup}",
        "rollback": (
            "Bei Fehlschlag: beim fehlgeschlagenen Schritt anhalten, den Zustand "
            "vor dem Change auf {devices} wiederherstellen (vorherige "
            "Firmware-Partition bzw. letztes Konfigurations-Backup), die auf "
            "diesem Change erfassten veröffentlichten Dienste erneut prüfen und "
            "erst danach das Wartungsfenster schliessen. Die Standardschritte "
            "dieser Aktion stehen in Abschnitt 7 des Change-Dokuments."),
        "rollback_prep": (
            "Bei Fehlschlag: beim fehlgeschlagenen Schritt anhalten, den Zustand "
            "vor dem Change auf {devices} wiederherstellen — Konfigurations-Backup "
            "{backup} aus dem Pre-Flight-Lauf #{prep_id} —, die auf diesem Change "
            "erfassten veröffentlichten Dienste erneut prüfen und erst danach das "
            "Wartungsfenster schliessen. Die Standardschritte dieser Aktion stehen "
            "in Abschnitt 7 des Change-Dokuments."),
    },
    "en": {
        "devices_none": "(no devices selected yet)",
        "choose_action": "— Choose the type of change —",
        "title": "{action} — {devices}",
        "reason": (
            "Planned execution of “{action}” on {devices}. The action is "
            "change-controlled and runs only inside the approved maintenance "
            "window set below."),
        "reason_prep": (
            "Planned execution of “{action}” on {devices}. Evidence: pre-flight "
            "run #{prep_id} of {prep_at} — verdict {verdict}, {services} published "
            "service(s) recorded{firmware}{backup}. The action runs only inside "
            "the approved maintenance window set below."),
        "verdict_ok": "passed",
        "verdict_bad": "NOT clean",
        "firmware": ", firmware at the time of the check {firmware}",
        "backup": ", configuration backup {backup}",
        "rollback": (
            "On failure: stop at the failed step, restore the pre-change state on "
            "{devices} (previous firmware partition, or the last configuration "
            "backup), re-check the published services recorded on this change, and "
            "only then close the maintenance window. The standard steps for this "
            "action are printed in section 7 of the change document."),
        "rollback_prep": (
            "On failure: stop at the failed step, restore the pre-change state on "
            "{devices} — configuration backup {backup} from pre-flight run "
            "#{prep_id} —, re-check the published services recorded on this change, "
            "and only then close the maintenance window. The standard steps for "
            "this action are printed in section 7 of the change document."),
    },
}


def action_label(action, lang) -> str:
    """The action's label in ``lang`` - the same string section 2 of the
    document uses.

    The English labels mirror the automation registry verbatim; the German ones
    exist only here. Reading both from the profile means the picker, the title
    it proposes and the printed document cannot name the same action three
    different ways."""
    return str(_profile_text(action, normalize_lang(lang)).get("label", "")
               or "").strip()


def draft_fields(action, lang, *, prep=None) -> dict:
    """Proposed ``title`` / ``reason`` / ``rollback`` for a new change request.

    ``prep`` is an optional plain mapping describing the pre-flight run the
    change rests on - ``{id, at, ok, services, firmware, backup}`` - prepared by
    the caller so this module keeps touching no ORM and no timezone.

    Every returned string carries :data:`DEVICES_TOKEN` where the device names
    belong; the caller substitutes the live selection. What comes back is a
    PROPOSAL rendered into editable fields, never stored behind the operator's
    back: section 1 of the document attributes this text to them by name.
    """
    code = normalize_lang(lang)
    t = _DRAFT[code]
    label = action_label(action, code)
    ctx = prep if isinstance(prep, dict) else None

    title = t["title"].format(action=label, devices=DEVICES_TOKEN)
    if ctx:
        firmware = str(ctx.get("firmware") or "").strip()
        backup = str(ctx.get("backup") or "").strip()
        prep_id = ctx.get("id", "?")
        reason = t["reason_prep"].format(
            action=label, devices=DEVICES_TOKEN, prep_id=prep_id,
            prep_at=str(ctx.get("at") or "?"),
            verdict=t["verdict_ok"] if ctx.get("ok") else t["verdict_bad"],
            services=ctx.get("services", 0),
            firmware=(t["firmware"].format(firmware=firmware) if firmware else ""),
            backup=(t["backup"].format(backup=backup) if backup else ""))
        rollback = (t["rollback_prep"].format(devices=DEVICES_TOKEN,
                                              backup=backup, prep_id=prep_id)
                    if backup else t["rollback"].format(devices=DEVICES_TOKEN))
    else:
        reason = t["reason"].format(action=label, devices=DEVICES_TOKEN)
        rollback = t["rollback"].format(devices=DEVICES_TOKEN)
    return {"title": title, "reason": reason, "rollback": rollback}


def action_placeholder(lang) -> str:
    """The picker's opening entry, in ``lang``.

    It exists so that NOTHING is pre-selected. A picker that opens on a real
    action makes that action a default nobody chose, and - worse - choosing it
    fires no ``change`` event, so the page never learns the question was
    answered. The entry carries an empty value: it is a question, not a
    submittable answer, and the view rejects it like any other unknown action.
    """
    return _DRAFT[normalize_lang(lang)]["choose_action"]


def devices_placeholder(lang) -> str:
    """What stands in for the device list while nothing is selected. It reads as
    an unfilled blank, never as a device name."""
    return _DRAFT[normalize_lang(lang)]["devices_none"]


__all__ = [
    "REQUIRED_PROFILE_KEYS",
    "GENERIC_ACTION",
    "ACTION_PROFILES",
    "SECTION_TITLES",
    "normalize_lang",
    "document_langs",
    "renderable_langs",
    "change_ref",
    "filename",
    "profile_for",
    "action_label",
    "draft_fields",
    "devices_placeholder",
    "DEVICES_TOKEN",
    "action_placeholder",
    "DRAFT_FIELDS",
    "render",
]


_localize_all()

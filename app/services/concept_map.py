"""Concept Map — the searchable "where is what" of this console.

SATOM has ~180 reachable GET endpoints across 79 blueprints. The sidebar shows
them grouped by ADOM (product), which answers *"what can I do here?"* but never
*"where does X live?"* — the question an operator actually asks. This module is
the answer: every navigable page, tagged with the CONCEPTS it serves, so a
free-text search ("certificate", "rollback", "who changed it") lands on the page
instead of on a manual.

Three rules hold this file honest, and each has a test in
``tests/test_concept_map.py``:

1. **The URL map is the authority on what exists.** Every parameterless GET
   endpoint is either in :data:`PAGES` or in :data:`EXCLUDED` with a reason.
   A page added without an entry FAILS the guard — it can never be silently
   missing from the map. The cost is one line per new endpoint; that is the
   price of the map never lying about coverage.
2. **Nothing here is a second source of truth for a URL or a permission.**
   Paths come from ``url_for``; the required permission is read off the view
   function (stamped by ``require_permission``), never re-declared here. A
   hand-copied permission column is how a map ends up advertising a page that
   403s.
3. **Identity keys are never translated.** ``concept`` keys and endpoint names
   are structural identity (same lesson as ``data-nav-group``, safeguards §68);
   only ``label``/``blurb`` are display text.

Concept keys are stable — they appear in URLs (``/map/?c=waf``) and in the
saved-search of anyone who bookmarks a cluster.
"""
from __future__ import annotations

from flask import current_app, url_for


# --------------------------------------------------------------------------
# Concept clusters. `accent` is used ONLY as a decorative rule/dot on a white
# card — never as text colour and never as a fill behind text. This product is
# a light theme (safeguards §9m); a mid-tone hue as body text would be the
# grey-slab bug again.
# --------------------------------------------------------------------------
CONCEPTS: tuple[dict, ...] = (
    {
        "key": "fleet", "label": "Fleet & Discovery", "icon": "bi-globe2",
        "accent": "#0A3F9F",
        "blurb": "Which devices exist, how they are wired, and how to find an "
                 "object across all of them.",
    },
    {
        "key": "monitoring", "label": "Monitoring & Telemetry",
        "icon": "bi-activity", "accent": "#0A6978",
        "blurb": "Is it healthy right now, what did it look like an hour ago, "
                 "and who gets told when it is not.",
    },
    {
        "key": "waf", "label": "Web Application Firewall", "icon": "bi-shield-check",
        "accent": "#B03A12",
        "blurb": "FortiWeb protection: policies, signatures, exceptions and the "
                 "attacks they actually stopped.",
    },
    {
        "key": "adc", "label": "Application Delivery", "icon": "bi-diagram-3",
        "accent": "#15692A",
        "blurb": "FortiADC load balancing — virtual servers, pools and the ADC "
                 "signature sets.",
    },
    {
        "key": "config", "label": "Device Configuration", "icon": "bi-sliders",
        "accent": "#4C2A85",
        "blurb": "Reading and writing what is actually on a box, and the object "
                 "model behind it.",
    },
    {
        "key": "automation", "label": "Automation & Change", "icon": "bi-gear-wide-connected",
        "accent": "#7A4A00",
        "blurb": "Turning an intention into a reviewed, scheduled, audited "
                 "change on many devices at once.",
    },
    {
        "key": "resilience", "label": "Backup, Firmware & Recovery",
        "icon": "bi-box-seam", "accent": "#0A5F6C",
        "blurb": "The copies you fall back to, the versions you move between, "
                 "and the second node that takes over.",
    },
    {
        "key": "access", "label": "Identity & Access", "icon": "bi-person-badge",
        "accent": "#8B1C2A",
        "blurb": "Who may do what, proven by certificates and recorded in the "
                 "audit trail.",
    },
    {
        "key": "platform", "label": "Platform & Administration",
        "icon": "bi-hdd-stack", "accent": "#3D4550",
        "blurb": "SATOM itself: settings, its own database, its updates and its "
                 "reports.",
    },
    {
        "key": "dev", "label": "Developer & Extensibility", "icon": "bi-braces",
        "accent": "#5B4B00",
        "blurb": "Raw API access, tokens, scripting and custom views for people "
                 "extending the product.",
    },
)

CONCEPT_KEYS = tuple(c["key"] for c in CONCEPTS)


def _p(endpoint, label, concept, keywords, blurb):
    return {"endpoint": endpoint, "label": label, "concept": concept,
            "keywords": keywords, "blurb": blurb}


# --------------------------------------------------------------------------
# The map. `keywords` are the SEARCH surface — write the words an operator
# types under pressure ("cert expired", "rollback", "who changed"), not the
# words engineering uses in the module name.
# --------------------------------------------------------------------------
PAGES: tuple[dict, ...] = (
    # ---- Fleet & Discovery -------------------------------------------------
    _p("index", "Global Dashboard", "fleet",
       "home global overview fleet dashboard start landing all products",
       "Fleet-wide console spanning every ADOM."),
    _p("fortiweb_home", "FortiWeb Dashboard", "fleet",
       "fortiweb waf home dashboard adom",
       "The FortiWeb ADOM entry point."),
    _p("adc.index", "FortiADC Dashboard", "fleet",
       "fortiadc adc load balancer home dashboard adom",
       "The FortiADC ADOM entry point."),
    _p("faz.index", "FortiAnalyzer Dashboard", "fleet",
       "fortianalyzer faz logs analyzer dashboard adom",
       "FortiAnalyzer devices and their log intake."),
    _p("fac.index", "FortiAuthenticator Dashboard", "fleet",
       "fortiauthenticator fac identity radius dashboard adom",
       "FortiAuthenticator devices."),
    _p("product.select", "ADOM Selector", "fleet",
       "adom product switch change context fortiweb fortiadc scope",
       "Choose which product scope this session works in."),
    _p("adom_assets.index", "Stored Assets", "fleet",
       "stored assets adom holds backups on the server config backup coverage "
       "days since last push never pushed serial number identity retired "
       "de-registered device history sot versions off-box firmware unclaimed "
       "orphan folder whose backup is this who owns this file",
       "Per ADOM: the config backups sitting on the backup server with a "
       "days-since-last-push grade, the configuration history split local vs "
       "off-box, firmware, and the identity — serial and every earlier name — "
       "of each device, including the ones that were de-registered."),
    _p("scout.index", "Scout — Fault Isolation", "monitoring",
       "scout troubleshoot fault isolation which layer is broken localise "
       "diagnose service down slow backend firewall drop reset routing "
       "timeout ttfb connect tls handshake pool members vip virtual server "
       "server policy why is this broken where is the problem ladder",
       "Walks one published service down ten rungs — appliance, object, name, "
       "front door, certificate, pool, backends, border path, decision, WAF — "
       "and stops at the first that fails, naming that layer with its "
       "evidence. Operator-started and object-given, which is what separates "
       "it from Sentinel."),
    _p("console.index", "Device Console", "config",
       "console cli ssh command line run command shell terminal type a command "
       "test password credential wrong login tac bundle support ticket fortinet "
       "case transcript reboot restore execute get show diagnose",
       "A CLI session to a registered appliance — the only place SSH writes in "
       "SATOM — plus a username/password test against any FortiOS device and a "
       "redacted transcript packaged for a Fortinet support ticket."),
    _p("process.index", "Process — Procedures & Recovery Plans", "automation",
       "process procedure runbook recovery plan disaster dr flowchart diagram "
       "checklist steps validate after upgrade onboarding verify everything "
       "works automatic check run the plan decision branch manual gate walk "
       "import export xml file load a runbook move a procedure between "
       "installations drawio bpmn visio",
       "Operator-drawn procedures SATOM walks step by step: each step asks the "
       "module that owns the question (HTTP, TCP, DNS, appliance health, the "
       "read-only console, a catalogue action) and the arrows say where to go "
       "depending on the answer. A run says which step stopped it, and is a "
       "rehearsal unless it is armed."),
    _p("sentinel.index", "Sentinel — Incidents", "monitoring",
       "sentinel incident attack detection anomaly correlation score band "
       "respond breach suspicious spike who attacked",
       "Correlated incidents across every signal Sentinel collects, scored and "
       "banded by how far it is allowed to act on its own."),
    _p("sentinel.context", "Sentinel Context", "monitoring",
       "sentinel context trusted source maintenance window topology false "
       "positive scanner whitelist suppress",
       "What Sentinel must NOT call an attack: trusted sources, maintenance "
       "windows and the topology it scores against."),
    _p("sentinel.docs", "Sentinel Architecture", "monitoring",
       "sentinel architecture how it works weights scoring bands action "
       "catalog reference explain",
       "How Sentinel decides — rendered from the live weights and action "
       "catalog, not from a transcription."),
    _p("sentinel.policies", "Sentinel Response Policies", "automation",
       "sentinel policy response action arm automatic block gate approval "
       "semi-auto band",
       "Which responses Sentinel may take by itself, which need a human, and "
       "the gates in front of the ones that can block traffic."),
    _p("sentinel.blocklist", "Sentinel Border Blocklist", "automation",
       "sentinel blocklist border feed fortigate threat external connector "
       "block ip release unblock false positive ttl expiry publish mirror",
       "The list SATOM publishes for a border firewall to read, and the place "
       "an address is released from it. Nothing here is written to a "
       "FortiGate — the operator's own deny policy reads the feed."),
    _p("settings.sentinel_section", "Sentinel Settings", "monitoring",
       "sentinel settings configure knobs demo scenario simulation pipeline "
       "weights score bands kill switch arm response tune thresholds example",
       "The whole Sentinel section: every knob, the pipeline stage by stage, "
       "the live scoring weights, and ten demonstrations runnable against "
       "the real engine."),
    _p("appliances.index", "Appliances", "fleet",
       "devices inventory appliance host add register credentials ip serial model",
       "The device inventory — every managed box and how SATOM reaches it."),
    _p("architecture.index", "Architecture", "fleet",
       "topology map diagram network wiring vip service graph",
       "Whole-fleet service topology drawn from the device cache."),
    _p("fleet_objects.index", "Fleet Objects", "fleet",
       "objects across devices compare duplicate inventory pools servers",
       "One object type across every device at once."),
    _p("waf.index", "WAF Overview", "fleet",
       "waf fleet overview posture blocking monitor mode detection unprotected "
       "coverage charts statistics protections weak tls stale snapshot",
       "Fleet-wide FortiWeb posture: what blocks, what only watches, what is "
       "protected by nothing."),
    _p("waf.inventory", "WAF Inventory", "fleet",
       "every server policy fleet wide list filter csv export virtual server "
       "pool profile certificate tls plain http disabled",
       "Every server policy on every visible FortiWeb, filterable and "
       "exportable."),
    _p("waf.profiles", "WAF Profiles", "fleet",
       "web protection profile inline offline predefined custom unused orphan "
       "signature policy slots filled usage",
       "Every web protection profile, how many policies use it, and how much "
       "of it is filled in."),
    _p("waf.coverage", "WAF Coverage", "fleet",
       "protection matrix per device adom heatmap gaps signatures bot "
       "mitigation geo block json xml openapi validation csrf cookie",
       "Protection-by-scope matrix: which WAF features each device's policies "
       "actually switch on."),
    _p("waf.artifacts", "WAF Artifacts", "fleet",
       "artifacts fleet wide file backed objects xml schema xsd dtd wsdl "
       "openapi grpc json schema lua scripting held missing blocked at risk "
       "borrowed orphan empty library store migration blockers sweep",
       "Every file-backed WAF object the estate needs, whether SATOM holds it, "
       "and which policies cannot be migrated without it."),
    _p("waf.exceptions", "WAF Exceptions", "fleet",
       "exception carve out waiver false positive signature disable custom "
       "signature inventory who has it fleet wide library version rollback "
       "restore stale orphan bot geo syntax cookie url encryption file",
       "Every authored WAF/signature carve-out across the estate, which scopes "
       "hold each one, and whether it can be rolled back."),
    _p("search.index", "Search", "fleet",
       "find search free text lookup where is object policy pool certificate",
       "Free-text sweep across live device configuration."),
    _p("dns_tool.index", "DNS Lookup", "fleet",
       "dns resolve record a cname lookup nslookup dig zone",
       "Resolve names and inspect DNS records from the console."),
    _p("device_provision.index", "Device Provisioning", "fleet",
       "onboard new device bootstrap enroll zero touch provision",
       "Bring a new appliance under management."),
    _p("analysis.index", "Fleet Analysis", "fleet",
       "analysis orphans freshness cardinality subelements wpp matrix report",
       "Cross-device analytics: orphans, staleness, cardinality."),

    # ---- Monitoring & Telemetry -------------------------------------------
    _p("monitoring.index", "Device Health", "monitoring",
       "health cpu memory disk sessions alerts capacity guardrail device up down",
       "Appliance cards, capacity guardrails and health alerts."),
    _p("monitoring.satom", "SATOM Health", "monitoring",
       "self health this installation nodes units redundancy crypto healthz",
       "The health of this installation, not of the devices."),
    _p("service_monitor.index", "Service Monitor", "monitoring",
       "service probe http tcp reachability uptime latency synthetic check",
       "Synthetic probes against the services the devices publish."),
    _p("deep_monitor.index", "Deep Monitors", "monitoring",
       "deep monitor probe custom threshold cadence detailed",
       "Per-object deep probes with their own cadence."),
    _p("monitor_analytics.index", "Monitoring Analytics", "monitoring",
       "boards panels charts trends analytics dashboard metricsql history",
       "Dashboards over the metric store, panel by panel."),
    _p("monitor_reports.index", "Monitoring Reports", "monitoring",
       "report daily weekly period summary export scheduled pdf",
       "Periodic reports built from monitoring data."),
    _p("metrics.index", "Metrics", "monitoring",
       "metrics graphs timeseries chart range traffic throughput",
       "Time-series charts over the collected metrics."),
    _p("metrics_admin.index", "Metric Collection", "monitoring",
       "collector scrape interval top-n target victoriametrics store tuning",
       "Which collectors run, how often, and how the store is doing."),
    _p("capacity.index", "Capacity", "monitoring",
       "capacity limits headroom licence policies count sizing",
       "How close each device is to its structural limits."),
    _p("notifications.index", "Notifications", "monitoring",
       "alerts bell notification inbox unread warning message",
       "The alert inbox for this user."),

    # ---- Web Application Firewall -----------------------------------------
    _p("web_protection.index", "Web Protection", "waf",
       "waf profile inline protection signature policy protect ruleset",
       "FortiWeb protection profiles and what they enforce."),
    _p("attack_search.index", "Attack Search", "waf",
       "attack log incident blocked event forensics threat hunting evidence",
       "Search the attack log across the FortiWeb fleet."),
    _p("signatures.index", "Signatures", "waf",
       "signature ips update sync base device attack definitions",
       "Signature sets and their sync state per device."),
    _p("exceptions.index", "Exceptions", "waf",
       "exception carve-out false positive allow bypass url exclusion",
       "The carve-outs that stop a legitimate request being blocked."),
    _p("server_objects.index", "Server Objects", "waf",
       "server policy virtual server pool real server backend vip",
       "Server policies, virtual servers and pools on one device."),
    _p("appids.index", "Application IDs", "waf",
       "application id appid catalogue naming ownership app registry",
       "The application catalogue policies are attributed to."),
    _p("classification.index", "Classification", "waf",
       "classification tier criticality label taxonomy risk grading",
       "How applications are graded and labelled."),
    _p("line_profiles.index", "Line Profiles", "waf",
       "line profile segment network certificate class wpp template declaration",
       "What each classification line receives: segments, certificate class "
       "and the Web Protection Profile a new policy starts from."),
    _p("workspace.index", "Workspace", "waf",
       "workspace scratch working set staging draft",
       "The per-user working set of objects."),

    # ---- Application Delivery ---------------------------------------------
    _p("adc.signatures", "ADC Signatures", "adc",
       "fortiadc signature web attack policy set waf adc",
       "FortiADC Web Attack Signature policies."),
    _p("adc.wizard_virtual_server", "ADC Virtual Server Wizard", "adc",
       "wizard virtual server create vip load balance new adc guided",
       "Guided creation of an ADC virtual server."),

    # ---- Device Configuration ---------------------------------------------
    _p("section_config.index", "Configuration", "config",
       "configuration live device section browse edit settings on box",
       "Browse and edit what is actually on the selected device."),
    _p("registry.index", "Endpoint Registry", "config",
       "registry endpoint api urn coverage schema object model",
       "Every device endpoint SATOM knows how to talk to."),
    _p("registry.search", "Registry Search", "config",
       "registry search endpoint find urn api path",
       "Find an endpoint in the registry by name or path."),
    _p("registry.reconcile", "Registry Reconcile (FortiWeb)", "config",
       "reconcile registry drift sweep dead endpoint retire confirm apply "
       "fortiweb missing stale",
       "Compare the registry against what the sweep actually reached, and "
       "retire the endpoints no appliance answers."),
    _p("registry.api_versions", "API Versions (FortiWeb)", "config",
       "api version firmware line matrix preflight field divergence 7.6 8.0 "
       "fortiweb unmeasured",
       "Which fields each firmware line really carries — the same API "
       "version is not the same set of fields."),
    _p("adc_api.reconcile", "Registry Reconcile (FortiADC)", "adc",
       "reconcile registry drift sweep dead endpoint retire confirm apply "
       "fortiadc missing stale",
       "The FortiADC registry against what the sweep reached."),
    _p("adc_api.api_versions", "API Versions (FortiADC)", "adc",
       "api version firmware line matrix preflight field divergence fortiadc "
       "unmeasured",
       "Which fields each FortiADC firmware line really carries."),
    _p("structure.index", "Object Structure", "config",
       "structure tree dependency hierarchy object relationships coverage",
       "The dependency tree of FortiWeb objects and its registry coverage."),
    _p("section_catalog.index", "Section Catalog", "config",
       "catalog approved template section desired state library",
       "Approved templates grouped by the section they configure."),
    _p("logs.index", "Device Logs", "config",
       "log device traffic event syslog history tail",
       "Logs pulled from the device itself."),

    # ---- Automation & Change ----------------------------------------------
    _p("templates.index", "Templates", "automation",
       "template desired state reusable config snippet draft approve",
       "Reusable configuration fragments, drafted and approved."),
    _p("provisioning.index", "Provisioning", "automation",
       "provision system profile rollout apply many devices baseline",
       "System profiles that push a baseline onto devices."),
    _p("provisioning.baselines", "Baselines", "automation",
       "baseline zone line department combination matrix standard",
       "The zone x line x department grid of expected configuration."),
    _p("change_requests.index", "Change Requests", "automation",
       "change request approval workflow cr ticket review sign off document",
       "The review-and-approve workflow before a change lands."),
    _p("cr_types.index", "Change Types", "automation",
       "change type category cr taxonomy workflow definition",
       "The kinds of change request the workflow accepts."),
    _p("scheduled_actions.index", "Scheduled Actions", "automation",
       "schedule cron timer recurring job automation periodic task",
       "Recurring work SATOM runs on its own."),
    _p("jobs.manager", "Job Manager", "automation",
       "job queue running task progress history background worker",
       "Everything SATOM is doing or has done, with its result."),
    _p("naming.index", "Naming Rules", "automation",
       "naming convention rule pattern standard object name validate",
       "The naming conventions objects are held to."),
    _p("segments.index", "Segments", "automation",
       "segment grouping zone scope selection cohort",
       "Groupings used to target automation at a subset of the fleet."),
    _p("upgrade_flow.index", "Upgrade Flow", "automation",
       "upgrade flow staged rollout firmware plan sequence maintenance",
       "The staged plan for moving a fleet between versions."),

    # ---- Backup, Firmware & Recovery --------------------------------------
    _p("backups.index", "Device Backups", "resilience",
       "backup device config save restore snapshot copy download",
       "Configuration backups taken from the appliances."),
    _p("system_backup.index", "System Backup & Restore", "resilience",
       "system backup restore bundle source of truth sot rollback recovery disaster",
       "SATOM's own backups, the source-of-truth store and how to recover."),
    _p("system_backup.compare", "Backup Compare", "resilience",
       "compare diff version drift changed config before after",
       "Structural diff between two recorded versions of a device."),
    _p("import_backup.index", "Import Backup", "resilience",
       "import upload backup file snapshot restore external ingest",
       "Bring an externally-taken backup into SATOM."),
    _p("firmware.index", "Firmware", "resilience",
       "firmware version upgrade downgrade image flash release build",
       "Firmware images and what is running where."),
    _p("appliances.flash_reports", "Flash Reports", "resilience",
       "flash report before after upgrade downgrade evidence firmware history",
       "Before/after evidence for every firmware flash."),
    _p("ha.index", "High Availability", "resilience",
       "ha failover standby replica peer node cluster redundancy",
       "The primary/standby pair and its replication state."),
    _p("self_update.index", "Software Update & HA", "resilience",
       "update satom version upgrade self reconciler deploy release install",
       "Updating SATOM itself, on both nodes."),

    # ---- Identity & Access -------------------------------------------------
    _p("users.index", "Users", "access",
       "user account login create disable password person operator",
       "Console accounts."),
    _p("profiles.index", "Permission Profiles", "access",
       "profile permission role rbac grant access rights authorisation",
       "What each role is allowed to do."),
    _p("auth.profile", "My Profile", "access",
       "my profile password language 2fa preferences me account settings",
       "Your own account: password, language, two-factor."),
    _p("audit.index", "Audit Log", "access",
       "audit trail who did what when history change accountability forensics",
       "Every action SATOM took, by whom, from where."),
    _p("cert_manager.index", "Certificate Manager", "access",
       "certificate tls ssl expiry renew acme chain ca pki",
       "Certificates on the devices and on SATOM itself."),
    _p("cert_manager.renewals", "Certificate Renewals", "access",
       "renewal journal acme expiry automatic certificate history",
       "The renewal journal for both nodes."),

    # ---- Platform & Administration ----------------------------------------
    _p("settings.index", "Settings", "platform",
       "settings configuration preferences admin console alerts smtp language adom",
       "The admin console — every SATOM-level setting."),
    _p("integrations.index", "Integrations", "platform",
       "integration external system connect webhook api third party",
       "External systems SATOM talks to."),
    _p("database.index", "Database", "platform",
       "database table sql postgres rows schema query browse",
       "SATOM's own database, browsable."),
    _p("reports.inbox", "Report Inbox", "platform",
       "report inbox generated document output delivered archive",
       "Generated reports waiting to be read."),
    _p("advisor.index", "Advisor", "platform",
       "advisor ai assistant llm suggestion analysis chat help",
       "The AI advisor over your own fleet data."),
    _p("monitoring.infra", "Infrastructure Health", "platform",
       "infrastructure gitea peer off-box external dependency health",
       "Cross-node and off-box dependencies."),
    _p("monitoring.encryption", "Encryption Posture", "platform",
       "encryption tls posture channel replication cipher in transit",
       "Which channels are encrypted, and how."),

    # ---- Developer & Extensibility ----------------------------------------
    _p("api_explorer.index", "API Explorer", "dev",
       "api explorer rest call endpoint try request response swagger",
       "Call device and SATOM APIs interactively."),
    _p("api_tokens.index", "API Tokens", "dev",
       "token api key bearer credential integration machine access",
       "Tokens for programmatic access to SATOM."),
    _p("adc_api.index", "FortiADC API", "dev",
       "adc api console rest fortiadc raw call",
       "Raw API console scoped to FortiADC."),
    _p("faz_api.index", "FortiAnalyzer API", "dev",
       "faz api console rest fortianalyzer raw call jsonrpc",
       "Raw API console scoped to FortiAnalyzer."),
    _p("fac_api.index", "FortiAuthenticator API", "dev",
       "fac api console rest fortiauthenticator raw call",
       "Raw API console scoped to FortiAuthenticator."),
    _p("artifacts.index", "WAF Artifacts", "waf",
       "artifact xml schema xsd dtd wsdl openapi grpc idl json lua script file "
       "upload capture push clone migrate content -7694",
       "The file content FortiWeb keeps out of its own configuration, so a "
       "clone can carry it."),
    _p("artifacts.inventory", "Artifact inventory", "waf",
       "artifact inventory statistics filter orphan used by policy spo "
       "coverage migration missing stale where held "
       "upload edit author version file manage delete capture "
       "schema xsd wsdl openapi grpc idl json lua editor online view",
       "What SATOM holds, where each copy lives, which server policies need "
       "it, and which policies are blocked on content nobody has."),
    _p("artifacts.audit", "Artifact device audit", "waf",
       "artifact audit device appliance per device evidence export csv json "
       "blocked at risk borrowed orphan divergence profile wpp web protection "
       "profile policy walk failed stale migration readiness inventory all",
       "Everything SATOM knows about file-backed WAF objects, grouped by "
       "device and exportable: which policies were walked, which walks failed, "
       "which artifacts are blocked, and where two boxes hold different "
       "content under one name."),
    _p("lua_studio.index", "Lua Studio", "dev",
       "lua script studio code automation custom logic editor",
       "Author and run Lua automation scripts."),
    _p("plugins.index", "Plugins", "dev",
       "plugin custom view extension add-on module install",
       "Custom views built on top of SATOM."),
    _p("plugins.gallery", "Plugin Gallery", "dev",
       "gallery published plugin browse custom view share",
       "Published custom views, for everyone."),
    _p("database.py_console_page", "Python Console", "dev",
       "python console repl shell execute code debug",
       "A Python console against the live application."),
)


# --------------------------------------------------------------------------
# Every remaining parameterless GET endpoint, with WHY it is not on the map.
# One line per endpoint is the price of the guard; the guard is what makes the
# map's coverage claim true instead of aspirational.
# --------------------------------------------------------------------------
EXCLUDED: dict[str, str] = {
    # The New-process form is reached from the Process page and has no
    # standing of its own on the map; "where does X live" is answered by
    # process.index.
    "process.create": "form",
    # Same standing as the New-process form: a door on process.index,
    # reached from it, and findable through its keywords rather than as a
    # second concept. "Where do I import a runbook" and "where do processes
    # live" must not resolve to two different answers.
    "process.import_xml": "form",
    # JSON feeds consumed by a page's own JS.
    "advisor.attach_sot_search": "json feed", "advisor.attachable": "json feed",
    "advisor.tools": "json feed", "advisor.usage": "json feed",
    "analysis.data": "json feed", "analysis.inventory": "json feed",
    "analysis.deep_objects": "json feed", "analysis.faz_ops": "json feed",
    "analysis.freshness": "json feed", "analysis.orphans": "json feed",
    "analysis.subelements": "json feed", "analysis.wpp_matrix": "json feed",
    "architecture.topology_data": "json feed", "architecture.map_data": "json feed",
    "architecture.picker": "html fragment",
    "bookmarks.panel": "html fragment", "bookmarks.devices": "json feed",
    "adom_assets.files": "json feed",
    # The three helper tools are API-only blueprints; their UI is rendered by
    # a page that is already on the map, so these two are feeds, not pages.
    "cert_inspect.targets": "json feed", "txn_trace.context": "json feed", "cert_manager.renewals_durability": "json feed",
    "database.report_column_values": "json feed", "database.table": "sub-view of database.index",
    "device_provision.data": "json feed", "dns_tool.records_list": "json feed",
    "dns_tool.records_schema": "json feed", "jobs.index": "json feed",
    "jobs.all_jobs": "json feed", "metrics.api_data": "json feed",
    "monitor_analytics.cadence": "json feed", "monitor_analytics.catalog": "json feed",
    "monitor_analytics.data": "json feed", "metrics_admin.data": "json feed",
    "waf.api_summary": "json feed",
    "waf.api_artifacts": "json feed",
    "waf.api_exceptions": "json feed",
    "waf.export": "file download — the panel that drives it is on all five /waf pages",
    "metrics_admin.peer_store": "json feed", "metrics_admin.snapshots": "json feed",
    "metrics_admin.stores": "json feed", "monitoring.data": "json feed",
    "deep_monitor.data": "json feed", "monitor_reports.data": "json feed",
    "monitor_reports.preview": "json feed", "monitoring.satom_data": "json feed",
    "service_monitor.data": "json feed", "notifications.unread": "json feed",
    "sentinel.data": "json feed",
    "sentinel.blocklist_feed":
        "machine endpoint — the border blocklist as plain text, fetched by a "
        "FortiGate threat-feed connector with a token in the path. It answers "
        "without a session on purpose (a firewall cannot log in), so it is not "
        "a page a person navigates to and must not be offered as one: the URL "
        "is a credential. Sentinel.blocklist is the page that shows it.",
    "search.results": "sub-view of search.index",
    "settings.ai_state": "json feed", "settings.preview_alerts": "json feed",
    "settings.git_info": "json feed", "settings.hypervisor_state": "json feed",
    "settings.dns_backends_state": "json feed",
    "settings.library_pip_drift": "json feed", "settings.library_pip_state": "json feed",
    "settings.library_updates": "json feed", "settings.node_cert_state": "json feed",
    "settings.peer_libraries": "json feed", "settings.peer_services": "json feed",
    "settings.services_state": "json feed", "settings.services_peers": "json feed",
    "settings.thresholds_state": "json feed", "settings.trust_store_state": "json feed",
    "system_backup.external_content": "json feed", "system_backup.external_diff": "json feed",
    "system_backup.external_download": "file download",
    "system_backup.external_files": "json feed", "system_backup.external_outline": "json feed",
    "system_backup.external_search": "json feed",
    "system_backup.git_bundle_external_download": "file download",
    "system_backup.git_bundle_external_list": "json feed",
    "exceptions.type_fields": "json feed", "firmware.manifest": "json feed",
    "firmware.upload_status_route": "json feed", "logs.history": "json feed",
    "logs.status": "json feed", "regex_lab.examples": "json feed",
    "release_notes.advise": "json feed", "release_notes.data": "json feed",
    "release_notes.issues": "json feed", "release_notes.notes": "json feed",
    "release_notes.scan_status": "json feed",
    "cert_manager.settings": "moved into settings.index",
    # Sub-pages reached FROM a mapped page — listing them doubles the map's
    # size and halves its signal.
    "cert_manager.device_cert": "detail view of cert_manager.index",
    "cert_manager.new": "create form of cert_manager.index",
    "change_requests.new": "create form of change_requests.index",
    "database.report_new": "create form of database.index",
    "lua_studio.new": "create form of lua_studio.index",
    # Verbs of artifacts.inventory. They were reachable from artifacts.index
    # and from artifacts.manage before; index is reference-only and manage was
    # a second copy of the inventory, so pointing these reasons at either would
    # describe a form that no longer exists.
    "artifacts.upload": "form action of artifacts.inventory",
    "artifacts.capture": "form action of artifacts.inventory",
    "artifacts.blob": "file download from artifacts.inventory",
    "artifacts.api_list": "JSON feed of artifacts.inventory",
    "artifacts.object_page": "detail view of artifacts.inventory",
    "artifacts.save": "form action of artifacts.inventory",
    "artifacts.delete": "form action of artifacts.object_page",
    "artifacts.raw": "inline view from artifacts.object_page",
    "artifacts.refresh_refs": "form action of artifacts.inventory",
    "artifacts.api_refs": "JSON feed of artifacts.inventory",
    "artifacts.api_coverage": "JSON feed of artifacts.inventory",
    "plugins.new": "create form of plugins.index",
    "provisioning.new": "create form of provisioning.index",
    "provisioning.baseline_new": "create form of provisioning.baselines",
    "scheduled_actions.new": "create form of scheduled_actions.index",
    # Auth flow — reachable without a session, never a destination.
    "auth.login": "auth flow", "auth.logout": "auth flow",
    "auth.two_factor": "auth flow", "auth.forgot_password": "auth flow",
    # Machinery: health probes, service worker, selftest, legacy redirects.
    "healthz": "health probe", "healthz_backups": "health probe",
    "healthz_cert_renewals": "health probe", "healthz_primary": "health probe",
    "updiag": "health probe", "favicon_ico": "asset",
    "service_worker": "asset", "upload_worker": "asset",
    "_selftest_403": "selftest", "_selftest_404": "selftest",
    "_selftest_error": "selftest",
    "product.switch": "action, not a page",
    "product.fortiadc_home": "legacy redirect to adc.index",
    "product.placeholder_home": "scaffold for placeholder ADOMs",
    "concept_map.index": "this page",
    "concept_map.data": "json feed",
}


# --------------------------------------------------------------------------
# Introspection over the live URL map — the authority, not this file.
# --------------------------------------------------------------------------
def page_endpoints(app=None) -> set[str]:
    """Every parameterless GET endpoint a browser can land on.

    Deliberately NOT ``render_template``-based: several real pages render
    through helpers, so that heuristic reports them as feeds. The shape of the
    URL is the honest signal; classification is then explicit, above.
    """
    app = app or current_app
    out: set[str] = set()
    for rule in app.url_map.iter_rules():
        if "GET" not in rule.methods or rule.arguments:
            continue
        if rule.rule.startswith("/static") or rule.rule.startswith("/api/"):
            continue
        if rule.endpoint.startswith("static"):
            continue
        out.add(rule.endpoint)
    return out


def required_permission(endpoint: str, app=None):
    """The permission the view itself declares, or ``None``.

    Read off the stamp ``require_permission`` leaves on the wrapper. Never
    re-declared in :data:`PAGES` — a hand-copied permission column drifts, and
    a map that drifts advertises pages that 403.
    """
    app = app or current_app
    fn = app.view_functions.get(endpoint)
    return getattr(fn, "__required_permission__", None) if fn else None


def _visible(page, user, app) -> bool:
    perm = required_permission(page["endpoint"], app)
    if perm is None:
        return True
    try:
        return bool(user is not None and user.is_authenticated and user.can(perm))
    except Exception:  # noqa: BLE001 — an odd user object hides the row, never 500s
        return False


def build(user=None, app=None) -> list[dict]:
    """The clusters, resolved to real URLs and filtered to what *user* may open.

    A cluster with no visible page is dropped entirely — an empty heading is a
    promise the console does not keep.
    """
    app = app or current_app._get_current_object()
    by_concept: dict[str, list[dict]] = {}
    for page in PAGES:
        if not _visible(page, user, app):
            continue
        # NOT wrapped: a registered endpoint whose URL cannot be built is a
        # bug, and swallowing it would make the page VANISH from the map —
        # indistinguishable from "this page does not exist", which is the one
        # thing the map must never say wrongly. :func: reports
        # dangling entries; this raises on anything it could not have caught.
        href = url_for(page["endpoint"])
        by_concept.setdefault(page["concept"], []).append({
            "endpoint": page["endpoint"], "label": page["label"],
            "blurb": page["blurb"], "keywords": page["keywords"],
            "href": href, "permission": required_permission(page["endpoint"], app),
        })
    clusters = []
    for concept in CONCEPTS:
        pages = by_concept.get(concept["key"], [])
        if not pages:
            continue
        clusters.append({**concept, "pages": sorted(pages, key=lambda p: p["label"])})
    return clusters


def coverage(app=None) -> dict:
    """What the map claims vs what the URL map holds.

    Surfaced on the page itself. A map that quietly omits pages reads exactly
    like a complete one — so it says the number out loud.
    """
    app = app or current_app._get_current_object()
    live = page_endpoints(app)
    mapped = {p["endpoint"] for p in PAGES}
    return {
        "live": len(live),
        "mapped": len(mapped & live),
        "excluded": len(set(EXCLUDED) & live),
        "unmapped": sorted(live - mapped - set(EXCLUDED)),
        "dangling": sorted(mapped - live),
    }

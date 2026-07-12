"""FortiAnalyzer sidebar menu — curated groups bound to registry endpoints.

FortiADC/FortiWeb build their sidebar from the registry (live object types
resolved off a device). FortiAnalyzer's GUI areas don't map 1:1 to a CMDB
tree, so its Configuration/Operation/Automation groups stay a curated, static
menu — but every leaf now carries ``logicals``: (registry_name, tab_label)
pairs resolved through ``registry.loader.resolve_faz`` and fetched live by
:func:`app.views.faz.menu_page` via the JSON-RPC client. Renaming an URI on a
FAZ upgrade is a Registry-page edit, never a code change (same contract as
FortiWeb/FortiADC). The Fleet and Administration areas are NOT here — they
reuse the real shared blueprints and are hardcoded in the sidebar, exactly
like FortiADC.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Item:
    key: str
    label: str
    icon: str = 'bi-dot'
    desc: str = ''
    # (registry logical name, tab label) pairs — live tabs on the section page.
    logicals: tuple = field(default=())


@dataclass(frozen=True)
class Group:
    key: str
    label: str
    icon: str
    items: tuple


_MENU = (
    Group('configuration', 'Configuration', 'bi-sliders', (
        Item('system-global', 'System Settings', 'bi-gear',
             'FortiAnalyzer system global — hostname, timezone, admin timeout and GUI/idle settings.',
             (('system_global', 'Global'), ('system_ntp', 'NTP'),
              ('system_backup_all_settings', 'Scheduled backup'),
              ('system_password_policy', 'Password policy'),
              ('system_saml', 'SAML SSO'))),
        Item('network', 'Network', 'bi-hdd-network',
             'Management interfaces, static routes and DNS of the FortiAnalyzer unit.',
             (('system_interface', 'Interfaces'), ('system_route', 'Routes'),
              ('system_dns', 'DNS'))),
        Item('admin', 'Admin & Access', 'bi-person-badge',
             'Administrators, admin profiles, trusted hosts and authentication sources.',
             (('admin_user', 'Administrators'), ('admin_profile', 'Profiles'),
              ('admin_setting', 'Admin settings'), ('admin_ldap', 'LDAP'),
              ('admin_radius', 'RADIUS'))),
        Item('ha', 'High Availability', 'bi-diagram-3',
             'FortiAnalyzer HA cluster members, roles and configuration sync status.',
             (('sys_ha_status', 'Live status'), ('system_ha', 'HA config'))),
        Item('storage', 'Log Storage', 'bi-hdd-stack',
             'Disk allocation, data policy (analytics vs archive) and per-ADOM log quotas.',
             (('storage_info', 'ADOM storage'), ('sql_settings', 'SQL database'),
              ('log_settings', 'Log settings'), ('system_auto_delete', 'Auto delete'),
              ('locallog_setting', 'Local log'))),
        Item('certificates', 'Certificates', 'bi-shield-lock',
             'Local and CA certificates used by the FortiAnalyzer services.',
             (('system_certificate_local', 'Local'),
              ('system_certificate_ca', 'CA'))),
    )),
    Group('device-manager', 'Device Manager', 'bi-hdd-rack', (
        Item('adoms', 'ADOMs', 'bi-collection',
             'Administrative domains defined on the unit (per-product log buckets).',
             (('dvmdb_adom', 'ADOMs'),)),
        Item('devices', 'Devices', 'bi-router',
             'Devices registered to send logs, and the device groups that organize them.',
             (('dvmdb_device', 'Devices'), ('dvmdb_group', 'Groups'))),
    )),
    Group('operation', 'Operation', 'bi-tools', (
        Item('log-view', 'Log View', 'bi-journal-text',
             'Logging pipeline state: per-device log rates, forwarding and syslog targets.',
             (('logview_logstats', 'Log stats'), ('log_forward', 'Log forwarding'),
              ('system_syslog', 'Syslog servers'))),
        Item('fortiview', 'FortiView', 'bi-bar-chart-steps',
             'FortiView dashboards configuration and browse-time estimation settings.',
             (('system_fortiview_setting', 'Settings'),
              ('report_est_browse_time', 'Est. browse time'))),
        Item('incidents', 'Incidents & Events', 'bi-exclamation-octagon',
             'SOC incidents, the event monitor and alert triage.',
             (('eventmgmt_alerts', 'Alerts'),
              ('incidentmgmt_incidents', 'Incidents'))),
    )),
    Group('automation', 'Automation', 'bi-gear-wide-connected', (
        Item('event-handlers', 'Alert Delivery', 'bi-lightning-charge',
             'Alert console and alert-email delivery of triggered event handlers.',
             (('system_alert_console', 'Alert console'),
              ('system_alertemail', 'Alert email'))),
        Item('report-schedules', 'Reports', 'bi-file-earmark-bar-graph',
             'Report layouts, schedules, datasets and output profiles.',
             (('report_layouts', 'Layouts'), ('report_schedules', 'Schedules'),
              ('report_datasets', 'Datasets'), ('report_outputs', 'Output profiles'))),
        Item('playbooks', 'Tasks & Updates', 'bi-diagram-2',
             'Task monitor and FortiGuard update service state of the unit.',
             (('task_task', 'Tasks'), ('fmupdate_service', 'FortiGuard services'),
              ('system_workflow_approval_matrix', 'Approval matrix'))),
    )),
)


def menu():
    """The ordered tuple of FortiAnalyzer menu groups."""
    return _MENU


def find_item(key: str):
    """Return (group, item) for a leaf key, or None."""
    for g in _MENU:
        for it in g.items:
            if it.key == key:
                return g, it
    return None

"""FortiAnalyzer sidebar menu — the STATIC, backend-less mirror of adc_menu.

FortiADC/FortiWeb build their sidebar from the registry (live object types
resolved off a device). FortiAnalyzer has no REST/CMDB client yet (it speaks
JSON-RPC and its 'objects' are logs/reports/incidents, not config objects), so
its Configuration/Operation/Automation groups are a curated, static menu whose
leaves land on honest scaffold pages (:func:`app.views.faz.menu_page`). The
Fleet and Administration areas are NOT here — they reuse the real shared
blueprints and are hardcoded in the sidebar, exactly like FortiADC.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Item:
    key: str
    label: str
    icon: str = 'bi-dot'
    desc: str = ''


@dataclass(frozen=True)
class Group:
    key: str
    label: str
    icon: str
    items: tuple


_MENU = (
    Group('configuration', 'Configuration', 'bi-sliders', (
        Item('system-global', 'System Settings', 'bi-gear',
             'FortiAnalyzer system global — hostname, timezone, admin timeout and GUI/idle settings.'),
        Item('network', 'Network', 'bi-hdd-network',
             'Management interfaces, static routes and DNS of the FortiAnalyzer unit.'),
        Item('admin', 'Admin & Access', 'bi-person-badge',
             'Administrators, admin profiles, trusted hosts and authentication sources.'),
        Item('ha', 'High Availability', 'bi-diagram-3',
             'FortiAnalyzer HA cluster members, roles and configuration sync status.'),
        Item('storage', 'Log Storage', 'bi-hdd-stack',
             'Disk allocation, data policy (analytics vs archive) and per-ADOM log quotas.'),
        Item('certificates', 'Certificates', 'bi-shield-lock',
             'Local and CA certificates used by the FortiAnalyzer services.'),
    )),
    Group('operation', 'Operation', 'bi-tools', (
        Item('log-view', 'Log View', 'bi-journal-text',
             'Browse collected logs (traffic, event, security) across the managed devices.'),
        Item('fortiview', 'FortiView', 'bi-bar-chart-steps',
             'Real-time and historical FortiView dashboards and drill-downs.'),
        Item('incidents', 'Incidents & Events', 'bi-exclamation-octagon',
             'SOC incidents, the event monitor and alert triage.'),
    )),
    Group('automation', 'Automation', 'bi-gear-wide-connected', (
        Item('event-handlers', 'Event Handlers', 'bi-lightning-charge',
             'Event handler rules that trigger on log patterns and thresholds.'),
        Item('report-schedules', 'Report Schedules', 'bi-file-earmark-bar-graph',
             'Scheduled report templates, datasets and generated report runs.'),
        Item('playbooks', 'Playbooks', 'bi-diagram-2',
             'Playbooks, connectors and automation stitches (FortiSOAR-style).'),
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

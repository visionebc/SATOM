"""FortiGate sidebar menu — BASE ADOM (2026-10-07).

Groups follow the FortiOS 8.0 GUI's top-level menu (Network, Policy & Objects,
Security Profiles, VPN, User & Authentication, System, Log & Report). Each
leaf is one section page whose TABS are cmdb paths read live through
:class:`app.clients.fortigate.FortiGateClient`.

Every path below was checked against fgt02 (FortiOS 8.0.1 build0245): it is
in the 618-table schema captured with ``?action=schema`` AND answers GET 200
with the read-only ``satom-ro`` profile. ``tests/test_fgt_adom.py`` pins the
list against that capture, so a typo cannot ship as a 400 page.

What the base deliberately does NOT do yet:

* bind leaves through the endpoint registry (the FortiWeb/FAC "rename after an
  upgrade is a Registry edit" contract) — paths are literal here;
* write anything — section pages are read-only tables;
* cover the whole GUI — only the panes an operator opens first. The full
  table list per build lives in the API library (Build compatibility).
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Item:
    key: str
    label: str
    icon: str = 'bi-dot'
    desc: str = ''
    # (cmdb path, tab label) pairs — live tabs on the section page.
    tabs: tuple = field(default=())


@dataclass(frozen=True)
class Group:
    key: str
    label: str
    icon: str
    items: tuple


_MENU = (
    Group('network', 'Network', 'bi-diagram-3', (
        Item('interfaces', 'Interfaces', 'bi-ethernet',
             'Physical, VLAN, aggregate and tunnel interfaces, and zones.',
             (('system/interface', 'Interfaces'), ('system/zone', 'Zones'))),
        Item('dns', 'DNS', 'bi-signpost-split', 'System DNS servers.',
             (('system/dns', 'DNS settings'),)),
        Item('routing', 'Routing', 'bi-signpost-2',
             'Static routes and policy routes.',
             (('router/static', 'Static routes'),
              ('router/policy', 'Policy routes'))),
        Item('sdwan', 'SD-WAN', 'bi-shuffle', 'SD-WAN members, zones and rules.',
             (('system/sdwan', 'SD-WAN'),)),
        Item('dhcp', 'DHCP servers', 'bi-hdd-network', 'IPv4 DHCP servers.',
             (('system.dhcp/server', 'DHCP servers'),)),
    )),
    Group('policy', 'Policy & Objects', 'bi-shield-check', (
        Item('firewall_policy', 'Firewall Policy', 'bi-list-check',
             'IPv4/IPv6 firewall policies, in sequence order.',
             (('firewall/policy', 'Policies'),)),
        Item('addresses', 'Addresses', 'bi-geo-alt',
             'Address objects and address groups.',
             (('firewall/address', 'IPv4 addresses'),
              ('firewall/address6', 'IPv6 addresses'),
              ('firewall/addrgrp', 'Address groups'))),
        Item('services', 'Services', 'bi-plug',
             'Custom services and service groups.',
             (('firewall.service/custom', 'Services'),
              ('firewall.service/group', 'Service groups'))),
        Item('schedules', 'Schedules', 'bi-calendar-week',
             'Recurring schedules.',
             (('firewall.schedule/recurring', 'Recurring'),)),
        Item('vips', 'Virtual IPs', 'bi-arrow-left-right',
             'Destination NAT (virtual IPs).',
             (('firewall/vip', 'Virtual IPs'),)),
        Item('ippools', 'IP Pools', 'bi-collection',
             'Source NAT pools.', (('firewall/ippool', 'IP pools'),)),
        Item('shaping', 'Traffic Shaping', 'bi-speedometer',
             'Traffic shaping policies.',
             (('firewall/shaping-policy', 'Shaping policies'),)),
    )),
    Group('security', 'Security Profiles', 'bi-shield-lock', (
        Item('antivirus', 'AntiVirus', 'bi-bug', '',
             (('antivirus/profile', 'Profiles'),)),
        Item('webfilter', 'Web Filter', 'bi-funnel', '',
             (('webfilter/profile', 'Profiles'),)),
        Item('dnsfilter', 'DNS Filter', 'bi-funnel-fill', '',
             (('dnsfilter/profile', 'Profiles'),)),
        Item('appctrl', 'Application Control', 'bi-app-indicator', '',
             (('application/list', 'Sensors'),)),
        Item('ips', 'Intrusion Prevention', 'bi-shield-exclamation', '',
             (('ips/sensor', 'Sensors'),)),
        Item('sslinspect', 'SSL/SSH Inspection', 'bi-lock', '',
             (('firewall/ssl-ssh-profile', 'Profiles'),)),
    )),
    Group('vpn', 'VPN', 'bi-key', (
        Item('ipsec', 'IPsec Tunnels', 'bi-link-45deg',
             'Phase 1 and phase 2 interface-mode tunnels.',
             (('vpn.ipsec/phase1-interface', 'Phase 1'),
              ('vpn.ipsec/phase2-interface', 'Phase 2'))),
        Item('sslvpn', 'SSL-VPN Settings', 'bi-globe', '',
             (('vpn.ssl/settings', 'Settings'),)),
    )),
    Group('user', 'User & Authentication', 'bi-people', (
        Item('users', 'User Definition', 'bi-person', 'Local users.',
             (('user/local', 'Local users'),)),
        Item('groups', 'User Groups', 'bi-people-fill', '',
             (('user/group', 'Groups'),)),
        Item('servers', 'Authentication Servers', 'bi-server',
             'LDAP and RADIUS servers.',
             (('user/ldap', 'LDAP'), ('user/radius', 'RADIUS'))),
        Item('auth_settings', 'Authentication Settings', 'bi-sliders', '',
             (('user/setting', 'Settings'),)),
    )),
    Group('system', 'System', 'bi-hdd-stack', (
        Item('settings', 'Settings', 'bi-gear',
             'Global settings and the per-VDOM settings block.',
             (('system/global', 'Global'), ('system/settings', 'VDOM settings'),
              ('system/ntp', 'NTP'))),
        Item('admins', 'Administrators', 'bi-person-badge',
             'Administrators, REST API users and admin profiles. A token '
             'whose profile is read-only is served NO administrators at all '
             '(measured on fgt02: 0 rows while admin exists) — an empty '
             'list here is the profile, not the device.',
             (('system/admin', 'Administrators'),
              ('system/api-user', 'REST API users'),
              ('system/accprofile', 'Admin profiles'))),
        Item('ha', 'HA', 'bi-hdd-stack-fill', 'High-availability settings.',
             (('system/ha', 'HA'),)),
        Item('snmp', 'SNMP', 'bi-broadcast', '',
             (('system.snmp/community', 'Communities'),)),
        Item('certificates', 'Certificates', 'bi-patch-check',
             'Local and CA certificates.',
             (('vpn.certificate/local', 'Local'),
              ('vpn.certificate/ca', 'CA'))),
    )),
    Group('log', 'Log & Report', 'bi-journal-text', (
        Item('log_settings', 'Log Settings', 'bi-journal', '',
             (('log/setting', 'Log settings'),
              ('log.syslogd/setting', 'Syslog'))),
    )),
)


def menu() -> tuple:
    return _MENU


def visible_menu() -> tuple:
    """Same as :func:`menu` — no per-build pruning in the base ADOM."""
    return _MENU


def find_item(key: str):
    for g in _MENU:
        for it in g.items:
            if it.key == key:
                return g, it
    return None, None


def all_paths() -> list[str]:
    return [p for g in _MENU for it in g.items for p, _ in it.tabs]

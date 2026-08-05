"""FortiAuthenticator sidebar menu — the REAL FAC 8.0 GUI panes, verbatim.

Source of truth: the ``nav_menu_definition`` JSON block the unit itself serves
on ``GET /`` to an authenticated session — captured from fac01
(FACVMKVM v8.0.3 build0099) on 2026-08-05. That is a stronger source than the
administration guide the FortiAnalyzer menu was crawled from: it is what THIS
firmware actually renders, so it cannot drift from the documentation's release
cadence. The device declares **6 top-level groups and 129 leaves**.

Mapping rule, applied without exception:

* a top-level nav group  -> :class:`Group`
* a second-level pane    -> :class:`Item` (one section page)
* the API resources that back that pane's leaves -> its live TABS

This file must NOT invent groupings. When the GUI gains or moves a pane on an
upgrade, re-capture ``nav_menu_definition`` from the unit and mirror it here.

**The GUI is much wider than the API**: 129 leaves against 58 advertised REST
resources, of which 40 answer GET. Panes with no REST surface (Network,
Portals, SAML IdP, LDAP Service, the Monitor group, Certificate Authorities,
Log Access, …) keep an EMPTY ``logicals`` tuple on purpose, and their ``desc``
names which GUI leaves they cover and why nothing is bound. The page then
renders the honest "no endpoint bound" state instead of fabricating data — the
same contract FortiAnalyzer uses for its session-driven FortiView drilldowns.
Every one of the 40 GET-able registry endpoints is bound exactly once below;
``tests/test_fac_menu.py`` fails if that stops being true, so a resource can
neither go missing nor be double-listed.

Renaming a URI after a firmware upgrade is a Registry-page edit, never a code
change (same contract as FortiWeb/FortiADC/FortiAnalyzer). The Fleet and
Administration areas are NOT here — they reuse the real shared blueprints and
are hardcoded in the sidebar, exactly like the other product ADOMs.
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
    Group('system', 'System', 'bi-hdd-stack', (
        Item('dashboard', 'Dashboard', 'bi-speedometer2',
             'Unit status, serial, firmware and the per-feature licence '
             'counters. The GUI also has User Lookup and HA Status here; '
             'neither is exposed as a REST resource on 8.0.3.',
             (('system_info', 'Status'),)),
        Item('network', 'Network', 'bi-diagram-3',
             'Interfaces, DNS, static routing, Zero Trust tunnels and packet '
             'capture. FortiAuthenticator serves NO REST resource for any of '
             'them — the API is an identity API, not a device-config API. Use '
             'the unit GUI or its CLI for network changes.',
             ()),
        Item('administration', 'Administration', 'bi-sliders',
             'System access, HA, firmware, scheduled config backup, SNMP, '
             'licensing, FortiGuard, FTP servers, admin profiles, NetHSMs and '
             'replacement messages. Only the backup/SNMP/FTP panes have REST '
             'resources; the rest are GUI-only on 8.0.3.',
             (('system_scheduled_backup', 'Config auto-backup'),
              ('system_snmp_general', 'SNMP general'),
              ('system_snmp_hosts', 'SNMP hosts'),
              ('system_ftp_servers', 'FTP servers'))),
        Item('messaging', 'Messaging', 'bi-envelope',
             'SMTP servers, email services and SMS gateways. The FortiGuard '
             'messaging tab shows the SMS quota the unit reports for token '
             'delivery.',
             (('system_smtp_servers', 'SMTP servers'),
              ('token_fortiguard_messages', 'FortiGuard SMS quota'))),
    )),
    Group('authentication', 'Authentication', 'bi-person-badge', (
        Item('account-policies', 'User Account Policies', 'bi-shield-lock',
             'Password policies and lockout thresholds. The GUI also carries '
             'General, Custom User Fields, Token policy, Trusted Subnets and '
             'Adaptive MFA Rules under this pane — none of them is a REST '
             'resource on 8.0.3.',
             (('policy_password', 'Passwords'),
              ('policy_user_lockout', 'Lockouts'))),
        Item('user-management', 'User Management', 'bi-people',
             'Local, remote (LDAP/RADIUS) and IAM identities, their groups and '
             'memberships, MAC-authenticated devices and FortiToken '
             'inventory. Social Login Users, Guest Users, Usage Profiles, '
             'Realms and Remote User Sync Rules are GUI-only.',
             (('auth_local_users', 'Local users'),
              ('auth_ldap_users', 'LDAP users'),
              ('auth_radius_users', 'RADIUS users'),
              ('auth_user_groups', 'User groups'),
              ('auth_local_group_members', 'Group memberships'),
              ('auth_mac_devices', 'MAC devices'),
              ('auth_mac_groups', 'MAC groups'),
              ('auth_mac_group_members', 'MAC group memberships'),
              ('auth_iam_users', 'IAM users'),
              ('auth_iam_accounts', 'IAM accounts'),
              ('token_fortitokens', 'FortiTokens'),
              ('token_ftm_provisioning', 'FTM provisioning'),
              ('token_ftm_licenses', 'FTM licences'))),
        Item('remote-auth', 'Remote Auth. Servers', 'bi-hdd-network',
             'Upstream LDAP, RADIUS, TACACS+, OAuth and SAML servers this unit '
             'authenticates AGAINST. Not to be confused with the RADIUS/TACACS+ '
             'Service panes below, which are the clients that authenticate to '
             'this unit. No REST resource exposes the upstream servers on 8.0.3.',
             ()),
        Item('radius-service', 'RADIUS Service', 'bi-router',
             'NAS clients allowed to authenticate against this unit, their '
             'groups, the authentication policies and the bindings between '
             'them. Services, Dictionaries, Auth Profiles and Accounting Proxy '
             'are GUI-only.',
             (('radius_clients', 'Clients'),
              ('radius_client_groups', 'Client groups'),
              ('radius_policies', 'Policies'),
              ('radius_group_client', 'Group -> client'),
              ('radius_policy_client', 'Policy -> client'),
              ('radius_policy_client_group', 'Policy -> client group'))),
        Item('tacplus-service', 'TACACS+ Service', 'bi-terminal',
             'TACACS+ clients, client groups, policies and their bindings. The '
             'GUI Authorization pane has no REST resource on 8.0.3.',
             (('tacplus_clients', 'Clients'),
              ('tacplus_client_groups', 'Client groups'),
              ('tacplus_policies', 'Policies'),
              ('tacplus_group_client', 'Group -> client'),
              ('tacplus_policy_client', 'Policy -> client'),
              ('tacplus_policy_group', 'Policy -> group'))),
        Item('ldap-service', 'LDAP Service', 'bi-list-columns',
             'The LDAP directory this unit PUBLISHES (General + Directory '
             'Tree). No REST resource on 8.0.3 — the directory is served over '
             'LDAP itself, not over the API.',
             ()),
        Item('oauth-service', 'OAuth Service', 'bi-key',
             'Relying parties, scopes, policies and portals. The unit DOES '
             'advertise an ``oauth`` resource, but it answers 403 even to a '
             'valid API key (verified 2026-08-05) — it is privileged or '
             'internal, so nothing is bound rather than binding an endpoint '
             'that always errors.',
             ()),
        Item('saml-idp', 'SAML IdP', 'bi-box-arrow-in-right',
             'SAML identity-provider settings, service providers and user '
             'sources. GUI-only on 8.0.3.',
             ()),
        Item('scim', 'SCIM', 'bi-arrow-left-right',
             'SCIM service provider configuration. GUI-only on 8.0.3.',
             ()),
        Item('portals', 'Portals', 'bi-window',
             'Self-service portal policies, portals, access points and '
             'replacement messages, plus the beta Guest Portals tree. '
             'GUI-only on 8.0.3.',
             ()),
        Item('fac-agent', 'FAC Agent', 'bi-windows',
             'Microsoft Windows and Outlook Web Access agent configuration. '
             'GUI-only on 8.0.3.',
             ()),
    )),
    Group('fortinet-sso', 'Fortinet SSO', 'bi-diagram-2', (
        Item('sso-settings', 'Settings', 'bi-gear',
             'FortiGate registration, collection methods, tiered architecture '
             'and log config. Only the FortiGate group filter is exposed over '
             'REST.',
             (('sso_fgt_group_filter', 'FortiGate group filter'),)),
        Item('sso-methods', 'Methods', 'bi-collection',
             'Web services, SAML authentication, Windows event log, RADIUS '
             'accounting and syslog collectors. GUI-only on 8.0.3.',
             ()),
        Item('sso-filtering', 'Filtering', 'bi-funnel',
             'The SSO groups pushed to FortiGates. SSO Users, Fine-grained '
             'Controls, Domain Groupings and IP Rules are GUI-only.',
             (('sso_groups', 'SSO groups'),)),
    )),
    Group('monitor', 'Monitor', 'bi-activity', (
        Item('monitor-sso', 'SSO', 'bi-people-fill',
             'Live domains, SSO sessions, connected event-log sources, '
             'FortiGates, DC/TS agents and NTLM statistics. These are session '
             'monitors; the API exposes none of them as a readable list on '
             '8.0.3.',
             ()),
        Item('monitor-auth', 'Authentication', 'bi-lock',
             'Locked-out users and IPs, live RADIUS sessions, Windows AD and '
             'device logins, SAML IdP sessions, OAuth tokens and active users. '
             'The advertised ``idpsessiondata`` resource answers 405 on GET '
             '(verified) — it is a POST action, not a readable list.',
             ()),
    )),
    Group('certificates', 'Certificate Management', 'bi-patch-check', (
        Item('cert-policies', 'Policies', 'bi-sliders2',
             'Certificate expiry policy. GUI-only on 8.0.3.',
             ()),
        Item('cert-end-entities', 'End Entities', 'bi-file-earmark-lock',
             'Issued user certificates with their subject, issuer, serial, '
             'expiry and revocation state. Local Services (server '
             'certificates) is GUI-only.',
             (('cert_user_certificates', 'User certificates'),)),
        Item('cert-authorities', 'Certificate Authorities', 'bi-building',
             'Local CAs, CRLs and trusted CAs. GUI-only on 8.0.3 — the API '
             'exposes issued end-entity certificates but not the authorities '
             'that signed them.',
             ()),
        Item('cert-scep', 'SCEP', 'bi-arrow-repeat',
             'Pending SCEP enrolment requests. This is an operational queue, '
             'so it is deliberately EXCLUDED from the configuration snapshot '
             '(see device_sync._FAC_SOT_EXCLUDE) — otherwise every harvest '
             'would record churn as a config change.',
             (('cert_scep_requests', 'Enrolment requests'),)),
        Item('cert-cmp', 'CMP', 'bi-arrow-left-right',
             'CMP general settings and enrolment requests. GUI-only on 8.0.3.',
             ()),
    )),
    Group('logging', 'Logging', 'bi-journal-text', (
        Item('log-access', 'Log Access', 'bi-search',
             'Alert logs, log records and log types. The unit serves these '
             'through its own log viewer, not through ``/api/v1/`` — nothing '
             'is bound rather than showing an empty table that looks like '
             '"no logs".',
             ()),
        Item('log-config', 'Log Config', 'bi-gear-wide-connected',
             'Log retention, remote FortiAnalyzer/syslog forwarding and the '
             'configured syslog servers.',
             (('system_log_settings', 'Log settings'),
              ('system_syslog_servers', 'Syslog servers'))),
        Item('log-audit', 'Audit Reports', 'bi-clipboard-data',
             'The per-user audit report the GUI renders. GUI-only on 8.0.3.',
             ()),
    )),
)


def visible_menu() -> tuple:
    """The menu as rendered. Kept as a function (not a bare constant) so the
    sidebar and the section pages share one entry point, matching faz_menu."""
    return _MENU


def all_items() -> tuple:
    return tuple(it for g in _MENU for it in g.items)


def find_item(key: str):
    """(group, item) for a section key, or (None, None)."""
    for g in _MENU:
        for it in g.items:
            if it.key == key:
                return g, it
    return None, None


def bound_logicals() -> tuple:
    """Every registry logical bound by the menu, in menu order.

    Used by the guard test that asserts the menu and
    ``endpoints_fortiauthenticator.yaml`` cover exactly the same set: a
    resource that falls out of the menu becomes unreachable from the UI while
    still being harvested, and one bound twice renders the same table on two
    pages. Neither failure raises an error on its own.
    """
    return tuple(lg for it in all_items() for (lg, _label) in it.logicals)

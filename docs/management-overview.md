# Fortinet Manager Web — Management Overview

> **Audience:** managers and non-technical stakeholders. No networking or
> programming knowledge is assumed. Technical readers should see the
> [User Guide](user-guide.md) and the [Engineering Manual](engineering.md).

---

## 1. What is it?

Fortinet Manager Web is an in-house web application that our team uses to
operate the company's **Fortinet security appliances** — the devices that sit
in front of our web applications and protect them (FortiWeb, a *web
application firewall*) and balance their traffic (FortiADC, a *load
balancer*).

Think of it as a **single control room** for a fleet of security devices:
instead of logging into each appliance one by one and clicking through its
own administration screens, engineers work from one place that knows about
every device, remembers every change, and enforces our safety rules.

## 2. The problem it solves

Managing these appliances directly has real business risks:

| Without the manager | With the manager |
|---|---|
| Each device is configured by hand, one at a time — slow and error-prone | Policies and objects are edited centrally, with reusable patterns and cloning between devices |
| A mistyped change can take a customer service offline, with no record of what changed | Every change is **previewed before it happens**, recorded with before/after detail, and reversible from backups |
| Knowledge lives in individual engineers' heads | The fleet's entire configuration is stored, searchable, and documented in one system |
| Risky work (firmware upgrades) depends on individual discipline | Upgrades only run inside an **approved maintenance window**, with automatic backups and service checks before and after |
| If a device fails or its license lapses, visibility disappears | The manager keeps a local copy of every device's configuration — teams keep working and planning even when a device is unreachable |

## 3. What it can do (in business terms)

- **See everything:** a live map of the fleet — which public services exist,
  which device publishes them, which servers are behind them, and which
  security profile protects each one.
- **Change safely:** every modification shows a preview first, is logged with
  who/when/what, and destructive actions require approvals.
- **Recover quickly:** automatic configuration backups (even for devices with
  expired licenses), a restore vault, and a full backup of the manager
  itself.
- **Standardize:** templates and naming rules keep configurations consistent
  across devices; exceptions to security rules are tracked per customer
  service so nothing is forgotten when services move.
- **Automate routine work:** nightly device syncs, certificate scans,
  scheduled backups, and report generation run unattended.
- **Manage certificates:** a central inventory of TLS certificates with
  expiry tracking and automated issuance/renewal against our certificate
  authority.
- **Integrate:** other systems can read fleet data through a restricted,
  token-based API that cannot perform dangerous actions.

## 4. How mature is it?

- Version 1.0, in production use by the team.
- **700+ automated tests** run against every change — the test suite must
  pass before code is deployed.
- Every feature that talks to a real device was verified against live lab
  appliances before release.
- Complete documentation at three levels (user, engineering, management —
  you are reading one of them).

## 5. Security posture (plain language)

- Access requires individual accounts with role-based permissions; admin
  functions are separated from day-to-day operator functions. Optional
  two-factor authentication and corporate directory login are supported.
- Device passwords are stored **encrypted**; the encryption key lives only on
  the server, outside the code repository.
- The application enforces modern browser security policies (the same class
  of protections used by banking front-ends) and locks accounts after
  repeated failed logins.
- Every action is audited: who did what, when, and what changed.
- The riskiest operation — updating device firmware — cannot run without an
  explicitly approved change request and maintenance window.

## 6. Risks & current limitations (honest list)

| Risk / limitation | Status |
|---|---|
| The default administrator password is documented and must be changed at installation | Procedure documented; enforce at rollout |
| One deployment, one site — no high-availability pair of the manager itself yet | Mitigated by full system backups with verified restore; the appliances themselves keep working without the manager |
| FortiADC support is newer than FortiWeb support; some device actions (firmware, restore-apply) are not possible remotely because the vendor provides no interface for them | The UI states these limits explicitly |
| The project knowledge base inside the repository references internal infrastructure details | Should be reviewed/sanitized before sharing the code externally |
| Depends on vendor firmware behavior; a major vendor API change requires catalog updates (designed to be data edits, not code rewrites) | Low effort by design |

## 7. What it costs to run

- **Infrastructure:** one small Linux container (a few GB of RAM), a
  PostgreSQL database, and a Redis cache — negligible hosting cost on
  existing virtualization.
- **Maintenance:** routine OS/library updates; the install script upgrades
  the app in place. Backups are automated.
- **People:** built and maintained in-house; the engineering manual enables
  any Python/Flask developer to take over.

## 8. Roadmap candidates (for prioritization)

1. Publish the repository externally (open source or portfolio) — requires a
   final sanitization pass and a license decision.
2. High-availability deployment of the manager (a second, read-only standby
   exists in early form).
3. Deeper FortiADC parity as the vendor's interface allows.
4. E-mail delivery of client maintenance notices (today they are generated
   and tracked, not sent automatically).
5. Continuous integration runners so the test suite runs automatically on
   every code push.

## 9. Glossary

| Term | Meaning |
|---|---|
| **WAF** | Web Application Firewall — filters malicious traffic before it reaches a web application |
| **FortiWeb / FortiADC** | Fortinet's WAF and load-balancer products, the devices this app manages |
| **Server Policy** | The rule on a FortiWeb that publishes one web service: where traffic enters, which servers answer, which protections apply |
| **ADOM** | "Administrative domain" — a workspace inside the app scoped to one product family |
| **Dry-run** | A preview of a change that shows exactly what would happen without doing it |
| **Change Request** | A recorded, approved maintenance window that authorizes risky work |
| **Certificate** | The cryptographic file that makes a website show the padlock (HTTPS); it expires and must be renewed |
| **Registry** | The app's catalog of device commands, editable as data — how the app adapts to new firmware without reprogramming |

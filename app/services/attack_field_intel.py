"""Field-by-field investigation help for one attack-log entry.

The detail panel used to be a flat key/value dump: eighty rows, every one of
them a bare string. That tells an operator what the box recorded, not what any
of it *means*, and the fields that decide a false-positive call — is that source
address the real client or a proxy, is that URL actually traversal or just
percent-encoded punctuation, is that user agent a browser — are exactly the ones
a bare string hides.

So each field gets: what it is, what this particular value classifies as, and
the concrete follow-ups worth doing. The verdict stays the operator's; this
module supplies the facts the verdict is made of.

**Everything here is computed locally.** No WHOIS, no geolocation service, no
threat-intelligence API. Two reasons, both firm:

1. Those lookups are a **data export**. The attacker IPs, hostnames and URLs of
   the customer's own traffic would leave the appliance for a third party, from
   a page whose whole point is deciding what to trust — and nobody approved
   that export. SATOM already keeps a redaction boundary and an export log for
   the AI path; a quiet side-channel from the field panel would walk straight
   around it.
2. This product ships onto isolated management networks. An enrichment that
   only works with internet access is an enrichment that is missing exactly
   where the WAF is most locked down, and it would fail slowly (DNS/HTTP
   timeouts) inside a panel the operator opened to move fast.

The one network call is an optional reverse-DNS lookup against **this host's own
resolver** — the same resolver the appliance manager already uses — hard-capped
so an unreachable resolver costs a second and a half, once.
"""
from __future__ import annotations

import ipaddress
import re
import socket
from concurrent.futures import ThreadPoolExecutor, TimeoutError as _FTimeout
from urllib.parse import parse_qsl, unquote, urlsplit

#: Reverse DNS is best-effort garnish, never a gate. Capped hard: an isolated
#: management network has no resolver and must not make the panel feel broken.
_PTR_TIMEOUT_S = 1.5

#: The ranges that actually mean "there is an intermediary in front of this".
_RFC1918 = [ipaddress.ip_network(n) for n in
            ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', 'fc00::/7')]

#: Documentation/example ranges. ``ipaddress`` calls these private too, which is
#: technically true and operationally misleading — see :func:`_ip_intel`.
_DOCS = [ipaddress.ip_network(n) for n in
         ('192.0.2.0/24', '198.51.100.0/24', '203.0.113.0/24', '2001:db8::/32')]


def _in_any(ip, nets) -> bool:
    return any(ip.version == n.version and ip in n for n in nets)

# --------------------------------------------------------------------------- #
#  What each field IS — plain language, independent of the value               #
# --------------------------------------------------------------------------- #
FIELD_HELP: dict[str, str] = {
    'src': 'The address FortiWeb saw the request arrive from. Behind a CDN, '
           'load balancer or reverse proxy this is the intermediary, not the '
           'end user.',
    'src_port': 'The client\'s ephemeral source port. Almost never meaningful '
                'on its own — it is chosen by the client\'s OS per connection.',
    'dst': 'The virtual server / VIP address the request was sent to. This is '
           'which of your published services was targeted.',
    'dst_port': 'The port the request arrived on, i.e. which listener of the '
                'virtual server handled it.',
    'srccountry': 'Country FortiWeb\'s own geo database maps the source address '
                  'to. Resolved on the appliance, not by SATOM.',
    'http_host': 'The Host header — which site the client asked for. This, not '
                 'the destination IP, is what selects the Server Policy on a '
                 'shared VIP.',
    'http_url': 'The request path and query string as received, before the '
                'backend saw it.',
    'http_method': 'The HTTP verb. Whether the request intended to read or to '
                   'change something.',
    'http_agent': 'The client-supplied User-Agent. Trivially forged — useful as '
                  'a signal, never as proof.',
    'http_refer': 'The client-supplied Referer. When it points at your own '
                  'application, the request probably came from your own UI.',
    'signature_id': 'The specific FortiWeb signature that matched. This is the '
                    'narrowest thing you can carve out.',
    'signature_subclass': 'The signature\'s sub-class — the family the matching '
                          'rule belongs to.',
    'signature_cve_id': 'The CVE the signature is written for, when it targets '
                        'a specific published vulnerability.',
    'owasp_top10': 'Which OWASP Top-10 category the match falls under. A '
                   'reporting label, not a detection setting.',
    'policy': 'The Server Policy that handled the request. This decides which '
              'Web Protection Profile — and therefore which exceptions — apply.',
    'action': 'What FortiWeb actually did. "Alert" means the request was '
              'allowed through and only logged.',
    'threat_level': 'FortiWeb\'s own severity weighting for the match.',
    'severity_level': 'Log severity. Independent of how confident the detection '
                      'is.',
    'monitor_status': 'Whether the profile was in monitor (alert-only) mode. In '
                      'monitor mode nothing was blocked, so there may be '
                      'nothing to carve out.',
    'server_pool_name': 'The back-end pool the policy would have forwarded to.',
    'msg': 'The appliance\'s own description of the match.',
}

# --------------------------------------------------------------------------- #
#  Value classifiers                                                           #
# --------------------------------------------------------------------------- #
#: Ports worth naming without asking the OS. ``getservbyport`` disagrees with
#: what a WAF operator means for several of these (8080 is "http-alt" to glibc,
#: "the app server behind the WAF" here).
_PORTS: dict[int, str] = {
    80: 'HTTP', 443: 'HTTPS', 8080: 'HTTP (alternate / back-end app server)',
    8443: 'HTTPS (alternate)', 8000: 'HTTP (alternate)', 8888: 'HTTP (alternate)',
    22: 'SSH', 21: 'FTP', 25: 'SMTP', 3306: 'MySQL', 5432: 'PostgreSQL',
    6379: 'Redis', 27017: 'MongoDB', 1433: 'MSSQL', 3389: 'RDP', 9443: 'HTTPS (admin)',
}

#: Substring → what it says about the client. Ordered: first match wins, so the
#: explicit attack tools are listed before the generic runtimes they are built on
#: (sqlmap identifies as sqlmap, but a bare "python-requests" is just a script).
_AGENTS: list[tuple[str, str, str]] = [
    ('sqlmap', 'scanner', 'sqlmap — an automated SQL-injection tool. This is '
                          'not a browser and not a health check.'),
    ('nikto', 'scanner', 'Nikto web scanner.'),
    ('nessus', 'scanner', 'Nessus vulnerability scanner.'),
    ('acunetix', 'scanner', 'Acunetix scanner.'),
    ('nmap', 'scanner', 'Nmap scripting engine.'),
    ('masscan', 'scanner', 'masscan.'),
    ('dirbuster', 'scanner', 'DirBuster — directory brute-forcing.'),
    ('gobuster', 'scanner', 'gobuster — directory/vhost brute-forcing.'),
    ('wpscan', 'scanner', 'WPScan — WordPress enumeration.'),
    ('havij', 'scanner', 'Havij — SQL-injection tool.'),
    ('zgrab', 'scanner', 'zgrab — internet-wide scanning.'),
    ('curl/', 'tool', 'curl. A script or a person testing by hand — common for '
                      'monitoring and for probing alike.'),
    ('wget', 'tool', 'wget.'),
    ('python-requests', 'tool', 'A Python script using requests.'),
    ('python-urllib', 'tool', 'A Python script using urllib.'),
    ('go-http-client', 'tool', 'A Go program\'s default HTTP client.'),
    ('java/', 'tool', 'A Java program\'s default HTTP client.'),
    ('postmanruntime', 'tool', 'Postman.'),
    ('googlebot', 'crawler', 'Claims to be Googlebot. Verify by reverse DNS '
                             'before trusting it — the header is forgeable.'),
    ('bingbot', 'crawler', 'Claims to be Bingbot. Header is forgeable.'),
    ('ahrefsbot', 'crawler', 'AhrefsBot — commercial SEO crawler.'),
    ('semrushbot', 'crawler', 'SemrushBot — commercial SEO crawler.'),
    ('uptimerobot', 'monitor', 'UptimeRobot — an availability monitor.'),
    ('pingdom', 'monitor', 'Pingdom — an availability monitor.'),
    ('kube-probe', 'monitor', 'A Kubernetes liveness/readiness probe.'),
    ('elb-healthchecker', 'monitor', 'An AWS load-balancer health check.'),
    ('mozilla/', 'browser', 'Presents as a browser. Nearly every real browser '
                            'and plenty of tools start their agent this way.'),
]

#: Patterns worth pointing at inside a URL. Descriptive — a hit is a thing to
#: look at, never a verdict. Deliberately conservative: this panel exists to
#: help a human judge, and a false "SQL injection!" badge on a search box that
#: happens to contain the word ``select`` teaches operators to ignore the badge.
_URL_FLAGS: list[tuple[str, str, str]] = [
    (r'\.\./|\.\.%2f|%2e%2e/', 'path traversal',
     'Contains "../" (or an encoded form). Traversal sequences are how a '
     'request reaches files outside the web root.'),
    (r'%00|\x00', 'null byte',
     'Contains a null byte. Legitimate URLs do not; null bytes are used to '
     'truncate filename checks.'),
    (r'%25[0-9a-f]{2}', 'double encoding',
     'Percent sign is itself encoded (%25xx). Double encoding is used to slip '
     'a payload past one decoding layer and have it decoded by the next.'),
    (r'(?i)\bunion\b[\s/*]+\bselect\b', 'SQL union',
     'Contains "UNION SELECT". That pairing is rare in legitimate traffic.'),
    (r'(?i)<script[\s>]|javascript:|onerror\s*=', 'script injection',
     'Contains script-injection syntax.'),
    (r'(?i)/(etc/passwd|proc/self/environ|windows/win\.ini)', 'system file',
     'Names a well-known system file — a canonical file-disclosure probe.'),
    (r'(?i)\b(cmd|exec|system|passthru|shell_exec)\s*\(', 'command execution',
     'Contains a command-execution function call.'),
    (r'(?i)\$\{jndi:', 'JNDI lookup',
     'Contains a ${jndi:} lookup — the Log4Shell pattern.'),
]

_SAFE_METHODS = {'GET', 'HEAD', 'OPTIONS', 'TRACE'}
_WRITE_METHODS = {'POST', 'PUT', 'PATCH', 'DELETE'}

#: Which log keys are which kind of thing. Anything unlisted gets the generic
#: treatment rather than being dropped — an unknown field is still worth showing.
FIELD_KIND: dict[str, str] = {
    'src': 'ip', 'dst': 'ip', 'x_forwarded_for': 'ip',
    'src_port': 'port', 'dst_port': 'port',
    'http_url': 'url', 'http_host': 'host', 'http_method': 'method',
    'http_agent': 'agent', 'http_refer': 'referer',
    'signature_id': 'signature', 'signature_subclass': 'text',
    'signature_cve_id': 'cve', 'srccountry': 'country',
}


def _fact(label: str, value, note: str = '') -> dict:
    return {'label': label, 'value': '' if value is None else str(value),
            'note': note}


def _ptr(addr: str) -> str:
    """Reverse DNS via this host's resolver, hard-capped. '' on any failure.

    Run on a worker thread because ``gethostbyaddr`` ignores socket timeouts on
    glibc: without the cap an unreachable resolver stalls the whole panel for
    the system resolver timeout, which on an isolated network is the normal case.
    """
    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            return pool.submit(socket.gethostbyaddr, addr).result(
                timeout=_PTR_TIMEOUT_S)[0]
    except (_FTimeout, OSError, IndexError, Exception):  # noqa: BLE001
        return ''


def _ip_intel(value: str, *, resolve_ptr: bool = True) -> dict:
    facts: list[dict] = []
    notes: list[str] = []
    try:
        ip = ipaddress.ip_address(value.strip())
    except ValueError:
        return {'facts': [_fact('Parsed', 'no', 'Not a valid IP address.')],
                'notes': [], 'classification': 'unparseable'}

    facts.append(_fact('Version', 'IPv%d' % ip.version))
    if ip.is_loopback:
        kind = 'loopback'
        notes.append('This is a loopback address — the request originated on '
                     'the appliance itself, or the real client address was '
                     'lost before logging.')
    elif _in_any(ip, _RFC1918):
        kind = 'private (RFC1918)'
        notes.append('This is a private address, so the request reached '
                     'FortiWeb from inside your network — typically a reverse '
                     'proxy, load balancer or CDN node. The real client is in '
                     'the X-Forwarded-For header; if you carve out on this '
                     'address you carve out for EVERY client behind that '
                     'intermediary.')
    elif _in_any(ip, _DOCS):
        # ``ipaddress`` reports the documentation ranges as ``is_private``, so
        # a bare ``is_private`` check labels TEST-NET traffic "RFC1918" and
        # tells the operator to go looking for a reverse proxy that does not
        # exist. They mean something quite different and much more interesting.
        kind = 'documentation range (RFC 5737/3849)'
        notes.append('This address is reserved for documentation and examples. '
                     'It should never appear as a real client — either the '
                     'traffic was synthetic (a test or a scan using placeholder '
                     'addresses), or something upstream rewrote the source.')
    elif ip.is_private:
        kind = 'special-purpose / reserved'
        notes.append('IANA reserves this range for a special purpose rather '
                     'than for ordinary internet hosts. Treat it as a routing '
                     'or configuration signal, not as an end user.')
    elif ip.version == 4 and ip in ipaddress.ip_network('100.64.0.0/10'):
        kind = 'carrier-grade NAT'
        notes.append('This is CGNAT space. It is shared by many unrelated '
                     'subscribers of one carrier — never treat it as one user.')
    elif ip.is_multicast:
        kind = 'multicast'
    elif ip.is_reserved or ip.is_link_local:
        kind = 'reserved / link-local'
    else:
        kind = 'public'
    facts.append(_fact('Scope', kind))

    if ip.version == 4:
        octets = str(ip).split('.')
        facts.append(_fact('/24 network', '.'.join(octets[:3]) + '.0/24',
                           'Use this to spot a burst from one neighbourhood.'))
    if resolve_ptr and kind == 'public':
        ptr = _ptr(str(ip))
        facts.append(_fact('Reverse DNS (PTR)', ptr or '(none / not resolvable)',
                           'Resolved by this manager\'s DNS, not by a third '
                           'party. A crawler claiming to be Googlebot should '
                           'have a googlebot.com PTR.' if ptr else
                           'No PTR record, or no resolver reachable from here.'))
    return {'facts': facts, 'notes': notes, 'classification': kind}


def _port_intel(value: str) -> dict:
    try:
        port = int(str(value).strip())
    except (TypeError, ValueError):
        return {'facts': [], 'notes': [], 'classification': ''}
    name = _PORTS.get(port)
    if not name:
        try:
            name = socket.getservbyport(port)
        except OSError:
            name = ''
    facts = [_fact('Port', port, name or 'No well-known service.')]
    if 1024 <= port <= 65535 and port not in _PORTS:
        facts.append(_fact('Range', 'ephemeral / registered',
                           'Ports above 1023 are picked by the client OS per '
                           'connection. A source port is not an identifier.'))
    elif port < 1024:
        facts.append(_fact('Range', 'well-known (< 1024)'))
    return {'facts': facts, 'notes': [], 'classification': name or ''}


def _url_intel(value: str) -> dict:
    raw = str(value or '')
    parts = urlsplit(raw if '://' in raw else ('http://placeholder' + raw
                                               if raw.startswith('/') else raw))
    decoded = unquote(raw)
    facts = [_fact('Path', parts.path or '/'),
             _fact('Length', len(raw),
                   'Unusually long paths are a common overflow/obfuscation '
                   'signal.' if len(raw) > 512 else '')]
    if decoded != raw:
        facts.append(_fact('Percent-decoded', decoded,
                           'This is what the value becomes after one decoding '
                           'pass — judge the DECODED form, not the raw one.'))
    params = []
    if parts.query:
        for k, v in parse_qsl(parts.query, keep_blank_values=True):
            params.append({'name': k, 'value': v})
        facts.append(_fact('Query parameters', len(params)))
    ext = ''
    if '.' in (parts.path or '').rsplit('/', 1)[-1]:
        ext = (parts.path or '').rsplit('.', 1)[-1][:12]
        facts.append(_fact('Extension', '.' + ext))

    flags = []
    hay = raw + '\n' + decoded
    for rx, label, why in _URL_FLAGS:
        if re.search(rx, hay):
            flags.append({'label': label, 'note': why})
    return {'facts': facts, 'notes': [], 'classification': ext,
            'params': params, 'flags': flags,
            'decoded': decoded if decoded != raw else ''}


def _agent_intel(value: str) -> dict:
    ua = str(value or '')
    low = ua.lower()
    if not ua.strip():
        return {'facts': [_fact('User-Agent', '(empty)',
                                'No User-Agent at all. Browsers always send '
                                'one; scripts and scanners often do not.')],
                'notes': [], 'classification': 'absent'}
    for needle, kind, why in _AGENTS:
        if needle in low:
            return {'facts': [_fact('Client type', kind, why),
                              _fact('Length', len(ua))],
                    'notes': ['A User-Agent is client-supplied text. It is '
                              'evidence of intent, never proof of identity.'],
                    'classification': kind}
    return {'facts': [_fact('Client type', 'unrecognised',
                            'Matches no known browser, tool or crawler pattern.'),
                      _fact('Length', len(ua))],
            'notes': [], 'classification': 'unknown'}


def _method_intel(value: str) -> dict:
    m = str(value or '').strip().upper()
    if m in _SAFE_METHODS:
        note = ('A read-only method by definition. It can still carry an '
                'injection payload in the URL or headers.')
        cls = 'safe'
    elif m in _WRITE_METHODS:
        note = 'A state-changing method — the request intended to write.'
        cls = 'write'
    else:
        note = ('Not one of the standard verbs. Unusual methods are often the '
                'thing the Allow Method check blocked.')
        cls = 'unusual'
    return {'facts': [_fact('Method', m or '(none)', note)], 'notes': [],
            'classification': cls}


def _signature_intel(value: str) -> dict:
    sid = str(value or '').strip()
    facts = [_fact('Signature ID', sid)]
    if re.fullmatch(r'\d{9,10}', sid):
        facts.append(_fact(
            'Main class', sid[:-6].rjust(3, '0') + '000000',
            'The first digits identify the signature\'s main class. Carving out '
            'the CLASS disables far more than carving out this one signature.'))
        facts.append(_fact(
            'Narrowest carve-out', 'Signature Exception (per-id)',
            'A per-id exception with an element match (URL, host or client IP) '
            'skips ONLY this signature and ONLY where you say — it is the '
            'smallest change that fixes a false positive.'))
    return {'facts': facts, 'notes': [], 'classification': ''}


def _cve_intel(value: str) -> dict:
    cve = str(value or '').strip()
    return {'facts': [_fact('CVE', cve,
                            'The signature targets a published vulnerability. '
                            'If your back-end is not the affected product or '
                            'version, a match here is very likely a false '
                            'positive — confirm the version, then carve out.')],
            'notes': [], 'classification': ''}


def _host_intel(value: str) -> dict:
    host = str(value or '').strip()
    facts = [_fact('Host', host)]
    if ':' in host:
        facts.append(_fact('Includes port', host.rsplit(':', 1)[-1]))
    try:
        ipaddress.ip_address(host.split(':')[0])
        facts.append(_fact('Form', 'IP literal',
                           'The client addressed the site by IP, not by name. '
                           'Normal browsers use the hostname; scanners sweeping '
                           'address ranges use the literal.'))
    except ValueError:
        labels = host.split('.')
        if len(labels) >= 2:
            facts.append(_fact('Registrable domain', '.'.join(labels[-2:])))
    return {'facts': facts, 'notes': [], 'classification': ''}


_KIND_FN = {
    'ip': _ip_intel, 'port': _port_intel, 'url': _url_intel,
    'agent': _agent_intel, 'method': _method_intel,
    'signature': _signature_intel, 'cve': _cve_intel, 'host': _host_intel,
}


def describe(key: str, value, *, resolve_ptr: bool = True) -> dict:
    """Everything worth knowing about ONE field of ONE entry.

    ``value`` is whatever the log row held. Returns a dict the panel renders
    directly — never raises, because a field that cannot be analysed must still
    show its value.
    """
    kind = FIELD_KIND.get(key, 'text')
    out = {'key': key, 'value': '' if value is None else str(value),
           'kind': kind, 'help': FIELD_HELP.get(key, ''),
           'facts': [], 'notes': [], 'flags': [], 'params': [],
           'classification': '', 'decoded': ''}
    fn = _KIND_FN.get(kind)
    if fn is None or not str(out['value']).strip():
        return out
    try:
        if kind == 'ip':
            res = fn(out['value'], resolve_ptr=resolve_ptr)
        else:
            res = fn(out['value'])
    except Exception as exc:  # noqa: BLE001 — analysis is garnish, the value is the point
        out['facts'] = [_fact('Analysis', 'unavailable', str(exc)[:200])]
        return out
    out.update({k: v for k, v in res.items() if k in out})
    return out


def correlate(rows: list[dict], key: str, value) -> dict:
    """How often *value* appears in *key* across a set of recent entries.

    The single most useful thing about a source address during triage is
    whether it is one request or a campaign, and that answer is already sitting
    in the log the page just read. One address, twelve signatures, four minutes
    is not a false positive; one address, one signature, once, from your own
    office range, usually is.
    """
    want = str(value or '')
    if not want or not rows:
        return {'total': 0, 'matches': 0, 'types': [], 'policies': [], 'urls': []}
    hits = [r for r in rows if str(r.get(key) or '') == want]
    def _distinct(k):
        seen = []
        for r in hits:
            v = str(r.get(k) or '').strip()
            if v and v != 'N/A' and v not in seen:
                seen.append(v)
        return seen[:8]
    return {'total': len(rows), 'matches': len(hits),
            'types': _distinct('main_type'), 'policies': _distinct('policy'),
            'urls': _distinct('http_url')}

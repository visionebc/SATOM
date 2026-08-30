#!/usr/bin/env python3
"""Create/destroy a two-backend fixture on a FortiWeb, one REAL and one FAKE.

The point of the fixture is that the ground truth is known BEFORE the script
under test runs:

    192.0.2.41:18080   a real HTTP server, same L2 as the appliance -> must be UP
    192.0.2.10:80     TEST-NET-1, RFC 5737, can never be a host    -> must be DOWN

The fake address is deliberately NOT a free LAN address: a free 10.0.0.x could
be claimed by DHCP between two runs and the test would start lying.

Teardown deletes in reverse dependency order; a FortiWeb refuses to delete an
object that is still referenced, so the order is not cosmetic.
"""
import sys, json, argparse
sys.dont_write_bytecode = True
sys.path.insert(0, '/opt/satom')
from dotenv import load_dotenv
load_dotenv('/opt/satom/.env')
from app import create_app
from app.models import Appliance
from app.clients.fortiweb import FortiWebClient

CMDB = '/api/v2.0/cmdb/'
VIP, VS, POOL, POL = 'vip-satom-test', 'vs-satom-test', 'pool-satom-test', 'pol-satom-test'
REAL = {'ip': '192.0.2.41', 'port': 18080}
FAKE = {'ip': '192.0.2.10', 'port': 80}

#: Start the real backend on REAL['ip'] first, or setup creates a fixture whose
#: "real" half is down and the run proves nothing:
#:     python3 testbackend.py 18080     # answers HEAD / with 200, any path


def call(c, method, ep, data=None):
    r = getattr(c, method)(CMDB + ep, data) if data is not None else getattr(c, method)(CMDB + ep)
    try:
        body = r.json()
    except Exception:
        body = {'raw': r.text[:200]}
    code = body.get('errcode', body.get('results', {}).get('errcode') if isinstance(body.get('results'), dict) else None)
    print('  %-6s %-58s http=%s errcode=%s %s' % (
        method.upper(), ep[:58], r.status_code, code,
        '' if r.status_code == 200 else json.dumps(body)[:160]))
    return r.status_code == 200, body


def setup(c):
    print('CREATE')
    call(c, 'post', 'system/vip', {'data': {'name': VIP, 'vip': '240.0.99.99/24', 'interface': 'port2'}})
    call(c, 'post', 'server-policy/vserver', {'data': {'name': VS}})
    call(c, 'post', 'server-policy/vserver/vip-list?mkey=' + VS,
         {'data': {'vip': VIP, 'status': 'enable'}})
    call(c, 'post', 'server-policy/server-pool',
         {'data': {'name': POOL, 'type': 'reverse-proxy', 'protocol': 'HTTP',
                   'server-balance': 'enable', 'health': 'HLTHCK_HTTP'}})
    for tag, m in (('REAL', REAL), ('FAKE', FAKE)):
        print('  member %s -> %s:%s' % (tag, m['ip'], m['port']))
        call(c, 'post', 'server-policy/server-pool/pserver-list?mkey=' + POOL,
             {'data': {'server-type': 'physical', 'ip': m['ip'], 'port': m['port'],
                       'weight': 1, 'status': 'enable'}})
    call(c, 'post', 'server-policy/policy',
         {'data': {'name': POL, 'deployment-mode': 'server-pool', 'protocol': 'HTTP',
                   'service': 'HTTP', 'vserver': VS, 'server-pool': POOL,
                   'web-protection-profile': 'Inline Alert Only'}})


def teardown(c):
    print('DELETE (reverse dependency order)')
    call(c, 'delete', 'server-policy/policy?mkey=' + POL)
    for seq in ('2', '1'):
        call(c, 'delete', 'server-policy/server-pool/pserver-list?mkey=%s&sub_mkey=%s' % (POOL, seq))
    call(c, 'delete', 'server-policy/server-pool?mkey=' + POOL)
    call(c, 'delete', 'server-policy/vserver/vip-list?mkey=%s&sub_mkey=1' % VS)
    call(c, 'delete', 'server-policy/vserver?mkey=' + VS)
    call(c, 'delete', 'system/vip?mkey=' + VIP)


def show(c):
    print('STATE')
    for ep, key in (('server-policy/policy', POL), ('server-policy/server-pool', POOL),
                    ('server-policy/vserver', VS), ('system/vip', VIP)):
        names = [x.get('name') for x in (c.get(CMDB + ep).json().get('results') or [])]
        print('  %-32s %s' % (key, 'PRESENT' if key in names else 'absent'))
    rows = c.get(CMDB + 'server-policy/server-pool/pserver-list?mkey=' + POOL).json().get('results') or []
    for r in rows:
        print('  member seq=%s %s:%s status=%s' % (r.get('seq'), r.get('ip'), r.get('port'), r.get('status')))


ap = argparse.ArgumentParser()
ap.add_argument('mode', choices=['setup', 'teardown', 'show'])
ap.add_argument('--appliance', default='fortiweb13')
ap.add_argument('--real', default='192.0.2.41:18080',
                help='host:port of the REAL backend (must already be serving)')
ap.add_argument('--fake', default='192.0.2.10:80',
                help='host:port that can never answer (default: RFC 5737 TEST-NET-1)')
a = ap.parse_args()
for tgt, flag in ((REAL, a.real), (FAKE, a.fake)):
    h, _, p = flag.partition(':')
    tgt['ip'], tgt['port'] = h, int(p or 80)

app = create_app()
with app.app_context():
    c = FortiWebClient(Appliance.query.filter_by(name=a.appliance).one())
    {'setup': setup, 'teardown': teardown, 'show': show}[a.mode](c)

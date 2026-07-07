"""Pure-builder tests for the FortiADC guided virtual-server wizard.

No device I/O — asserts the plan is well-formed and validates inputs the same
way the view does before it ever calls the box.
"""
from app.services import adc_objform


def _spec(**kw):
    base = dict(vs_name='vs-x', pool_name='pool-x', address='192.0.2.10',
                real_servers=[{'name': 'rs-1', 'address': '192.0.2.20'}])
    base.update(kw)
    return base


def test_valid_plan_is_bottom_up():
    steps, errors = adc_objform.build_virtual_server_plan(_spec())
    assert errors == []
    order = [(s['kind'], s['logical']) for s in steps]
    # real server(s) -> pool -> member(s) -> virtual server
    assert order == [
        ('object', 'load_balance_real_server'),
        ('object', 'load_balance_pool'),
        ('child', 'load_balance_pool_child_pool_member'),
        ('object', 'load_balance_virtual_server'),
    ]
    vs = steps[-1]['payload']
    assert vs['pool'] == 'pool-x' and vs['address'] == '192.0.2.10'
    mem = steps[2]
    assert mem['pkey'] == 'pool-x' and mem['payload']['real_server_id'] == 'rs-1'


def test_missing_pool_and_vs_name():
    _s, errors = adc_objform.build_virtual_server_plan(
        _spec(vs_name='', pool_name=''))
    assert any('Virtual server name' in e for e in errors)
    assert any('Pool name' in e for e in errors)


def test_no_real_servers():
    _s, errors = adc_objform.build_virtual_server_plan(_spec(real_servers=[]))
    assert any('At least one real server' in e for e in errors)


def test_bad_ip_rejected():
    _s, errors = adc_objform.build_virtual_server_plan(_spec(address='not-an-ip'))
    assert any('not a valid IP' in e for e in errors)


def test_duplicate_real_server_names():
    _s, errors = adc_objform.build_virtual_server_plan(_spec(real_servers=[
        {'name': 'dup', 'address': '192.0.2.20'},
        {'name': 'dup', 'address': '192.0.2.21'}]))
    assert any('unique' in e for e in errors)


def test_blank_rows_are_skipped():
    steps, errors = adc_objform.build_virtual_server_plan(_spec(real_servers=[
        {'name': 'rs-1', 'address': '192.0.2.20'},
        {'name': '', 'address': ''}]))
    assert errors == []
    members = [s for s in steps if s['kind'] == 'child']
    assert len(members) == 1


def test_multiple_servers_get_sequential_member_ids():
    steps, _e = adc_objform.build_virtual_server_plan(_spec(real_servers=[
        {'name': 'rs-1', 'address': '192.0.2.20'},
        {'name': 'rs-2', 'address': '192.0.2.21'}]))
    members = [s for s in steps if s['kind'] == 'child']
    assert [m['mkey'] for m in members] == ['1', '2']
    assert [m['payload']['real_server_id'] for m in members] == ['rs-1', 'rs-2']

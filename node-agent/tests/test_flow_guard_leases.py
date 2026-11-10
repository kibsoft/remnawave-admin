import collections
import importlib.util
import subprocess
import sys
from pathlib import Path
from unittest.mock import Mock
import pytest

spec = importlib.util.spec_from_file_location("lease_guard", Path(__file__).parents[1]/"flow-guard"/"flow_guard.py")
g = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = g
spec.loader.exec_module(g)

@pytest.fixture
def setup():
    firewall = Mock(ttl=120)
    owner = Mock()
    now = [0.0]
    counts = collections.Counter()
    leases = g.BlockLeases(firewall, owner, counts, clock=lambda: now[0])
    flow = g.Flow(4, 'udp', '8.8.8.8', 42000, '1.1.1.1', 18000)
    owner.resolve_identity.return_value = (flow, '123')
    return leases, firewall, owner, now, counts, flow

def test_same_socket_stays_blocked_beyond_original_timeout(setup):
    leases, fw, owner, now, counts, flow = setup
    assert leases.confirm(flow, '123')
    for second in (40, 80, 120, 160, 200):
        now[0] = second
        leases.maintain()
    assert flow in leases.entries
    assert fw.renew.call_count == 5
    assert counts['blocks'] == 1

def test_repeated_dpi_confirmation_renews_and_is_rate_limited(setup):
    leases, fw, owner, now, counts, flow = setup
    leases.confirm(flow, '123')
    now[0] = 10
    assert not leases.confirm(flow, '123')
    fw.renew.assert_called_once_with(flow)
    leases.confirm(flow, '123')
    assert fw.renew.call_count == 1
    assert counts['blocks'] == 1 and counts['detection_renewals'] == 1

@pytest.mark.parametrize('replacement', [None, '456'])
def test_closed_or_replaced_socket_releases_exact_flow(setup, replacement):
    leases, fw, owner, now, counts, flow = setup
    leases.confirm(flow, '123')
    owner.resolve_identity.return_value = None if replacement is None else (flow, replacement)
    now[0] = 2
    leases.maintain()
    fw.unblock.assert_called_once_with(flow)
    fw.renew.assert_not_called()
    assert not leases.entries

def test_confirmed_new_socket_can_be_blocked_independently(setup):
    leases, fw, owner, now, counts, flow = setup
    leases.confirm(flow, '123')
    now[0] = 2
    assert leases.confirm(flow, '456')
    assert leases.entries[flow].inode == '456'
    assert fw.block.call_count == 2 and fw.unblock.call_count == 1

def test_ownership_failure_never_renews_or_falsely_deletes(setup):
    leases, fw, owner, now, counts, flow = setup
    leases.confirm(flow, '123')
    owner.resolve_identity.side_effect = PermissionError('proc denied')
    now[0] = 50
    leases.maintain()
    fw.renew.assert_not_called()
    fw.unblock.assert_not_called()
    assert counts['lease_errors'] == 1
    assert leases.entries[flow].refreshed_at == 0

def test_failed_refresh_does_not_move_safety_deadline(setup):
    leases, fw, owner, now, counts, flow = setup
    leases.confirm(flow, '123')
    fw.renew.side_effect = subprocess.CalledProcessError(1, 'nft')
    now[0] = 50
    leases.maintain()
    assert leases.entries[flow].refreshed_at == 0
    assert counts['lease_errors'] == 1

def test_dry_run_never_mutates_firewall(setup):
    leases, fw, owner, now, counts, flow = setup
    leases.enforce = False
    leases.confirm(flow, '123')
    now[0] = 50
    leases.maintain()
    owner.resolve_identity.return_value = None
    leases.maintain()
    assert fw.method_calls == []
    assert counts['would_block'] == 1

def test_atomic_nft_renewal_recreates_only_exact_element():
    fw = g.Firewall()
    fw.run = Mock()
    flow = g.Flow(6, 'tcp', '2001:4860:4860::8888', 42000, '2606:4700:4700::1111', 18000)
    fw.renew(flow)
    script = fw.run.call_args.args[0]
    assert script.count('delete element') == 1
    assert script.count('add element') == 1
    assert 'tcp6' in script and 'timeout 120s' in script
    assert 'flush' not in script

def test_atomic_renewal_retries_add_only_when_element_expired():
    fw = g.Firewall()
    flow = g.Flow(4, 'udp', '8.8.8.8', 42000, '1.1.1.1', 18000)
    fw.run = Mock(side_effect=[subprocess.CalledProcessError(1,'nft',stderr='No such file or directory'), None])
    fw.renew(flow)
    assert fw.run.call_count == 2
    assert fw.run.call_args.args[0].startswith('add element')
    fw.run = Mock(side_effect=subprocess.CalledProcessError(1,'nft',stderr='Operation not permitted'))
    with pytest.raises(subprocess.CalledProcessError): fw.renew(flow)
    assert fw.run.call_count == 1


def test_identity_tracks_inode_and_direction_and_rejects_foreign_socket(tmp_path):
    net = tmp_path/'net'
    net.mkdir()
    (net/'tcp').write_text('header\n 0: 08080808:A410 01010101:4650 01 0:0 00:0 0 0 0 123\n')
    owner = g.SocketOwner(tmp_path)
    owner.refresh = lambda: None
    owner.inodes = {'123'}
    flow = g.Flow(4, 'tcp', '8.8.8.8', 42000, '1.1.1.1', 18000)
    assert owner.resolve_identity(flow) == (flow, '123')
    reversed_flow = g.Flow(4, 'tcp', flow.peer_ip, flow.peer_port, flow.local_ip, flow.local_port)
    assert owner.resolve_identity(reversed_flow) == (flow, '123')
    owner.inodes = {'456'}
    assert owner.resolve_identity(flow) is None
    owner.inodes = {'123'}
    owner.tables.clear()
    (net/'tcp').write_text('header\n')
    assert owner.resolve_identity(flow) is None

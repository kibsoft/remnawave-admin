import json
from pathlib import Path
from datetime import datetime,timezone
from unittest.mock import patch
from src.collectors.flow_enforcement import collect_flow_enforcement

def state():
    now=datetime.now(timezone.utc)
    return dict(updated_at=now.timestamp(),started_at=now.timestamp(),mode="enforce",connected=True,counts={'blocks':3},
      firewall=dict(sampled_at=now.isoformat(),table_handle=7,active_flows=2,dropped_packets=10,dropped_bytes=800,
        input_packets=4,output_packets=6,input_bytes=300,output_bytes=500))

def test_guard_snapshot_has_real_kernel_values_and_stable_table_epoch(tmp_path):
    p=tmp_path/'status.json';d=state();p.write_text(json.dumps(d))
    with patch('pathlib.Path.read_text',return_value='test-boot'):
        a=collect_flow_enforcement(str(p));assert a is not None
        assert a.firewall.dropped_packets==10
        d['started_at']-=10;p.write_text(json.dumps(d))
        b=collect_flow_enforcement(str(p));assert a.firewall.epoch==b.firewall.epoch
        d['firewall']['table_handle']=8;p.write_text(json.dumps(d))
        assert collect_flow_enforcement(str(p)).firewall.epoch!=a.firewall.epoch

def test_optional_missing_corrupt_and_oversized_status(tmp_path):
    p=tmp_path/'status.json'
    assert collect_flow_enforcement(str(p)) is None
    p.write_text('{broken');assert collect_flow_enforcement(str(p)) is None
    p.write_text('x'*32769);assert collect_flow_enforcement(str(p)) is None

def test_kernel_failure_does_not_create_zero_counter_snapshot(tmp_path):
    p=tmp_path/'status.json';d=state();d['firewall']=None;p.write_text(json.dumps(d))
    a=collect_flow_enforcement(str(p));assert a is not None and a.firewall is None

def test_stale_snapshot_keeps_original_timestamp(tmp_path):
    p=tmp_path/'status.json';d=state();d['updated_at']-=300;d['firewall']=None;p.write_text(json.dumps(d))
    a=collect_flow_enforcement(str(p));assert a.sampled_at.timestamp()==d['updated_at']


def test_kernel_snapshot_sums_actual_drop_rules_and_preserves_table_identity():
    import importlib.util
    import sys
    from types import SimpleNamespace
    spec = importlib.util.spec_from_file_location("flow_guard", Path(__file__).parents[1]/"flow-guard"/"flow_guard.py")
    guard = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = guard
    spec.loader.exec_module(guard)
    payload = {"nftables": [
        {"table": {"handle": 42}},
        {"set": {"elem": [{"elem": {}}, {"elem": {}}]}},
        {"rule": {"chain": "input", "expr": [{"counter": {"packets": 3, "bytes": 90}}, {"drop": None}]}},
        {"rule": {"chain": "output", "expr": [{"counter": {"packets": 5, "bytes": 200}}, {"drop": None}]}},
    ]}
    with patch.object(guard.subprocess, "run", return_value=SimpleNamespace(stdout=json.dumps(payload))) as run:
        sample = guard.Firewall().snapshot()
    assert sample["table_handle"] == 42
    assert sample["active_flows"] == 2
    assert sample["dropped_packets"] == 8
    assert sample["dropped_bytes"] == 290
    assert sample["input_packets"] == 3
    assert sample["output_packets"] == 5
    assert run.call_args.args[0] == ["nft", "-a", "-j", "list", "table", "inet", guard.TABLE]
    with patch.object(guard.subprocess, "run", return_value=SimpleNamespace(stdout='{"nftables": []}')):
        import pytest
        with pytest.raises(ValueError):
            guard.Firewall().snapshot()

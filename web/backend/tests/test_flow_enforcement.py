import copy
import json
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, MagicMock, patch
import pytest
from pydantic import ValidationError
from shared.flow_enforcement import FlowEnforcementReport
from shared.db.flow_enforcement import counter_rates, FlowEnforcementMixin
from web.backend.api.v2 import advanced_analytics, collector
from web.backend.tests.test_collector_api import make_db_mock, make_batch, NODE_UUID, AGENT_HEADERS

@pytest.fixture(autouse=True)
def reset_node_rate_limit():
    collector._node_last_batch.clear()
    yield
    collector._node_last_batch.clear()

def snapshot(seconds=0, packets=100, epoch="epoch-a"):
    at=(datetime.now(timezone.utc)+timedelta(seconds=seconds)).isoformat()
    return dict(schema_version=1,sampled_at=at,guard_started_at=at,mode="enforce",ndpi_connected=True,blocks_applied=2,
      firewall=dict(sampled_at=at,epoch=epoch,active_flows=2,dropped_packets=packets,dropped_bytes=packets*100,
        input_packets=packets,output_packets=0,input_bytes=packets*100,output_bytes=0))

def test_contract_rejects_negative_future_and_extra_node_identity():
    for mutate in [lambda d:d.update(node_uuid=NODE_UUID),lambda d:d["firewall"].update(dropped_packets=-1),
                   lambda d:d.update(sampled_at=(datetime.now(timezone.utc)+timedelta(hours=1)).isoformat())]:
        d=snapshot();mutate(d)
        with pytest.raises(ValidationError):FlowEnforcementReport(**d)

def test_rates_are_not_totals_and_reset_safely():
    a=snapshot(-30,100);b=copy.deepcopy(a)
    b['firewall']['sampled_at']=(datetime.fromisoformat(a['firewall']['sampled_at'])+timedelta(seconds=30)).isoformat()
    b['firewall'].update(dropped_packets=160,dropped_bytes=16000)
    assert counter_rates(a,b)=={'packets_per_second':2.0,'bytes_per_second':200.0}
    assert counter_rates(b,b) is None
    b['firewall']['epoch']='new';assert counter_rates(a,b) is None
    b['firewall']['epoch']=a['firewall']['epoch'];b['firewall']['dropped_packets']=0
    assert counter_rates(a,b) is None

@pytest.mark.asyncio
async def test_authenticated_snapshot_is_saved_only_for_token_node(anon_client):
    db=make_db_mock();db.save_flow_enforcement_snapshot=AsyncMock()
    body=make_batch();body['flow_enforcement']=snapshot()
    with patch.object(collector,'db_service',db),patch.object(collector,'get_node_by_token',AsyncMock(return_value=NODE_UUID)):
        resp=await anon_client.post('/api/v2/collector/batch',json=body,headers=AGENT_HEADERS)
    assert resp.status_code==200,resp.text
    assert db.save_flow_enforcement_snapshot.await_args.args[0]==NODE_UUID

@pytest.mark.asyncio
async def test_wrong_node_cannot_write_snapshot(anon_client):
    db=make_db_mock();db.save_flow_enforcement_snapshot=AsyncMock()
    body=make_batch('ffffffff-0000-0000-0000-000000000000');body['flow_enforcement']=snapshot()
    with patch.object(collector,'db_service',db),patch.object(collector,'get_node_by_token',AsyncMock(return_value=NODE_UUID)):
        resp=await anon_client.post('/api/v2/collector/batch',json=body,headers=AGENT_HEADERS)
    assert resp.status_code==403
    db.save_flow_enforcement_snapshot.assert_not_awaited()

@pytest.mark.asyncio
async def test_dashboard_passes_node_scope_to_storage(client):
    db=MagicMock();db.get_flow_enforcement_snapshots=AsyncMock(return_value=[])
    with patch.object(advanced_analytics,'_db',return_value=db),patch.object(advanced_analytics,'_node_scope',AsyncMock(return_value=[NODE_UUID])):
        resp=await client.get('/api/v2/analytics/advanced/flow-enforcement')
    assert resp.status_code==200
    db.get_flow_enforcement_snapshots.assert_awaited_once_with([NODE_UUID])

@pytest.mark.asyncio
async def test_dashboard_requires_authentication(anon_client):
    resp=await anon_client.get('/api/v2/analytics/advanced/flow-enforcement')
    assert resp.status_code in (401,403)

class FakeDB(FlowEnforcementMixin):
    def __init__(self, conn):
        cm=MagicMock();cm.__aenter__=AsyncMock(return_value=conn);cm.__aexit__=AsyncMock(return_value=False)
        self.acquire=lambda:cm

@pytest.mark.asyncio
async def test_duplicate_and_old_snapshots_do_not_rewrite_or_add_counters():
    old=snapshot(-60);new=snapshot(-30)
    conn=AsyncMock();conn.fetchrow=AsyncMock(return_value={'flow_enforcement':json.dumps(new)})
    tx=MagicMock();tx.__aenter__=AsyncMock();tx.__aexit__=AsyncMock(return_value=False);conn.transaction=MagicMock(return_value=tx)
    db=FakeDB(conn)
    await db.save_flow_enforcement_snapshot(NODE_UUID,new)
    await db.save_flow_enforcement_snapshot(NODE_UUID,old)
    conn.execute.assert_not_awaited()

@pytest.mark.asyncio
async def test_unknown_stale_disconnected_and_kernel_failure_are_not_zeroes():
    fresh=snapshot();stale=snapshot(-120);disconnected=snapshot();disconnected['ndpi_connected']=False
    unavailable=snapshot();unavailable['firewall']=None
    data=[None,stale,disconnected,unavailable,fresh]
    conn=AsyncMock();conn.fetch=AsyncMock(return_value=[{'uuid':str(i),'name':str(i),'flow_enforcement':d,'flow_enforcement_received_at':None} for i,d in enumerate(data)])
    result=await FakeDB(conn).get_flow_enforcement_snapshots([])
    assert [r['state'] for r in result]==['not_reporting','stale','disconnected','kernel_unavailable','enforce']
    assert result[0]['snapshot'] is None
    assert result[1]['snapshot']['firewall']['dropped_packets']==100

"""Atomic latest snapshots per authenticated node; duplicates never add to counters."""
import json
from datetime import datetime, timezone

def counter_rates(previous, current):
    a, b = (previous or {}).get("firewall"), current.get("firewall")
    if not a or not b or a["epoch"] != b["epoch"]:
        return None
    seconds = (datetime.fromisoformat(b["sampled_at"]) - datetime.fromisoformat(a["sampled_at"])).total_seconds()
    packets = b["dropped_packets"] - a["dropped_packets"]
    size = b["dropped_bytes"] - a["dropped_bytes"]
    if seconds <= 0 or seconds > 180 or packets < 0 or size < 0:
        return None
    return {"packets_per_second": round(packets / seconds, 3), "bytes_per_second": round(size / seconds, 3)}

class FlowEnforcementMixin:
    async def save_flow_enforcement_snapshot(self, node_uuid, snapshot):
        async with self.acquire() as conn:
            async with conn.transaction():
                row = await conn.fetchrow("SELECT flow_enforcement FROM nodes WHERE uuid=$1::uuid FOR UPDATE", node_uuid)
                if row is None:
                    return
                previous = row["flow_enforcement"]
                if isinstance(previous, str):
                    previous = json.loads(previous)
                if previous and datetime.fromisoformat(previous["sampled_at"]) >= datetime.fromisoformat(snapshot["sampled_at"]):
                    return
                snapshot = {**snapshot, "rates": counter_rates(previous, snapshot)}
                await conn.execute("UPDATE nodes SET flow_enforcement=$2::jsonb, flow_enforcement_received_at=NOW() WHERE uuid=$1::uuid", node_uuid, json.dumps(snapshot))

    async def get_flow_enforcement_snapshots(self, node_uuids=None):
        async with self.acquire() as conn:
            rows = await conn.fetch("SELECT uuid, name, flow_enforcement, flow_enforcement_received_at FROM nodes WHERE ($1::uuid[] IS NULL OR uuid=ANY($1::uuid[])) ORDER BY name", node_uuids)
        now = datetime.now(timezone.utc)
        result = []
        for row in rows:
            data = row["flow_enforcement"]
            if isinstance(data, str):
                data = json.loads(data)
            state = "not_reporting"
            if data:
                fw = data.get("firewall")
                age = (now - datetime.fromisoformat(data["sampled_at"])).total_seconds()
                kernel_age = (now - datetime.fromisoformat(fw["sampled_at"])).total_seconds() if fw else 0
                if age > 90 or kernel_age > 90:
                    state = "stale"
                elif not data["ndpi_connected"]:
                    state = "disconnected"
                elif not fw:
                    state = "kernel_unavailable"
                else:
                    state = data["mode"]
            result.append({"node_uuid": str(row["uuid"]), "node_name": row["name"], "state": state, "received_at": row["flow_enforcement_received_at"], "snapshot": data})
        return result

"""Read an optional local guard snapshot; never read packet data or run a firewall command."""
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from pydantic import ValidationError
from ..flow_enforcement_contract import FlowEnforcementReport

def collect_flow_enforcement(path: str):
    if not path:
        return None
    try:
        p = Path(path)
        with p.open("rb") as f:
            raw = f.read(32769)
        if len(raw) > 32768:
            return None
        state = json.loads(raw)
        if not isinstance(state, dict) or not isinstance(state.get("counts", {}), dict):
            return None
        fw = state.get("firewall")
        if fw is not None and not isinstance(fw, dict):
            return None
        if fw is not None:
            # The kernel table handle survives guard restarts; boot ID prevents
            # a reboot from making a newly created table look like the old one.
            boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
            fw = dict(fw)
            handle = fw.pop("table_handle")
            fw["epoch"] = hashlib.sha256((boot + ":" + str(handle)).encode()).hexdigest()[:32]
        return FlowEnforcementReport(
            sampled_at=datetime.fromtimestamp(state["updated_at"], timezone.utc),
            guard_started_at=datetime.fromtimestamp(state["started_at"], timezone.utc),
            mode=state["mode"], ndpi_connected=state["connected"],
            blocks_applied=state.get("counts", {}).get("blocks", 0),
            firewall=fw,
        )
    except (OSError, ValueError, KeyError, TypeError, OverflowError, ValidationError):
        return None

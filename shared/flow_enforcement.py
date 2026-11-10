"""Versioned, address-free flow enforcement telemetry. Counters are snapshots, not increments."""
from datetime import datetime, timezone, timedelta
from typing import Literal, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator

class FirewallSnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid")
    sampled_at: datetime
    epoch: str = Field(min_length=1, max_length=96)
    active_flows: int = Field(ge=0, le=16384)
    dropped_packets: int = Field(ge=0, le=2**63-1)
    dropped_bytes: int = Field(ge=0, le=2**63-1)
    input_packets: int = Field(ge=0, le=2**63-1)
    output_packets: int = Field(ge=0, le=2**63-1)
    input_bytes: int = Field(ge=0, le=2**63-1)
    output_bytes: int = Field(ge=0, le=2**63-1)

    @field_validator("sampled_at")
    @classmethod
    def valid_timestamp(cls, value):
        if value.tzinfo is None or value > datetime.now(timezone.utc) + timedelta(seconds=30):
            raise ValueError("Expected an aware, non-future timestamp")
        return value

class FlowEnforcementReport(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal[1] = 1
    sampled_at: datetime
    guard_started_at: datetime
    mode: Literal["enforce", "dry-run"]
    ndpi_connected: bool
    blocks_applied: int = Field(ge=0, le=2**63-1)
    firewall: Optional[FirewallSnapshot] = None

    _valid_times = field_validator("sampled_at", "guard_started_at")(FirewallSnapshot.valid_timestamp.__func__)

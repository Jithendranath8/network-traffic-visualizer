from __future__ import annotations
from typing import List, Dict, Optional
from pydantic import BaseModel, Field


class ProtocolCounts(BaseModel):
    tcp: int = 0
    udp: int = 0
    icmp: int = 0
    other: int = 0


class BandwidthPoint(BaseModel):
    timestamp_ms: int = Field(..., description="Unix epoch milliseconds")
    bytes: int


class TopTalker(BaseModel):
    ip: str
    bytes: int
    packets: int


class StatsSnapshot(BaseModel):
    protocol_counts: ProtocolCounts
    bandwidth_series: List[BandwidthPoint]
    top_talkers: List[TopTalker]


class WSMessage(StatsSnapshot):
    pass


class PacketDetail(BaseModel):
    id: int = Field(..., description="Unique packet ID")
    timestamp_ms: int = Field(..., description="Unix epoch milliseconds")
    src_ip: str
    dst_ip: str
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: str
    size_bytes: int
    data_length: int = Field(..., description="Payload/data length in bytes")
    flags: Optional[str] = None
    info: str = Field(..., description="Human-readable packet summary")


class PacketList(BaseModel):
    packets: List[PacketDetail]
    total: int

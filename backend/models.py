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


class FlowDetail(BaseModel):
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    first_seen: float
    last_seen: float
    duration: float
    total_bytes: int
    packet_count: int
    bytes_per_sec: float
    tcp_flags: List[str] = []


class FlowList(BaseModel):
    flows: List[FlowDetail]
    total: int


class SecurityAlert(BaseModel):
    timestamp: float
    alert_type: str
    severity: str
    source_ip: str
    description: str
    evidence: Dict
    acknowledged: bool = False


class AlertList(BaseModel):
    alerts: List[SecurityAlert]
    total: int


class GeoIPInfo(BaseModel):
    ip: str
    country: Optional[str] = None
    city: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None


class TopTalkerGeo(BaseModel):
    ip: str
    bytes: int
    packets: int
    geo: Optional[GeoIPInfo] = None

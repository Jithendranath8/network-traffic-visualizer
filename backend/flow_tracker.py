"""
Flow Tracker - Tracks network sessions using 5-tuple
"""
from __future__ import annotations
import time
import threading
from collections import defaultdict
from typing import Dict, Optional, Tuple, Set
from dataclasses import dataclass, field


@dataclass
class Flow:
    """Represents a network flow (session)"""
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    first_seen: float
    last_seen: float
    total_bytes: int = 0
    packet_count: int = 0
    tcp_flags: Set[str] = field(default_factory=set)
    
    @property
    def duration(self) -> float:
        """Flow duration in seconds"""
        return self.last_seen - self.first_seen
    
    @property
    def bytes_per_sec(self) -> float:
        """Average bytes per second"""
        if self.duration == 0:
            return 0.0
        return self.total_bytes / self.duration
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization"""
        return {
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "duration": self.duration,
            "total_bytes": self.total_bytes,
            "packet_count": self.packet_count,
            "bytes_per_sec": self.bytes_per_sec,
            "tcp_flags": list(self.tcp_flags),
        }


class FlowTracker:
    """Tracks network flows using 5-tuple (src_ip, dst_ip, src_port, dst_port, protocol)"""
    
    def __init__(self, idle_timeout_seconds: int = 300):
        """
        Args:
            idle_timeout_seconds: Flows idle for this duration are expired
        """
        self.idle_timeout = idle_timeout_seconds
        self.lock = threading.RLock()
        # Key: (src_ip, dst_ip, src_port, dst_port, protocol)
        self.flows: Dict[Tuple[str, str, int, int, str], Flow] = {}
        self._expired_flows: list[Flow] = []  # Store expired flows for history
        
    def _make_key(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int, protocol: str) -> Tuple[str, str, int, int, str]:
        """Create a normalized flow key (bidirectional flows use consistent ordering)"""
        # Normalize: always use smaller IP/port first for bidirectional tracking
        if src_ip < dst_ip or (src_ip == dst_ip and src_port < dst_port):
            return (src_ip, dst_ip, src_port, dst_port, protocol)
        else:
            return (dst_ip, src_ip, dst_port, src_port, protocol)
    
    def update_flow(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: Optional[int],
        dst_port: Optional[int],
        protocol: str,
        bytes_count: int,
        tcp_flags: Optional[str] = None
    ) -> Flow:
        """
        Update or create a flow
        
        Args:
            src_ip: Source IP address
            dst_ip: Destination IP address
            src_port: Source port (None for non-port protocols)
            dst_port: Destination port (None for non-port protocols)
            bytes_count: Bytes in this packet
            tcp_flags: TCP flags string (comma-separated)
        
        Returns:
            The updated or created Flow
        """
        # Handle non-port protocols
        src_port = src_port or 0
        dst_port = dst_port or 0
        
        now = time.time()
        key = self._make_key(src_ip, dst_ip, src_port, dst_port, protocol)
        
        with self.lock:
            if key not in self.flows:
                # Create new flow
                flow = Flow(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    protocol=protocol,
                    first_seen=now,
                    last_seen=now,
                )
                self.flows[key] = flow
            else:
                flow = self.flows[key]
            
            # Update flow metrics
            flow.last_seen = now
            flow.total_bytes += bytes_count
            flow.packet_count += 1
            
            if tcp_flags:
                for flag in tcp_flags.split(','):
                    flow.tcp_flags.add(flag.strip())
            
            return flow
    
    def expire_idle_flows(self) -> list[Flow]:
        """
        Remove flows that have been idle beyond the timeout
        
        Returns:
            List of expired flows
        """
        now = time.time()
        expired = []
        
        with self.lock:
            to_remove = []
            for key, flow in self.flows.items():
                if now - flow.last_seen > self.idle_timeout:
                    to_remove.append((key, flow))  # Store both key and flow
            
            for key, flow in to_remove:
                self.flows.pop(key)
                expired.append(flow)  # Append the flow, not None
                self._expired_flows.append(flow)
        
        return expired
    
    def get_active_flows(self, limit: Optional[int] = None) -> list[Flow]:
        """
        Get all active flows
        
        Args:
            limit: Maximum number of flows to return (None for all)
        
        Returns:
            List of active flows, sorted by last_seen (most recent first)
        """
        with self.lock:
            flows = list(self.flows.values())
            flows.sort(key=lambda f: f.last_seen, reverse=True)
            if limit:
                flows = flows[:limit]
            return flows
    
    def get_flow_stats(self) -> dict:
        """Get aggregate statistics about flows"""
        with self.lock:
            active_count = len(self.flows)
            total_bytes = sum(f.total_bytes for f in self.flows.values())
            total_packets = sum(f.packet_count for f in self.flows.values())
            
            return {
                "active_flows": active_count,
                "total_bytes": total_bytes,
                "total_packets": total_packets,
                "expired_flows": len(self._expired_flows),
            }
    
    def clear(self):
        """Clear all flows"""
        with self.lock:
            self.flows.clear()
            self._expired_flows.clear()
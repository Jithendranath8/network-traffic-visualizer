from __future__ import annotations
import logging
import threading
import time
from collections import defaultdict, deque
from typing import Callable, Deque, Dict, List, Optional, Tuple

from scapy.all import sniff, IP, TCP, UDP, ICMP  # type: ignore

logger = logging.getLogger(__name__)


class MetricsAggregator:
    def __init__(self, bandwidth_window_seconds: int = 60, max_packets: int = 1000) -> None:
        self.lock = threading.RLock()
        self.protocol_counts: Dict[str, int] = defaultdict(int)
        self.top_talkers_bytes: Dict[str, int] = defaultdict(int)
        self.top_talkers_packets: Dict[str, int] = defaultdict(int)
        self.bandwidth_window_seconds = bandwidth_window_seconds
        self.bandwidth_series: Deque[Tuple[int, int]] = deque()  # (timestamp_ms, bytes_in_second)
        self._current_second: Optional[int] = None
        self._current_second_bytes: int = 0
        # Store recent packets for inspection
        self.max_packets = max_packets
        self.packet_store: Deque[Dict] = deque(maxlen=max_packets)
        self._packet_id_counter = 0
        logger.info(f"MetricsAggregator initialized with max_packets={max_packets}")

    def _rollover_if_needed(self, now_ms: int) -> None:
        now_sec = now_ms // 1000
        if self._current_second is None:
            self._current_second = now_sec
            return
        if now_sec != self._current_second:
            # push completed second
            ts_ms = self._current_second * 1000
            self.bandwidth_series.append((ts_ms, self._current_second_bytes))
            self._current_second = now_sec
            self._current_second_bytes = 0
            # trim window
            cutoff = (now_sec - self.bandwidth_window_seconds) * 1000
            while self.bandwidth_series and self.bandwidth_series[0][0] < cutoff:
                self.bandwidth_series.popleft()

    def observe_packet(self, src_ip: str, dst_ip: str, proto: str, size_bytes: int, now_ms: Optional[int] = None, packet_detail: Optional[Dict] = None) -> None:
        if now_ms is None:
            now_ms = int(time.time() * 1000)
        with self.lock:
            self._rollover_if_needed(now_ms)
            self._current_second_bytes += size_bytes
            self.protocol_counts[proto] += 1
            self.top_talkers_bytes[src_ip] += size_bytes
            self.top_talkers_packets[src_ip] += 1
            # Store packet detail if provided
            if packet_detail:
                packet_detail['id'] = self._packet_id_counter
                self._packet_id_counter += 1
                self.packet_store.append(packet_detail)
                if self._packet_id_counter <= 10:
                    logger.info(f"Stored packet #{self._packet_id_counter} in packet_store (store size: {len(self.packet_store)})")

    def snapshot(self) -> Dict:
        with self.lock:
            # Include in-progress second as latest point
            now_ms = int(time.time() * 1000)
            self._rollover_if_needed(now_ms)
            series = list(self.bandwidth_series)
            if self._current_second is not None:
                series = series + [(self._current_second * 1000, self._current_second_bytes)]

            top_items = sorted(self.top_talkers_bytes.items(), key=lambda kv: kv[1], reverse=True)
            top = []
            # Filter out "unknown" IPs and take top 50 valid IPs
            for ip, b in top_items:
                if ip != "unknown" and len(top) < 50:
                    top.append({
                        "ip": ip,
                        "bytes": b,
                        "packets": self.top_talkers_packets.get(ip, 0)
                    })
                elif len(top) >= 50:
                    break

            return {
                "protocol_counts": {
                    "tcp": self.protocol_counts.get("TCP", 0),
                    "udp": self.protocol_counts.get("UDP", 0),
                    "icmp": self.protocol_counts.get("ICMP", 0),
                    "other": self.protocol_counts.get("Other", 0),
                },
                "bandwidth_series": [
                    {"timestamp_ms": ts, "bytes": b} for ts, b in series
                ],
                "top_talkers": top,
            }
    
    def get_recent_packets(self, limit: int = 100) -> List[Dict]:
        """Get recent packets, most recent first"""
        with self.lock:
            packets = list(self.packet_store)
            # Return most recent first, limit results
            return packets[-limit:][::-1]
    
    def get_packet_by_id(self, packet_id: int) -> Optional[Dict]:
        """Get a specific packet by ID"""
        with self.lock:
            for pkt in self.packet_store:
                if pkt.get('id') == packet_id:
                    return pkt
            return None


class PacketSniffer:
    def __init__(self, interface: Optional[str], aggregator: MetricsAggregator) -> None:
        self.interface = interface
        self.aggregator = aggregator
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

    def _proto_of(self, pkt) -> str:
        if TCP in pkt:
            return "TCP"
        if UDP in pkt:
            return "UDP"
        if ICMP in pkt:
            return "ICMP"
        return "Other"

    def _handle_packet(self, pkt) -> None:
        try:
            size_bytes = len(pkt.original) if hasattr(pkt, 'original') else len(bytes(pkt))
        except Exception:
            size_bytes = len(bytes(pkt))
        
        now_ms = int(time.time() * 1000)
        
        # Log first few packets for debugging
        if not hasattr(self, '_packet_count'):
            self._packet_count = 0
        self._packet_count += 1
        if self._packet_count <= 5:
            logger.info(f"Captured packet #{self._packet_count}: {size_bytes} bytes")
        src = None
        dst = None
        src_port = None
        dst_port = None
        proto = self._proto_of(pkt)
        flags = None
        data_length = 0
        info = ""
        
        if IP in pkt:
            src = pkt[IP].src
            dst = pkt[IP].dst
            # Calculate payload/data length (total size - header sizes)
            if TCP in pkt:
                src_port = pkt[TCP].sport
                dst_port = pkt[TCP].dport
                data_length = size_bytes - (pkt[IP].ihl * 4) - (pkt[TCP].dataofs * 4)
                flag_list = []
                if pkt[TCP].flags & 0x01: flag_list.append("FIN")
                if pkt[TCP].flags & 0x02: flag_list.append("SYN")
                if pkt[TCP].flags & 0x04: flag_list.append("RST")
                if pkt[TCP].flags & 0x08: flag_list.append("PSH")
                if pkt[TCP].flags & 0x10: flag_list.append("ACK")
                if pkt[TCP].flags & 0x20: flag_list.append("URG")
                flags = ",".join(flag_list) if flag_list else None
                info = f"{proto} {src}:{src_port} → {dst}:{dst_port}"
            elif UDP in pkt:
                src_port = pkt[UDP].sport
                dst_port = pkt[UDP].dport
                data_length = pkt[UDP].len - 8  # UDP header is 8 bytes
                info = f"{proto} {src}:{src_port} → {dst}:{dst_port}, Len={data_length}"
            elif ICMP in pkt:
                data_length = size_bytes - (pkt[IP].ihl * 4) - 8  # ICMP header is typically 8 bytes
                icmp_type = pkt[ICMP].type
                icmp_code = pkt[ICMP].code
                info = f"{proto} {src} → {dst}, Type={icmp_type}, Code={icmp_code}"
            else:
                data_length = size_bytes - (pkt[IP].ihl * 4)
                info = f"{proto} {src} → {dst}"
        else:
            # Non-IP packet
            src = "unknown"
            dst = "unknown"
            data_length = size_bytes
            info = f"{proto} packet ({size_bytes} bytes)"
        
        # Create packet detail
        packet_detail = {
            "timestamp_ms": now_ms,
            "src_ip": src,
            "dst_ip": dst,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": proto,
            "size_bytes": size_bytes,
            "data_length": data_length,
            "flags": flags,
            "info": info,
        }
        
        self.aggregator.observe_packet(src, dst, proto, size_bytes, now_ms, packet_detail)

    def _sniff_loop(self) -> None:
        # Run scapy sniff with a stop filter
        def stop_filter(_):
            return self._stop_event.is_set()

        interface_str = self.interface or "default"
        logger.info(f"Starting packet capture on interface: {interface_str}")
        
        try:
            sniff(iface=self.interface, prn=self._handle_packet, store=False, stop_filter=stop_filter)
        except PermissionError as e:
            logger.error(f"Permission denied for packet capture on {interface_str}. Try running with sudo.")
            # Insufficient privileges; keep thread idle until stop
            while not self._stop_event.is_set():
                time.sleep(0.5)
        except Exception as e:
            logger.error(f"Error starting packet capture on {interface_str}: {e}")
            # Any other error; keep thread idle until stop
            while not self._stop_event.is_set():
                time.sleep(0.5)

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._sniff_loop, name="packet-sniffer", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2)
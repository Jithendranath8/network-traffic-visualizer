from __future__ import annotations
import logging
import threading
import time
from collections import defaultdict, deque
from typing import Callable, Deque, Dict, List, Optional, Tuple

from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS  # type: ignore

from backend.flow_tracker import FlowTracker
from backend.security_detector import SecurityDetector

logger = logging.getLogger(__name__)


class MetricsAggregator:
    def __init__(
        self,
        bandwidth_window_seconds: int = 60,
        max_packets: int = 1000,
        flow_tracker: Optional[FlowTracker] = None,
        security_detector: Optional[SecurityDetector] = None
    ) -> None:
        self.lock = threading.RLock()
        self.protocol_counts: Dict[str, int] = defaultdict(int)
        self.top_talkers_bytes: Dict[str, int] = defaultdict(int)
        self.top_talkers_packets: Dict[str, int] = defaultdict(int)
        self.bandwidth_window_seconds = bandwidth_window_seconds
        self.bandwidth_series: Deque[Tuple[int, int]] = deque()  # (timestamp_ms, bytes_in_second)
        self._current_second: Optional[int] = None
        self._current_second_bytes: int = 0
        self._packets_in_current_second: int = 0  # Track packets per second
        self._last_spike_check_second: Optional[int] = None  # Track last spike check
        # Store recent packets for inspection
        self.max_packets = max_packets
        self.packet_store: Deque[Dict] = deque(maxlen=max_packets)
        self._packet_id_counter = 0
        
        # Integration with flow tracker and security detector
        self.flow_tracker = flow_tracker
        self.security_detector = security_detector
        
        logger.info(f"MetricsAggregator initialized with max_packets={max_packets}")

    def _rollover_if_needed(self, now_ms: int) -> None:
        now_sec = now_ms // 1000
        if self._current_second is None:
            self._current_second = now_sec
            self._packets_in_current_second = 0
            return
        if now_sec != self._current_second:
            # push completed second
            ts_ms = self._current_second * 1000
            self.bandwidth_series.append((ts_ms, self._current_second_bytes))
            self._current_second = now_sec
            self._current_second_bytes = 0
            self._packets_in_current_second = 0
            # trim window
            cutoff = (now_sec - self.bandwidth_window_seconds) * 1000
            while self.bandwidth_series and self.bandwidth_series[0][0] < cutoff:
                self.bandwidth_series.popleft()

    def observe_packet(self, src_ip: str, dst_ip: str, proto: str, size_bytes: int, now_ms: Optional[int] = None, packet_detail: Optional[Dict] = None) -> None:
        # Ensure size_bytes is always an integer (defensive check)
        if isinstance(size_bytes, (tuple, list)):
            size_bytes = int(size_bytes[0]) if size_bytes else 0
        elif isinstance(size_bytes, float):
            size_bytes = int(size_bytes)
        else:
            size_bytes = int(size_bytes)
        
        if now_ms is None:
            now_ms = int(time.time() * 1000)
        now_sec = now_ms // 1000
        with self.lock:
            self._rollover_if_needed(now_ms)
            self._current_second_bytes += size_bytes
            self._packets_in_current_second += 1
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
        
        # Update flow tracker
        if self.flow_tracker and packet_detail:
            self.flow_tracker.update_flow(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=packet_detail.get('src_port'),
                dst_port=packet_detail.get('dst_port'),
                protocol=proto,
                bytes_count=size_bytes,
                tcp_flags=packet_detail.get('flags')
            )
        
        # Security detection
        if self.security_detector and packet_detail:
            # Port scan detection
            if packet_detail.get('dst_port'):
                self.security_detector.detect_port_scan(
                    src_ip, dst_ip, packet_detail['dst_port']
                )
            
            # Brute force detection (check for RST or connection refused)
            is_failed = packet_detail.get('flags') and 'RST' in packet_detail['flags']
            if is_failed and packet_detail.get('dst_port'):
                self.security_detector.detect_brute_force(
                    src_ip, dst_ip, packet_detail['dst_port'], is_failed=True
                )
            
            # SYN flood detection
            if packet_detail.get('flags'):
                self.security_detector.detect_syn_flood(
                    src_ip, packet_detail['flags']
                )
            
            # DNS tunneling detection
            if packet_detail.get('domain'):
                self.security_detector.detect_dns_tunneling(
                    src_ip, packet_detail['domain']
                )
        
        # Traffic spike detection (check once per second)
        if self.security_detector and self._current_second_bytes > 0:
            if self._last_spike_check_second != now_sec:
                self._last_spike_check_second = now_sec
                bytes_per_sec = self._current_second_bytes
                self.security_detector.detect_traffic_spike(bytes_per_sec)

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
                "packets_per_sec": self._packets_in_current_second,
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

    def _safe_int(self, value, default=0):
        """Safely convert a value to int, handling tuples, lists, floats, etc."""
        try:
            if isinstance(value, (tuple, list)):
                value = value[0] if value else default
            elif isinstance(value, float):
                value = int(value)
            return int(value)
        except (TypeError, ValueError, IndexError):
            return default
    
    def _proto_of(self, pkt) -> str:
        if TCP in pkt:
            return "TCP"
        if UDP in pkt:
            return "UDP"
        if ICMP in pkt:
            return "ICMP"
        return "Other"

    def _handle_packet(self, pkt) -> None:
        """Handle a captured packet - must be thread-safe and error-tolerant"""
        try:
            # Safely get packet size - ensure it's an integer
            try:
                raw_size = len(pkt.original) if hasattr(pkt, 'original') else len(bytes(pkt))
            except Exception:
                raw_size = len(bytes(pkt))
            
            # Ensure size_bytes is an integer, not float or tuple
            size_bytes = self._safe_int(raw_size, default=0)
            
            now_ms = int(time.time() * 1000)
            
            # Log first few packets for debugging
            if not hasattr(self, '_packet_count'):
                self._packet_count = 0
            self._packet_count += 1
            if self._packet_count <= 5:
                logger.info(f"Captured packet #{self._packet_count}: {size_bytes} bytes")
            elif self._packet_count % 1000 == 0:
                logger.info(f"Captured {self._packet_count} packets so far...")
            
            src = None
            dst = None
            src_port = None
            dst_port = None
            proto = self._proto_of(pkt)
            flags = None
            data_length = 0
            info = ""
            domain = None
            
            if IP in pkt:
                src = pkt[IP].src
                dst = pkt[IP].dst
                # Safely extract IP header length (ihl can sometimes be a tuple)
                try:
                    ip_ihl = pkt[IP].ihl
                    ip_ihl = self._safe_int(ip_ihl, default=5)
                    ip_header_len = ip_ihl * 4
                except (AttributeError, TypeError, ValueError, IndexError):
                    ip_header_len = 20  # Default IP header length
                
                # Calculate payload/data length (total size - header sizes)
                if TCP in pkt:
                    src_port = pkt[TCP].sport
                    dst_port = pkt[TCP].dport
                    # Safely extract TCP data offset
                    try:
                        tcp_dataofs = pkt[TCP].dataofs
                        tcp_dataofs = self._safe_int(tcp_dataofs, default=5)
                        tcp_header_len = tcp_dataofs * 4
                    except (AttributeError, TypeError, ValueError, IndexError):
                        tcp_header_len = 20  # Default TCP header length
                    
                    # Ensure all values are integers before subtraction
                    size_bytes = self._safe_int(size_bytes)
                    ip_header_len = self._safe_int(ip_header_len)
                    tcp_header_len = self._safe_int(tcp_header_len)
                    data_length = max(0, size_bytes - ip_header_len - tcp_header_len)
                    flag_list = []
                    try:
                        tcp_flags = pkt[TCP].flags
                        tcp_flags = self._safe_int(tcp_flags, default=0)
                        if tcp_flags & 0x01: flag_list.append("FIN")
                        if tcp_flags & 0x02: flag_list.append("SYN")
                        if tcp_flags & 0x04: flag_list.append("RST")
                        if tcp_flags & 0x08: flag_list.append("PSH")
                        if tcp_flags & 0x10: flag_list.append("ACK")
                        if tcp_flags & 0x20: flag_list.append("URG")
                    except (AttributeError, TypeError, ValueError, IndexError):
                        pass
                    flags = ",".join(flag_list) if flag_list else None
                    info = f"{proto} {src}:{src_port} → {dst}:{dst_port}"
                elif UDP in pkt:
                    src_port = pkt[UDP].sport
                    dst_port = pkt[UDP].dport
                    # Safely extract UDP length
                    try:
                        udp_len = pkt[UDP].len
                        udp_len = self._safe_int(udp_len, default=8)
                        data_length = max(0, udp_len - 8)  # UDP header is 8 bytes
                    except (AttributeError, TypeError, ValueError, IndexError):
                        # Ensure all values are integers before subtraction
                        size_bytes = self._safe_int(size_bytes)
                        ip_header_len = self._safe_int(ip_header_len)
                        data_length = max(0, size_bytes - ip_header_len - 8)
                    info = f"{proto} {src}:{src_port} → {dst}:{dst_port}, Len={data_length}"
                    
                    # Extract DNS domain if present
                    if DNS in pkt:
                        try:
                            if pkt[DNS].qr == 0:  # Query
                                domain = pkt[DNS].qd.qname.decode('utf-8', errors='ignore').rstrip('.')
                                info += f", DNS: {domain}"
                        except Exception:
                            pass
                elif ICMP in pkt:
                    # Ensure all values are integers before subtraction
                    size_bytes = self._safe_int(size_bytes)
                    ip_header_len = self._safe_int(ip_header_len)
                    data_length = max(0, size_bytes - ip_header_len - 8)  # ICMP header is typically 8 bytes
                    try:
                        icmp_type = self._safe_int(pkt[ICMP].type, default=0)
                        icmp_code = self._safe_int(pkt[ICMP].code, default=0)
                        info = f"{proto} {src} → {dst}, Type={icmp_type}, Code={icmp_code}"
                    except (AttributeError, TypeError, ValueError, IndexError):
                        info = f"{proto} {src} → {dst}"
                else:
                    # Other IP protocol (not TCP/UDP/ICMP)
                    # Ensure all values are integers before subtraction
                    size_bytes = self._safe_int(size_bytes)
                    ip_header_len = self._safe_int(ip_header_len)
                    data_length = max(0, size_bytes - ip_header_len)
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
                "domain": domain,
            }
            
            # Process packet
            self.aggregator.observe_packet(src, dst, proto, size_bytes, now_ms, packet_detail)
            
        except Exception as e:
            # Log error with full details but don't crash the capture loop
            import traceback
            error_details = traceback.format_exc()
            logger.warning(f"Error processing packet: {e}")
            logger.debug(f"Full traceback: {error_details}")
            # Don't re-raise - continue capturing

    def _sniff_loop(self) -> None:
        """Main sniff loop with automatic restart on errors"""
        interface_str = self.interface or "default"
        logger.info(f"Starting packet capture on interface: {interface_str}")
        
        consecutive_errors = 0
        max_consecutive_errors = 5
        
        while not self._stop_event.is_set():
            try:
                # Run scapy sniff with a stop filter
                def stop_filter(_):
                    return self._stop_event.is_set()
                
                # Use sniff without timeout - let stop_filter handle stopping
                # The timeout parameter can cause issues on macOS BPF
                sniff(
                    iface=self.interface,
                    prn=self._handle_packet,
                    store=False,
                    stop_filter=stop_filter
                )
                
                # If we get here, sniff completed (stop_filter returned True)
                if self._stop_event.is_set():
                    break
                else:
                    # Sniff ended unexpectedly, restart
                    logger.warning("Sniff completed unexpectedly, restarting in 0.5s...")
                    time.sleep(0.5)
                    consecutive_errors = 0
                    
            except PermissionError as e:
                logger.error(f"Permission denied for packet capture on {interface_str}. Try running with sudo.")
                # Insufficient privileges; keep thread idle until stop
                while not self._stop_event.is_set():
                    time.sleep(0.5)
                break
            except KeyboardInterrupt:
                logger.info("Packet capture interrupted")
                break
            except Exception as e:
                consecutive_errors += 1
                error_msg = str(e)
                logger.error(f"Error in packet capture on {interface_str} (error #{consecutive_errors}): {error_msg}")
                
                # If we have too many consecutive errors, wait longer before retry
                if consecutive_errors >= max_consecutive_errors:
                    logger.error(f"Too many consecutive errors ({consecutive_errors}), waiting 5 seconds before retry...")
                    time.sleep(5)
                    consecutive_errors = 0  # Reset counter after long wait
                else:
                    time.sleep(1.0)  # Wait 1 second before retry to let socket close
                
                # Continue loop to retry sniff
                if not self._stop_event.is_set():
                    logger.info("Restarting packet capture...")
                    continue
                else:
                    break
        
        logger.info("Packet capture loop ended")

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
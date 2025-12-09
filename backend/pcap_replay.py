"""
PCAP File Replay - Playback PCAP files as if they were live traffic
"""
from __future__ import annotations
import time
import threading
from pathlib import Path
from typing import Optional, Callable
from scapy.all import rdpcap, IP, TCP, UDP, ICMP, DNS  # type: ignore


class PCAPReplay:
    """Replay PCAP files at variable speed"""
    
    def __init__(
        self,
        pcap_file: str,
        speed_multiplier: float = 1.0,
        packet_callback: Optional[Callable] = None
    ):
        """
        Args:
            pcap_file: Path to PCAP file
            speed_multiplier: Speed multiplier (1.0 = real-time, 2.0 = 2x speed, 0.5 = half speed)
            packet_callback: Callback function to call for each packet
        """
        self.pcap_file = Path(pcap_file)
        if not self.pcap_file.exists():
            raise FileNotFoundError(f"PCAP file not found: {pcap_file}")
        
        self.speed_multiplier = speed_multiplier
        self.packet_callback = packet_callback
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._is_playing = False
        
        # Load packets
        self.packets = rdpcap(str(self.pcap_file))
        self.start_time: Optional[float] = None
        self.first_packet_time: Optional[float] = None
    
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
    
    def _extract_packet_info(self, pkt) -> Optional[dict]:
        """Extract packet information similar to PacketSniffer"""
        try:
            raw_size = len(pkt.original) if hasattr(pkt, 'original') else len(bytes(pkt))
        except Exception:
            raw_size = len(bytes(pkt))
        
        # Ensure size_bytes is an integer
        size_bytes = self._safe_int(raw_size, default=0)
        
        src = None
        dst = None
        src_port = None
        dst_port = None
        protocol = "Other"
        flags = None
        data_length = 0
        info = ""
        domain = None
        
        if IP in pkt:
            src = pkt[IP].src
            dst = pkt[IP].dst
            
            # Safely extract IP header length
            try:
                ip_ihl = self._safe_int(pkt[IP].ihl, default=5)
                ip_header_len = ip_ihl * 4
            except (AttributeError, TypeError, ValueError, IndexError):
                ip_header_len = 20
            
            if TCP in pkt:
                protocol = "TCP"
                src_port = pkt[TCP].sport
                dst_port = pkt[TCP].dport
                # Safely extract TCP data offset
                try:
                    tcp_dataofs = self._safe_int(pkt[TCP].dataofs, default=5)
                    tcp_header_len = tcp_dataofs * 4
                except (AttributeError, TypeError, ValueError, IndexError):
                    tcp_header_len = 20
                
                data_length = max(0, size_bytes - ip_header_len - tcp_header_len)
                flag_list = []
                try:
                    tcp_flags = self._safe_int(pkt[TCP].flags, default=0)
                    if tcp_flags & 0x01: flag_list.append("FIN")
                    if tcp_flags & 0x02: flag_list.append("SYN")
                    if tcp_flags & 0x04: flag_list.append("RST")
                    if tcp_flags & 0x08: flag_list.append("PSH")
                    if tcp_flags & 0x10: flag_list.append("ACK")
                    if tcp_flags & 0x20: flag_list.append("URG")
                except (AttributeError, TypeError, ValueError, IndexError):
                    pass
                flags = ",".join(flag_list) if flag_list else None
                info = f"{protocol} {src}:{src_port} → {dst}:{dst_port}"
            elif UDP in pkt:
                protocol = "UDP"
                src_port = pkt[UDP].sport
                dst_port = pkt[UDP].dport
                # Safely extract UDP length
                try:
                    udp_len = self._safe_int(pkt[UDP].len, default=8)
                    data_length = max(0, udp_len - 8)
                except (AttributeError, TypeError, ValueError, IndexError):
                    data_length = max(0, size_bytes - ip_header_len - 8)
                info = f"{protocol} {src}:{src_port} → {dst}:{dst_port}, Len={data_length}"
                
                # Extract DNS domain if present
                if DNS in pkt:
                    try:
                        if pkt[DNS].qr == 0:  # Query
                            domain = pkt[DNS].qd.qname.decode('utf-8', errors='ignore').rstrip('.')
                    except Exception:
                        pass
            elif ICMP in pkt:
                protocol = "ICMP"
                data_length = max(0, size_bytes - ip_header_len - 8)
                try:
                    icmp_type = self._safe_int(pkt[ICMP].type, default=0)
                    icmp_code = self._safe_int(pkt[ICMP].code, default=0)
                    info = f"{protocol} {src} → {dst}, Type={icmp_type}, Code={icmp_code}"
                except (AttributeError, TypeError, ValueError, IndexError):
                    info = f"{protocol} {src} → {dst}"
            else:
                data_length = max(0, size_bytes - ip_header_len)
                info = f"{protocol} {src} → {dst}"
        else:
            src = "unknown"
            dst = "unknown"
            data_length = size_bytes
            info = f"{protocol} packet ({size_bytes} bytes)"
        
        return {
            "src_ip": src,
            "dst_ip": dst,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol,
            "size_bytes": size_bytes,
            "data_length": data_length,
            "flags": flags,
            "info": info,
            "domain": domain,
        }
    
    def _replay_loop(self):
        """Main replay loop"""
        if len(self.packets) == 0:
            return
        
        # Get first packet timestamp
        self.first_packet_time = float(self.packets[0].time)
        self.start_time = time.time()
        
        for i, pkt in enumerate(self.packets):
            if self._stop_event.is_set():
                break
            
            # Calculate delay based on packet timestamps
            if i == 0:
                delay = 0
            else:
                # Time difference in original capture
                original_delay = float(pkt.time) - self.first_packet_time
                # Adjust for speed multiplier
                delay = original_delay / self.speed_multiplier
                # Subtract time already elapsed
                elapsed = time.time() - self.start_time
                delay = delay - elapsed
                
                if delay > 0:
                    time.sleep(delay)
            
            # Extract packet info
            packet_info = self._extract_packet_info(pkt)
            if packet_info and self.packet_callback:
                # Use current time for timestamp
                packet_info['timestamp_ms'] = int(time.time() * 1000)
                self.packet_callback(pkt, packet_info)
        
        self._is_playing = False
    
    def start(self):
        """Start replay"""
        if self._is_playing:
            return
        
        self._stop_event.clear()
        self._is_playing = True
        self._thread = threading.Thread(target=self._replay_loop, name="pcap-replay", daemon=True)
        self._thread.start()
    
    def stop(self):
        """Stop replay"""
        self._stop_event.set()
        self._is_playing = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2)
    
    def is_playing(self) -> bool:
        """Check if replay is active"""
        return self._is_playing
    
    def set_speed(self, multiplier: float):
        """Change replay speed"""
        self.speed_multiplier = max(0.1, min(10.0, multiplier))  # Clamp between 0.1x and 10x
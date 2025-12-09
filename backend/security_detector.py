"""
Security Detection Engine - Real-time anomaly and threat detection
"""
from __future__ import annotations
import time
import threading
import statistics
from collections import defaultdict, deque
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum


class AlertSeverity(Enum):
    """Alert severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class SecurityAlert:
    """Represents a security alert"""
    timestamp: float
    alert_type: str
    severity: AlertSeverity
    source_ip: str
    description: str
    evidence: dict
    acknowledged: bool = False
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization"""
        return {
            "timestamp": self.timestamp,
            "alert_type": self.alert_type,
            "severity": self.severity.value,
            "source_ip": self.source_ip,
            "description": self.description,
            "evidence": self.evidence,
            "acknowledged": self.acknowledged,
        }


class SecurityDetector:
    """Real-time security threat detection engine"""
    
    def __init__(
        self,
        port_scan_threshold: int = 10,  # ports in time window
        port_scan_window: int = 60,  # seconds
        brute_force_threshold: int = 5,  # failed connections
        brute_force_window: int = 30,  # seconds
        syn_flood_threshold: int = 100,  # SYN packets
        syn_flood_window: int = 10,  # seconds
        dns_tunnel_domain_length: int = 50,  # characters
        dns_tunnel_rate: int = 20,  # requests per second
        traffic_spike_zscore: float = 3.0,  # standard deviations
        database=None,  # Database for auto-persistence
    ):
        self.lock = threading.RLock()
        
        # Port scan detection
        self.port_scan_threshold = port_scan_threshold
        self.port_scan_window = port_scan_window
        self.port_scan_tracker: Dict[str, deque] = defaultdict(lambda: deque())
        
        # Brute force detection
        self.brute_force_threshold = brute_force_threshold
        self.brute_force_window = brute_force_window
        self.brute_force_tracker: Dict[str, deque] = defaultdict(lambda: deque())
        
        # SYN flood detection
        self.syn_flood_threshold = syn_flood_threshold
        self.syn_flood_window = syn_flood_window
        self.syn_flood_tracker: Dict[str, deque] = defaultdict(lambda: deque())
        
        # DNS tunneling detection
        self.dns_tunnel_domain_length = dns_tunnel_domain_length
        self.dns_tunnel_rate = dns_tunnel_rate
        self.dns_requests: Dict[str, deque] = defaultdict(lambda: deque())
        self.dns_domains: Dict[str, set] = defaultdict(set)
        
        # Traffic spike detection
        self.traffic_spike_zscore = traffic_spike_zscore
        self.traffic_history: deque = deque(maxlen=100)  # Last 100 seconds of traffic
        
        # Alert storage
        self.alerts: deque = deque(maxlen=1000)  # Keep last 1000 alerts
        self.database = database  # Database for auto-persistence
        
    def _clean_old_entries(self, tracker: Dict[str, deque], window: int):
        """Remove entries older than window from tracker"""
        now = time.time()
        for ip, entries in tracker.items():
            while entries and now - entries[0] > window:
                entries.popleft()
    
    def _save_alert(self, alert: SecurityAlert):
        """Helper to save alert to database if available"""
        if self.database:
            try:
                self.database.save_alert(alert.to_dict())
            except Exception as e:
                import logging
                logger = logging.getLogger(__name__)
                logger.error(f"Failed to save alert to database: {e}")
    
    def detect_port_scan(self, src_ip: str, dst_ip: str, dst_port: int) -> Optional[SecurityAlert]:
        """
        Detect port scanning (rapid sequential port access from same source)
        
        Args:
            src_ip: Source IP address
            dst_ip: Destination IP address
            dst_port: Destination port
        
        Returns:
            SecurityAlert if detected, None otherwise
        """
        now = time.time()
        key = f"{src_ip}:{dst_ip}"
        
        with self.lock:
            self._clean_old_entries(self.port_scan_tracker, self.port_scan_window)
            
            # Track unique ports accessed
            if key not in self.port_scan_tracker:
                self.port_scan_tracker[key] = deque()
            
            # Store (timestamp, port)
            self.port_scan_tracker[key].append((now, dst_port))
            
            # Count unique ports in window
            ports_in_window = set()
            for ts, port in self.port_scan_tracker[key]:
                if now - ts <= self.port_scan_window:
                    ports_in_window.add(port)
            
            if len(ports_in_window) >= self.port_scan_threshold:
                alert = SecurityAlert(
                    timestamp=now,
                    alert_type="port_scan",
                    severity=AlertSeverity.HIGH,
                    source_ip=src_ip,
                    description=f"Port scan detected: {src_ip} scanned {len(ports_in_window)} ports on {dst_ip}",
                    evidence={
                        "target_ip": dst_ip,
                        "ports_scanned": len(ports_in_window),
                        "window_seconds": self.port_scan_window,
                        "ports": sorted(list(ports_in_window))[:20],  # First 20 ports
                    }
                )
                self.alerts.append(alert)
                self._save_alert(alert)
                return alert
        
        return None
    
    def detect_brute_force(self, src_ip: str, dst_ip: str, dst_port: int, is_failed: bool) -> Optional[SecurityAlert]:
        """
        Detect brute force attacks (rapid failed connection attempts)
        
        Args:
            src_ip: Source IP address
            dst_ip: Destination IP address
            dst_port: Destination port
            is_failed: Whether connection failed (RST, connection refused, etc.)
        
        Returns:
            SecurityAlert if detected, None otherwise
        """
        if not is_failed:
            return None
        
        now = time.time()
        key = f"{src_ip}:{dst_ip}:{dst_port}"
        
        with self.lock:
            self._clean_old_entries(self.brute_force_tracker, self.brute_force_window)
            
            if key not in self.brute_force_tracker:
                self.brute_force_tracker[key] = deque()
            
            self.brute_force_tracker[key].append(now)
            
            # Count failed attempts in window
            failed_count = sum(1 for ts in self.brute_force_tracker[key] if now - ts <= self.brute_force_window)
            
            if failed_count >= self.brute_force_threshold:
                alert = SecurityAlert(
                    timestamp=now,
                    alert_type="brute_force",
                    severity=AlertSeverity.HIGH,
                    source_ip=src_ip,
                    description=f"Brute force attack detected: {src_ip} made {failed_count} failed connection attempts to {dst_ip}:{dst_port}",
                    evidence={
                        "target_ip": dst_ip,
                        "target_port": dst_port,
                        "failed_attempts": failed_count,
                        "window_seconds": self.brute_force_window,
                    }
                )
                self.alerts.append(alert)
                self._save_alert(alert)
                return alert
        
        return None
    
    def detect_syn_flood(self, src_ip: str, flags: Optional[str]) -> Optional[SecurityAlert]:
        """
        Detect SYN flood attacks (excessive SYN packets without ACK)
        
        Args:
            src_ip: Source IP address
            flags: TCP flags string
        
        Returns:
            SecurityAlert if detected, None otherwise
        """
        if not flags or "SYN" not in flags or "ACK" in flags:
            return None
        
        now = time.time()
        
        with self.lock:
            self._clean_old_entries(self.syn_flood_tracker, self.syn_flood_window)
            
            if src_ip not in self.syn_flood_tracker:
                self.syn_flood_tracker[src_ip] = deque()
            
            self.syn_flood_tracker[src_ip].append(now)
            
            # Count SYN packets in window
            syn_count = sum(1 for ts in self.syn_flood_tracker[src_ip] if now - ts <= self.syn_flood_window)
            
            if syn_count >= self.syn_flood_threshold:
                alert = SecurityAlert(
                    timestamp=now,
                    alert_type="syn_flood",
                    severity=AlertSeverity.CRITICAL,
                    source_ip=src_ip,
                    description=f"SYN flood detected: {src_ip} sent {syn_count} SYN packets in {self.syn_flood_window}s",
                    evidence={
                        "syn_packets": syn_count,
                        "window_seconds": self.syn_flood_window,
                    }
                )
                self.alerts.append(alert)
                self._save_alert(alert)
                return alert
        
        return None
    
    def detect_dns_tunneling(self, src_ip: str, domain: Optional[str], query_type: Optional[str] = None) -> Optional[SecurityAlert]:
        """
        Detect DNS tunneling suspicion (long domain names, abnormal request rate)
        
        Args:
            src_ip: Source IP address
            domain: DNS query domain name
            query_type: DNS query type
        
        Returns:
            SecurityAlert if detected, None otherwise
        """
        if not domain:
            return None
        
        now = time.time()
        
        with self.lock:
            # Check domain length
            domain_too_long = len(domain) > self.dns_tunnel_domain_length
            
            # Track request rate
            if src_ip not in self.dns_requests:
                self.dns_requests[src_ip] = deque()
                self.dns_domains[src_ip] = set()
            
            self.dns_requests[src_ip].append(now)
            self.dns_domains[src_ip].add(domain)
            
            # Clean old entries
            while self.dns_requests[src_ip] and now - self.dns_requests[src_ip][0] > 60:
                self.dns_requests[src_ip].popleft()
            
            # Count requests in last second
            recent_requests = sum(1 for ts in self.dns_requests[src_ip] if now - ts <= 1.0)
            rate_too_high = recent_requests >= self.dns_tunnel_rate
            
            if domain_too_long or rate_too_high:
                severity = AlertSeverity.CRITICAL if (domain_too_long and rate_too_high) else AlertSeverity.MEDIUM
                
                alert = SecurityAlert(
                    timestamp=now,
                    alert_type="dns_tunneling",
                    severity=severity,
                    source_ip=src_ip,
                    description=f"DNS tunneling suspicion: {src_ip} - {'Long domain' if domain_too_long else ''} {'High request rate' if rate_too_high else ''}",
                    evidence={
                        "domain": domain[:100],  # Truncate for safety
                        "domain_length": len(domain),
                        "request_rate_per_sec": recent_requests,
                        "unique_domains": len(self.dns_domains[src_ip]),
                        "threshold_length": self.dns_tunnel_domain_length,
                        "threshold_rate": self.dns_tunnel_rate,
                    }
                )
                self.alerts.append(alert)
                self._save_alert(alert)
                return alert
        
        return None
    
    def detect_traffic_spike(self, bytes_per_second: float) -> Optional[SecurityAlert]:
        """
        Detect traffic spikes using z-score statistics
        
        Args:
            bytes_per_second: Current bytes per second
        
        Returns:
            SecurityAlert if detected, None otherwise
        """
        now = time.time()
        
        with self.lock:
            self.traffic_history.append((now, bytes_per_second))
            
            if len(self.traffic_history) < 20:  # Need at least 20 data points
                return None
            
            # Calculate mean and std dev
            values = [b for _, b in self.traffic_history]
            mean = statistics.mean(values)
            stdev = statistics.stdev(values) if len(values) > 1 else 0
            
            if stdev == 0:
                return None
            
            # Calculate z-score
            z_score = (bytes_per_second - mean) / stdev
            
            if z_score >= self.traffic_spike_zscore:
                alert = SecurityAlert(
                    timestamp=now,
                    alert_type="traffic_spike",
                    severity=AlertSeverity.MEDIUM,
                    source_ip="network",
                    description=f"Traffic spike detected: {bytes_per_second:.0f} bytes/sec (z-score: {z_score:.2f})",
                    evidence={
                        "bytes_per_second": bytes_per_second,
                        "mean": mean,
                        "std_dev": stdev,
                        "z_score": z_score,
                        "threshold": self.traffic_spike_zscore,
                    }
                )
                self.alerts.append(alert)
                self._save_alert(alert)
                return alert
        
        return None
    
    def get_recent_alerts(self, limit: int = 100, unacknowledged_only: bool = False) -> List[SecurityAlert]:
        """
        Get recent alerts
        
        Args:
            limit: Maximum number of alerts to return
            unacknowledged_only: Only return unacknowledged alerts
        
        Returns:
            List of alerts, most recent first
        """
        with self.lock:
            alerts = list(self.alerts)
            if unacknowledged_only:
                alerts = [a for a in alerts if not a.acknowledged]
            alerts.sort(key=lambda a: a.timestamp, reverse=True)
            return alerts[:limit]
    
    def acknowledge_alert(self, alert_timestamp: float, source_ip: str) -> bool:
        """
        Acknowledge an alert
        
        Args:
            alert_timestamp: Timestamp of alert to acknowledge
            source_ip: Source IP of alert
        
        Returns:
            True if alert was found and acknowledged
        """
        with self.lock:
            for alert in self.alerts:
                if abs(alert.timestamp - alert_timestamp) < 1.0 and alert.source_ip == source_ip:
                    alert.acknowledged = True
                    return True
        return False
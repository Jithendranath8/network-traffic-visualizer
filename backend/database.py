"""
Database layer for persisting alerts, flows, and traffic snapshots
"""
from __future__ import annotations
import sqlite3
import threading
import time
from contextlib import contextmanager
from typing import Dict, List, Optional
from pathlib import Path


class Database:
    """SQLite database for storing alerts, flows, and snapshots"""
    
    def __init__(self, db_path: str = "network_analyzer.db"):
        self.db_path = db_path
        self.lock = threading.RLock()
        self._init_db()
    
    def _init_db(self):
        """Initialize database schema"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            # Alerts table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL NOT NULL,
                    alert_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    source_ip TEXT NOT NULL,
                    description TEXT NOT NULL,
                    evidence TEXT NOT NULL,
                    acknowledged INTEGER DEFAULT 0,
                    created_at REAL DEFAULT (strftime('%s', 'now'))
                )
            """)
            
            # Flows table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS flows (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    src_ip TEXT NOT NULL,
                    dst_ip TEXT NOT NULL,
                    src_port INTEGER NOT NULL,
                    dst_port INTEGER NOT NULL,
                    protocol TEXT NOT NULL,
                    first_seen REAL NOT NULL,
                    last_seen REAL NOT NULL,
                    duration REAL NOT NULL,
                    total_bytes INTEGER NOT NULL,
                    packet_count INTEGER NOT NULL,
                    bytes_per_sec REAL NOT NULL,
                    tcp_flags TEXT,
                    created_at REAL DEFAULT (strftime('%s', 'now'))
                )
            """)
            
            # Traffic snapshots table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS traffic_snapshots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp_ms INTEGER NOT NULL,
                    packets_per_sec REAL NOT NULL,
                    bytes_per_sec REAL NOT NULL,
                    protocol_counts TEXT NOT NULL,
                    top_talkers TEXT NOT NULL,
                    created_at REAL DEFAULT (strftime('%s', 'now'))
                )
            """)
            
            # Create indexes
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_source_ip ON alerts(source_ip)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_flows_last_seen ON flows(last_seen)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_snapshots_timestamp ON traffic_snapshots(timestamp_ms)")
            
            conn.commit()
    
    @contextmanager
    def _get_connection(self):
        """Get database connection with thread safety"""
        with self.lock:
            conn = sqlite3.connect(self.db_path, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            try:
                yield conn
            finally:
                conn.close()
    
    def save_alert(self, alert: Dict) -> int:
        """Save an alert to database"""
        import json
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO alerts (timestamp, alert_type, severity, source_ip, description, evidence, acknowledged)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                alert['timestamp'],
                alert['alert_type'],
                alert['severity'],
                alert['source_ip'],
                alert['description'],
                json.dumps(alert['evidence']),
                1 if alert.get('acknowledged', False) else 0,
            ))
            conn.commit()
            return cursor.lastrowid
    
    def get_alerts(
        self,
        limit: int = 100,
        unacknowledged_only: bool = False,
        start_time: Optional[float] = None,
        end_time: Optional[float] = None
    ) -> List[Dict]:
        """Get alerts from database"""
        import json
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            query = "SELECT * FROM alerts WHERE 1=1"
            params = []
            
            if unacknowledged_only:
                query += " AND acknowledged = 0"
            
            if start_time:
                query += " AND timestamp >= ?"
                params.append(start_time)
            
            if end_time:
                query += " AND timestamp <= ?"
                params.append(end_time)
            
            query += " ORDER BY timestamp DESC LIMIT ?"
            params.append(limit)
            
            cursor.execute(query, params)
            rows = cursor.fetchall()
            
            alerts = []
            for row in rows:
                alerts.append({
                    'id': row['id'],
                    'timestamp': row['timestamp'],
                    'alert_type': row['alert_type'],
                    'severity': row['severity'],
                    'source_ip': row['source_ip'],
                    'description': row['description'],
                    'evidence': json.loads(row['evidence']),
                    'acknowledged': bool(row['acknowledged']),
                })
            
            return alerts
    
    def acknowledge_alert(self, alert_id: int) -> bool:
        """Acknowledge an alert"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE alerts SET acknowledged = 1 WHERE id = ?", (alert_id,))
            conn.commit()
            return cursor.rowcount > 0
    
    def save_flow(self, flow: Dict) -> int:
        """Save a flow to database"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO flows (src_ip, dst_ip, src_port, dst_port, protocol, first_seen, last_seen,
                                  duration, total_bytes, packet_count, bytes_per_sec, tcp_flags)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                flow['src_ip'],
                flow['dst_ip'],
                flow['src_port'],
                flow['dst_port'],
                flow['protocol'],
                flow['first_seen'],
                flow['last_seen'],
                flow['duration'],
                flow['total_bytes'],
                flow['packet_count'],
                flow['bytes_per_sec'],
                ','.join(flow.get('tcp_flags', [])),
            ))
            conn.commit()
            return cursor.lastrowid
    
    def get_flows(
        self,
        limit: int = 100,
        start_time: Optional[float] = None,
        end_time: Optional[float] = None,
        protocol: Optional[str] = None,
        src_ip: Optional[str] = None
    ) -> List[Dict]:
        """Get flows from database"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            query = "SELECT * FROM flows WHERE 1=1"
            params = []
            
            if start_time:
                query += " AND last_seen >= ?"
                params.append(start_time)
            
            if end_time:
                query += " AND last_seen <= ?"
                params.append(end_time)
            
            if protocol:
                query += " AND protocol = ?"
                params.append(protocol)
            
            if src_ip:
                query += " AND (src_ip = ? OR dst_ip = ?)"
                params.extend([src_ip, src_ip])
            
            query += " ORDER BY last_seen DESC LIMIT ?"
            params.append(limit)
            
            cursor.execute(query, params)
            rows = cursor.fetchall()
            
            flows = []
            for row in rows:
                flows.append({
                    'id': row['id'],
                    'src_ip': row['src_ip'],
                    'dst_ip': row['dst_ip'],
                    'src_port': row['src_port'],
                    'dst_port': row['dst_port'],
                    'protocol': row['protocol'],
                    'first_seen': row['first_seen'],
                    'last_seen': row['last_seen'],
                    'duration': row['duration'],
                    'total_bytes': row['total_bytes'],
                    'packet_count': row['packet_count'],
                    'bytes_per_sec': row['bytes_per_sec'],
                    'tcp_flags': row['tcp_flags'].split(',') if row['tcp_flags'] else [],
                })
            
            return flows
    
    def save_snapshot(self, snapshot: Dict) -> int:
        """Save a traffic snapshot"""
        import json
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO traffic_snapshots (timestamp_ms, packets_per_sec, bytes_per_sec, protocol_counts, top_talkers)
                VALUES (?, ?, ?, ?, ?)
            """, (
                snapshot['timestamp_ms'],
                snapshot.get('packets_per_sec', 0),
                snapshot.get('bytes_per_sec', 0),
                json.dumps(snapshot.get('protocol_counts', {})),
                json.dumps(snapshot.get('top_talkers', [])),
            ))
            conn.commit()
            return cursor.lastrowid
    
    def get_snapshots(
        self,
        start_time_ms: Optional[int] = None,
        end_time_ms: Optional[int] = None,
        limit: int = 100
    ) -> List[Dict]:
        """Get traffic snapshots"""
        import json
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            query = "SELECT * FROM traffic_snapshots WHERE 1=1"
            params = []
            
            if start_time_ms:
                query += " AND timestamp_ms >= ?"
                params.append(start_time_ms)
            
            if end_time_ms:
                query += " AND timestamp_ms <= ?"
                params.append(end_time_ms)
            
            query += " ORDER BY timestamp_ms DESC LIMIT ?"
            params.append(limit)
            
            cursor.execute(query, params)
            rows = cursor.fetchall()
            
            snapshots = []
            for row in rows:
                snapshots.append({
                    'id': row['id'],
                    'timestamp_ms': row['timestamp_ms'],
                    'packets_per_sec': row['packets_per_sec'],
                    'bytes_per_sec': row['bytes_per_sec'],
                    'protocol_counts': json.loads(row['protocol_counts']),
                    'top_talkers': json.loads(row['top_talkers']),
                })
            
            return snapshots
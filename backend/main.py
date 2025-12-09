"""
Main FastAPI application - Network Traffic Analyzer & Security Monitoring Dashboard
"""
from __future__ import annotations
from contextlib import asynccontextmanager
import argparse
import asyncio
import os
import signal
import sys
import time
import threading
from typing import List, Set, Optional
from pathlib import Path

# Add parent directory to path so 'backend' module can be imported when run as script
_parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _parent_dir not in sys.path:
    sys.path.insert(0, _parent_dir)

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
import uvicorn

from backend.models import (
    StatsSnapshot, ProtocolCounts, BandwidthPoint, TopTalker, PacketDetail, PacketList,
    FlowDetail, FlowList, SecurityAlert, AlertList, GeoIPInfo, TopTalkerGeo
)
from backend.packet_sniffer import MetricsAggregator, PacketSniffer
from backend.flow_tracker import FlowTracker
from backend.security_detector import SecurityDetector
from backend.database import Database
from backend.pcap_replay import PCAPReplay
from backend.geoip import GeoIPLookup


# Global state
aggregator: Optional[MetricsAggregator] = None
sniffer: Optional[PacketSniffer] = None
pcap_replay: Optional[PCAPReplay] = None
flow_tracker: Optional[FlowTracker] = None
security_detector: Optional[SecurityDetector] = None
database: Optional[Database] = None
geoip: Optional[GeoIPLookup] = None

# WebSocket clients
metrics_clients: Set[WebSocket] = set()
alerts_clients: Set[WebSocket] = set()
flows_clients: Set[WebSocket] = set()


async def metrics_broadcaster_task() -> None:
    """Broadcast metrics to all connected clients"""
    while True:
        if aggregator:
            snap = aggregator.snapshot()
            payload = {
                "protocol_counts": snap["protocol_counts"],
                "bandwidth_series": snap["bandwidth_series"],
                "top_talkers": snap["top_talkers"],
                "packets_per_sec": snap.get("packets_per_sec", 0),
                "active_sessions": flow_tracker.get_flow_stats()["active_flows"] if flow_tracker else 0,
            }
            
            dead: List[WebSocket] = []
            for client in list(metrics_clients):
                try:
                    await client.send_json(payload)
                except Exception:
                    dead.append(client)
            for d in dead:
                metrics_clients.discard(d)
        
        await asyncio.sleep(1)


async def alerts_broadcaster_task() -> None:
    """Broadcast new alerts to all connected clients"""
    last_alert_count = 0
    
    while True:
        if security_detector:
            alerts = security_detector.get_recent_alerts(limit=10, unacknowledged_only=True)
            
            if len(alerts) > last_alert_count:
                # New alerts detected
                new_alerts = [a.to_dict() for a in alerts[:len(alerts) - last_alert_count]]
                
                dead: List[WebSocket] = []
                for client in list(alerts_clients):
                    try:
                        await client.send_json({"alerts": new_alerts})
                    except Exception:
                        dead.append(client)
                for d in dead:
                    alerts_clients.discard(d)
            
            last_alert_count = len(alerts)
        
        await asyncio.sleep(2)


async def flows_broadcaster_task() -> None:
    """Broadcast active flows to all connected clients"""
    while True:
        if flow_tracker:
            flows = flow_tracker.get_active_flows(limit=100)
            payload = {
                "flows": [f.to_dict() for f in flows],
                "stats": flow_tracker.get_flow_stats(),
            }
            
            dead: List[WebSocket] = []
            for client in list(flows_clients):
                try:
                    await client.send_json(payload)
                except Exception:
                    dead.append(client)
            for d in dead:
                flows_clients.discard(d)
        
        await asyncio.sleep(2)


def flow_expiration_task() -> None:
    """Periodically expire idle flows"""
    while True:
        if flow_tracker:
            expired = flow_tracker.expire_idle_flows()
            if expired and database:
                # Save expired flows to database
                for flow in expired:
                    try:
                        database.save_flow(flow.to_dict())
                    except Exception:
                        pass
        time.sleep(30)  # Check every 30 seconds


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager"""
    global aggregator, sniffer, flow_tracker, security_detector, database, geoip
    
    # Startup
    import logging
    logger = logging.getLogger("uvicorn.info")
    
    # Initialize components
    database = Database(db_path=os.environ.get("DB_PATH", "network_analyzer.db"))
    flow_tracker = FlowTracker(idle_timeout_seconds=300)
    security_detector = SecurityDetector(database=database)  # Pass database for auto-persistence
    geoip = GeoIPLookup(db_path=os.environ.get("GEOIP_DB_PATH"))
    
    aggregator = MetricsAggregator(
        bandwidth_window_seconds=60,
        max_packets=10000,
        flow_tracker=flow_tracker,
        security_detector=security_detector
    )
    
    # Start packet capture if interface is specified
    iface = os.environ.get("NET_IFACE")
    if iface:
        logger.info(f"Packet capture interface set to: {iface}")
        sniffer = PacketSniffer(interface=iface, aggregator=aggregator)
        sniffer.start()
    else:
        logger.warning("No NET_IFACE set - packet capture disabled. Use --iface or export NET_IFACE")
    
    # Start background tasks
    metrics_task = asyncio.create_task(metrics_broadcaster_task())
    alerts_task = asyncio.create_task(alerts_broadcaster_task())
    flows_task = asyncio.create_task(flows_broadcaster_task())
    
    # Start flow expiration thread
    expiration_thread = threading.Thread(target=flow_expiration_task, daemon=True)
    expiration_thread.start()
    
    yield
    
    # Shutdown
    if sniffer:
        sniffer.stop()
    if pcap_replay:
        pcap_replay.stop()
    
    metrics_task.cancel()
    alerts_task.cancel()
    flows_task.cancel()
    
    try:
        await metrics_task
        await alerts_task
        await flows_task
    except asyncio.CancelledError:
        pass


app = FastAPI(
    title="Network Traffic Analyzer & Security Monitoring Dashboard",
    description="Production-grade SIEM platform for network traffic analysis",
    version="1.0.0",
    lifespan=lifespan
)

# CORS - allow local dev
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Static frontend (mounted at /static)
static_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'frontend')
static_files = StaticFiles(directory=static_dir)
app.mount("/static", static_files, name="static")


@app.get("/")
async def index() -> HTMLResponse:
    """Serve main dashboard"""
    index_path = os.path.join(static_dir, 'index.html')
    with open(index_path, 'r', encoding='utf-8') as f:
        return HTMLResponse(f.read())


@app.get("/stats", response_model=StatsSnapshot)
async def get_stats() -> StatsSnapshot:
    """Get current statistics snapshot"""
    if not aggregator:
        raise HTTPException(status_code=503, detail="Aggregator not initialized")
    
    snap = aggregator.snapshot()
    return StatsSnapshot(
        protocol_counts=ProtocolCounts(**snap["protocol_counts"]),
        bandwidth_series=[BandwidthPoint(**p) for p in snap["bandwidth_series"]],
        top_talkers=[TopTalker(**t) for t in snap["top_talkers"]],
    )


@app.get("/flows", response_model=FlowList)
async def get_flows(
    limit: int = 100,
    protocol: Optional[str] = None,
    src_ip: Optional[str] = None,
    start_time: Optional[float] = None,
    end_time: Optional[float] = None
) -> FlowList:
    """Get active flows with optional filtering"""
    if not flow_tracker:
        raise HTTPException(status_code=503, detail="Flow tracker not initialized")
    
    flows = flow_tracker.get_active_flows(limit=limit)
    
    # Apply filters
    if protocol:
        # Normalize protocol match (case-insensitive)
        proto = protocol.strip().upper()
        flows = [f for f in flows if f.protocol.upper() == proto]
    if src_ip:
        # Allow partial match against either endpoint to make UI filtering forgiving
        ip_filter = src_ip.strip()
        flows = [
            f for f in flows
            if ip_filter in f.src_ip or ip_filter in f.dst_ip
        ]
    if start_time:
        flows = [f for f in flows if f.last_seen >= start_time]
    if end_time:
        flows = [f for f in flows if f.last_seen <= end_time]
    
    return FlowList(
        flows=[FlowDetail(**f.to_dict()) for f in flows],
        total=len(flows)
    )


@app.get("/alerts", response_model=AlertList)
async def get_alerts(
    limit: int = 100,
    unacknowledged_only: bool = False,
    start_time: Optional[float] = None,
    end_time: Optional[float] = None
) -> AlertList:
    """Get security alerts"""
    if not security_detector:
        raise HTTPException(status_code=503, detail="Security detector not initialized")
    
    alerts = security_detector.get_recent_alerts(limit=limit, unacknowledged_only=unacknowledged_only)
    
    # Apply time filters
    if start_time:
        alerts = [a for a in alerts if a.timestamp >= start_time]
    if end_time:
        alerts = [a for a in alerts if a.timestamp <= end_time]
    
    return AlertList(
        alerts=[SecurityAlert(**a.to_dict()) for a in alerts],
        total=len(alerts)
    )


@app.post("/alerts/{alert_timestamp}/acknowledge")
async def acknowledge_alert(alert_timestamp: float, source_ip: str) -> JSONResponse:
    """Acknowledge a security alert"""
    if not security_detector:
        raise HTTPException(status_code=503, detail="Security detector not initialized")
    
    success = security_detector.acknowledge_alert(alert_timestamp, source_ip)
    
    if success and database:
        # Also update in database
        alerts = database.get_alerts(limit=1000)
        for alert in alerts:
            if abs(alert['timestamp'] - alert_timestamp) < 1.0 and alert['source_ip'] == source_ip:
                database.acknowledge_alert(alert['id'])
                break
    
    return JSONResponse({"success": success})


@app.get("/geo")
async def get_geo_info(ip: str) -> GeoIPInfo:
    """Get geographic information for an IP address"""
    if not geoip:
        raise HTTPException(status_code=503, detail="GeoIP not initialized")
    
    info = geoip.lookup(ip)
    return GeoIPInfo(**info.to_dict())


@app.get("/top-talkers")
async def get_top_talkers(limit: int = 50, with_geo: bool = False) -> List[TopTalkerGeo]:
    """Get top IP talkers with optional GeoIP information"""
    if not aggregator:
        raise HTTPException(status_code=503, detail="Aggregator not initialized")
    
    snap = aggregator.snapshot()
    talkers = snap["top_talkers"][:limit]
    
    if with_geo and geoip:
        result = []
        for talker in talkers:
            geo_info = geoip.lookup(talker["ip"])
            result.append(TopTalkerGeo(
                ip=talker["ip"],
                bytes=talker["bytes"],
                packets=talker["packets"],
                geo=GeoIPInfo(**geo_info.to_dict()) if geo_info.country else None
            ))
        return result
    
    return [TopTalkerGeo(**t, geo=None) for t in talkers]


@app.get("/packets", response_model=PacketList)
async def get_packets(limit: int = 100) -> PacketList:
    """Get recent packets"""
    if not aggregator:
        raise HTTPException(status_code=503, detail="Aggregator not initialized")
    
    packets = aggregator.get_recent_packets(limit=limit)
    return PacketList(
        packets=[PacketDetail(**p) for p in packets],
        total=len(packets)
    )


@app.get("/packets/{packet_id}", response_model=PacketDetail)
async def get_packet(packet_id: int) -> PacketDetail:
    """Get a specific packet by ID"""
    if not aggregator:
        raise HTTPException(status_code=503, detail="Aggregator not initialized")
    
    packet = aggregator.get_packet_by_id(packet_id)
    if packet is None:
        raise HTTPException(status_code=404, detail="Packet not found")
    return PacketDetail(**packet)


@app.post("/pcap/upload")
async def upload_pcap(file: UploadFile = File(...), speed: float = 1.0) -> JSONResponse:
    """Upload and replay a PCAP file"""
    global pcap_replay
    
    # Save uploaded file
    upload_dir = Path("uploads")
    upload_dir.mkdir(exist_ok=True, parents=True)
    
    file_path = upload_dir / file.filename
    with open(file_path, "wb") as f:
        content = await file.read()
        f.write(content)
    
    # Stop existing replay if any
    if pcap_replay:
        pcap_replay.stop()
    
    # Create new replay
    try:
        def packet_callback(pkt, info):
            """Callback for PCAP replay packets"""
            if aggregator:
                aggregator.observe_packet(
                    info["src_ip"],
                    info["dst_ip"],
                    info["protocol"],
                    info["size_bytes"],
                    info.get("timestamp_ms"),
                    info
                )
        
        pcap_replay = PCAPReplay(
            pcap_file=str(file_path),
            speed_multiplier=speed,
            packet_callback=packet_callback
        )
        pcap_replay.start()
        
        return JSONResponse({
            "success": True,
            "message": f"PCAP file uploaded and replay started at {speed}x speed",
            "filename": file.filename
        })
    except Exception as e:
        return JSONResponse(
            {"success": False, "error": str(e)},
            status_code=400
        )


@app.post("/pcap/replay/stop")
async def stop_pcap_replay() -> JSONResponse:
    """Stop PCAP replay"""
    global pcap_replay
    if pcap_replay:
        pcap_replay.stop()
        pcap_replay = None
        return JSONResponse({"success": True, "message": "PCAP replay stopped"})
    return JSONResponse({"success": False, "message": "No active replay"})


@app.websocket("/ws/metrics")
async def websocket_metrics(ws: WebSocket):
    """WebSocket endpoint for real-time metrics"""
    await ws.accept()
    metrics_clients.add(ws)
    try:
        while True:
            try:
                await ws.receive_text()
            except WebSocketDisconnect:
                break
            await asyncio.sleep(10)
    finally:
        metrics_clients.discard(ws)


@app.websocket("/ws/alerts")
async def websocket_alerts(ws: WebSocket):
    """WebSocket endpoint for real-time alerts"""
    await ws.accept()
    alerts_clients.add(ws)
    try:
        while True:
            try:
                await ws.receive_text()
            except WebSocketDisconnect:
                break
            await asyncio.sleep(10)
    finally:
        alerts_clients.discard(ws)


@app.websocket("/ws/flows")
async def websocket_flows(ws: WebSocket):
    """WebSocket endpoint for real-time flows"""
    await ws.accept()
    flows_clients.add(ws)
    try:
        while True:
            try:
                await ws.receive_text()
            except WebSocketDisconnect:
                break
            await asyncio.sleep(10)
    finally:
        flows_clients.discard(ws)


@app.get("/debug")
async def debug_info():
    """Debug endpoint to check system status"""
    if not aggregator:
        return {"error": "Aggregator not initialized"}
    
    with aggregator.lock:
        packet_count = len(aggregator.packet_store)
        total_bytes = sum(aggregator.top_talkers_bytes.values())
        total_packets = sum(aggregator.top_talkers_packets.values())
        protocol_totals = dict(aggregator.protocol_counts)
    
    # Get PCAP replay info
    pcap_info = {}
    if pcap_replay:
        pcap_info = {
            "is_playing": pcap_replay.is_playing(),
            "filename": str(pcap_replay.pcap_file) if hasattr(pcap_replay, 'pcap_file') else None,
            "speed": pcap_replay.speed_multiplier if hasattr(pcap_replay, 'speed_multiplier') else None,
            "packets_loaded": len(pcap_replay.packets) if hasattr(pcap_replay, 'packets') else 0,
        }
    else:
        pcap_info = {"is_playing": False, "status": "No active replay"}
    
    # Get current stats snapshot
    snap = aggregator.snapshot()
    
    return {
        "packets_in_store": packet_count,
        "total_bytes_captured": total_bytes,
        "total_packets_aggregated": total_packets,
        "protocol_counts": protocol_totals,
        "max_packets": aggregator.max_packets,
        "sniffer_active": sniffer is not None and sniffer._thread is not None and sniffer._thread.is_alive() if sniffer else False,
        "pcap_replay": pcap_info,
        "interface": os.environ.get("NET_IFACE", "not set"),
        "active_flows": flow_tracker.get_flow_stats()["active_flows"] if flow_tracker else 0,
        "total_alerts": len(security_detector.alerts) if security_detector else 0,
        "current_stats": {
            "packets_per_sec": snap.get("packets_per_sec", 0),
            "bandwidth_bytes_per_sec": snap.get("bandwidth_bytes_per_sec", 0),
            "active_sessions": snap.get("active_sessions", 0),
        }
    }


def main() -> None:
    """Main entry point"""
    import logging
    logging.basicConfig(level=logging.INFO)
    
    parser = argparse.ArgumentParser(description="Network Traffic Analyzer & Security Monitoring Dashboard")
    parser.add_argument("--iface", dest="iface", default=os.environ.get("NET_IFACE"), help="Network interface to sniff (e.g., eth0, en0)")
    parser.add_argument("--host", dest="host", default="0.0.0.0")
    parser.add_argument("--port", dest="port", type=int, default=8000)
    parser.add_argument("--db-path", dest="db_path", default="network_analyzer.db", help="Database file path")
    args = parser.parse_args()

    if args.iface:
        os.environ["NET_IFACE"] = args.iface
        print(f"✓ Network interface set to: {args.iface}")
    else:
        print("⚠ WARNING: No network interface specified. Use --iface en0 (or your interface)")
        print("⚠ Packet capture will be disabled. PCAP replay will still work.")

    os.environ["DB_PATH"] = args.db_path
    print(f"✓ Database path: {args.db_path}")
    print(f"✓ Server starting on http://{args.host}:{args.port}")
    print("✓ Open http://localhost:8000 in your browser")
    print("✓ Generate network traffic to see packets (browse websites, ping servers, etc.)")
    print("✓ Or upload a PCAP file via /pcap/upload endpoint")
    
    uvicorn.run("backend.main:app", host=args.host, port=args.port, reload=False, log_level="info")


if __name__ == "__main__":
    main()

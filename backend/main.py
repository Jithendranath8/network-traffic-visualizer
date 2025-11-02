from __future__ import annotations
from contextlib import asynccontextmanager
import argparse
import asyncio
import os
import signal
import sys
from typing import List, Set

# Add parent directory to path so 'backend' module can be imported when run as script
_parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _parent_dir not in sys.path:
    sys.path.insert(0, _parent_dir)

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
import uvicorn

from backend.models import StatsSnapshot, ProtocolCounts, BandwidthPoint, TopTalker, PacketDetail, PacketList
from backend.packet_sniffer import MetricsAggregator, PacketSniffer


# State
aggregator = MetricsAggregator(bandwidth_window_seconds=60)
sniffer: PacketSniffer | None = None
clients: Set[WebSocket] = set()


async def broadcaster_task() -> None:
    while True:
        snap = aggregator.snapshot()
        # Lightweight JSON
        payload = {
            "protocol_counts": snap["protocol_counts"],
            "bandwidth_series": snap["bandwidth_series"],
            "top_talkers": snap["top_talkers"],
        }
        dead: List[WebSocket] = []
        for c in list(clients):
            try:
                await c.send_json(payload)
            except Exception:
                dead.append(c)
        for d in dead:
            clients.discard(d)
        await asyncio.sleep(1)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    iface = os.environ.get("NET_IFACE")
    import logging
    logger = logging.getLogger("uvicorn.info")
    if iface:
        logger.info(f"Packet capture interface set to: {iface}")
    else:
        logger.warning("No NET_IFACE set - packet capture may not work. Use --iface or export NET_IFACE")
    
    global sniffer
    sniffer = PacketSniffer(interface=iface, aggregator=aggregator)
    sniffer.start()
    # Start broadcaster
    broadcaster = asyncio.create_task(broadcaster_task())
    yield
    # Shutdown
    if sniffer is not None:
        sniffer.stop()
    broadcaster.cancel()
    try:
        await broadcaster
    except asyncio.CancelledError:
        pass


app = FastAPI(title="Network Traffic Analyzer Dashboard", lifespan=lifespan)

# CORS - allow local dev
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Static frontend (mounted at /)
static_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'frontend')
app.mount("/static", StaticFiles(directory=static_dir), name="static")


@app.get("/")
async def index() -> HTMLResponse:
    index_path = os.path.join(static_dir, 'index.html')
    with open(index_path, 'r', encoding='utf-8') as f:
        return HTMLResponse(f.read())


@app.get("/stats")
async def get_stats() -> StatsSnapshot:
    snap = aggregator.snapshot()
    return StatsSnapshot(
        protocol_counts=ProtocolCounts(**snap["protocol_counts"]),
        bandwidth_series=[BandwidthPoint(**p) for p in snap["bandwidth_series"]],
        top_talkers=[TopTalker(**t) for t in snap["top_talkers"]],
    )


@app.get("/packets", response_model=PacketList)
async def get_packets(limit: int = 100) -> PacketList:
    """Get recent packets, most recent first"""
    packets = aggregator.get_recent_packets(limit=limit)
    import logging
    logger = logging.getLogger(__name__)
    
    # Convert to PacketDetail, handling validation errors
    packet_details = []
    for p in packets:
        try:
            # Ensure all required fields are present
            if 'id' not in p:
                continue
            if 'timestamp_ms' not in p:
                continue
            packet_details.append(PacketDetail(**p))
        except Exception as e:
            logger.warning(f"Failed to validate packet {p.get('id', 'unknown')}: {e}")
            continue
    
    return PacketList(
        packets=packet_details,
        total=len(packet_details)
    )


@app.get("/packets/{packet_id}", response_model=PacketDetail)
async def get_packet(packet_id: int) -> PacketDetail:
    """Get a specific packet by ID"""
    packet = aggregator.get_packet_by_id(packet_id)
    if packet is None:
        raise HTTPException(status_code=404, detail="Packet not found")
    return PacketDetail(**packet)


@app.get("/debug")
async def debug_info():
    """Debug endpoint to check packet capture status"""
    with aggregator.lock:
        packet_count = len(aggregator.packet_store)
        total_bytes = sum(aggregator.top_talkers_bytes.values())
        total_packets = sum(aggregator.top_talkers_packets.values())
        protocol_totals = dict(aggregator.protocol_counts)
        
    return {
        "packets_in_store": packet_count,
        "total_bytes_captured": total_bytes,
        "total_packets_aggregated": total_packets,
        "protocol_counts": protocol_totals,
        "max_packets": aggregator.max_packets,
        "sniffer_active": sniffer is not None and sniffer._thread is not None and sniffer._thread.is_alive() if sniffer else False,
        "interface": os.environ.get("NET_IFACE", "not set")
    }


@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws.accept()
    clients.add(ws)
    try:
        # Keep the connection open; server pushes updates
        while True:
            # Backpressure/read pings to detect disconnects; tiny sleep avoids busy loop
            try:
                await ws.receive_text()
            except WebSocketDisconnect:
                break
            await asyncio.sleep(10)
    finally:
        clients.discard(ws)


def main() -> None:
    import logging
    logging.basicConfig(level=logging.INFO)
    
    parser = argparse.ArgumentParser(description="Network Traffic Analyzer Dashboard")
    parser.add_argument("--iface", dest="iface", default=os.environ.get("NET_IFACE"), help="Network interface to sniff (e.g., eth0, en0)")
    parser.add_argument("--host", dest="host", default="0.0.0.0")
    parser.add_argument("--port", dest="port", type=int, default=8000)
    args = parser.parse_args()

    if args.iface:
        os.environ["NET_IFACE"] = args.iface
        print(f"✓ Network interface set to: {args.iface}")
    else:
        print("⚠ WARNING: No network interface specified. Use --iface en0 (or your interface)")

    print(f"✓ Server starting on http://{args.host}:{args.port}")
    print("✓ Open http://localhost:8000 in your browser")
    print("✓ Generate network traffic to see packets (browse websites, ping servers, etc.)")
    
    uvicorn.run("backend.main:app", host=args.host, port=args.port, reload=False, log_level="info")


if __name__ == "__main__":
    main()

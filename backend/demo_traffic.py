"""
Demo Traffic Generator
======================

Managed hosting platforms (Render, Railway, Fly, most PaaS) do not grant
containers the raw-socket capability (NET_RAW) that live packet capture needs,
and a web container sees no real network traffic to sniff. On those hosts the
live sniffer starts but captures nothing, so every chart on the dashboard sits
empty and the deployment looks broken.

This generator feeds realistic synthetic traffic straight into the
MetricsAggregator (the same ingestion point the live sniffer and PCAP replay
use) so the hosted dashboard always looks alive. It is *self-disabling*: the
moment real packets arrive — a live capture or an uploaded PCAP replay — it
stands down and lets the real data through, then resumes if the real traffic
stops. Set the env var ``DEMO_MODE=0`` (or ``false``) to turn it off entirely.
"""
from __future__ import annotations

import logging
import random
import threading
import time
from typing import Optional

logger = logging.getLogger("uvicorn.info")

# Internal hosts that initiate connections (clients on the LAN).
_CLIENTS = [f"192.168.1.{n}" for n in (10, 11, 15, 22, 23, 37, 42)] + [
    f"10.0.0.{n}" for n in (5, 8, 12, 19)
]

# Public servers the clients talk to — real, geo-diverse addresses so the
# top-talkers list reads naturally (and the geo map lights up if a GeoIP DB is
# configured). Paired with the service/port they typically serve.
_SERVERS = [
    ("8.8.8.8", 53, "UDP"),           # Google DNS
    ("1.1.1.1", 53, "UDP"),           # Cloudflare DNS
    ("140.82.121.4", 443, "TCP"),     # GitHub
    ("185.199.108.153", 443, "TCP"),  # GitHub Pages
    ("151.101.65.69", 443, "TCP"),    # Fastly
    ("104.244.42.1", 443, "TCP"),     # Twitter
    ("13.107.42.14", 443, "TCP"),     # Microsoft
    ("142.250.72.206", 443, "TCP"),   # Google
    ("93.184.216.34", 80, "TCP"),     # example.com
    ("52.84.150.39", 443, "TCP"),     # CloudFront
]

_DNS_NAMES = [
    "api.github.com", "cdn.jsdelivr.net", "fonts.googleapis.com",
    "www.cloudflare.com", "registry.npmjs.org", "github.githubassets.com",
    "update.microsoft.com", "i.redd.it", "pbs.twimg.com",
]


class DemoTrafficGenerator:
    """Emits lifelike synthetic packets into a MetricsAggregator."""

    def __init__(self, aggregator, packets_per_sec: int = 12):
        self.aggregator = aggregator
        self.packets_per_sec = max(1, packets_per_sec)
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._last_attack = 0.0

    # -- lifecycle ---------------------------------------------------------
    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._run, name="demo-traffic", daemon=True
        )
        self._thread.start()
        logger.info(
            "Demo traffic generator started (~%d pkt/s). It stands down "
            "automatically when real capture or an uploaded PCAP is active.",
            self.packets_per_sec,
        )

    def stop(self) -> None:
        self._stop.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2)

    # -- emit helpers ------------------------------------------------------
    def _emit(self, src, dst, proto, size, *, sport=None, dport=None,
              flags=None, domain=None) -> None:
        detail = {
            "src_ip": src,
            "dst_ip": dst,
            "src_port": sport,
            "dst_port": dport,
            "protocol": proto,
            "size_bytes": size,
            "data_length": max(0, size - 40),
            "flags": flags,
            "info": f"{proto} {src}:{sport} → {dst}:{dport}"
            if sport else f"{proto} {src} → {dst}",
            "domain": domain,
        }
        try:
            self.aggregator.observe_packet(
                src, dst, proto, size,
                int(time.time() * 1000), detail, is_demo=True,
            )
        except Exception:  # never let demo traffic crash the app
            logger.debug("demo emit failed", exc_info=True)

    def _normal_packet(self) -> None:
        """One packet of ordinary client/server traffic."""
        client = random.choice(_CLIENTS)
        server, port, proto = random.choice(_SERVERS)
        sport = random.randint(1024, 65535)

        if proto == "UDP":  # DNS query + response
            self._emit(client, server, "UDP", random.randint(70, 120),
                       sport=sport, dport=port,
                       domain=random.choice(_DNS_NAMES))
            self._emit(server, client, "UDP", random.randint(90, 300),
                       sport=port, dport=sport)
            return

        # TCP: a request out and a (usually larger) response back.
        self._emit(client, server, "TCP", random.randint(120, 600),
                   sport=sport, dport=port, flags="PSH,ACK")
        self._emit(server, client, "TCP", random.randint(200, 1460),
                   sport=port, dport=sport, flags="ACK")

    def _maybe_attack(self, now: float) -> None:
        """Every ~40s, inject a short burst that trips a security detector."""
        if now - self._last_attack < random.uniform(35, 55):
            return
        self._last_attack = now
        attacker = random.choice(["45.133.1.77", "193.46.255.20", "89.248.165.3"])
        target = random.choice(_CLIENTS)

        if random.random() < 0.5:
            # Port scan: one source hits many destination ports.
            for port in random.sample(range(20, 1024), 25):
                if self._stop.is_set():
                    return
                self._emit(attacker, target, "TCP", 60,
                           sport=random.randint(1024, 65535),
                           dport=port, flags="SYN")
                time.sleep(0.01)
            logger.info("Demo: injected port-scan burst from %s", attacker)
        else:
            # SYN flood: many half-open connections to one port.
            for _ in range(60):
                if self._stop.is_set():
                    return
                self._emit(attacker, target, "TCP", 60,
                           sport=random.randint(1024, 65535),
                           dport=80, flags="SYN")
                time.sleep(0.005)
            logger.info("Demo: injected SYN-flood burst from %s", attacker)

    # -- main loop ---------------------------------------------------------
    def _run(self) -> None:
        interval = 1.0 / self.packets_per_sec
        while not self._stop.is_set():
            # Stand down while real traffic is flowing (live or PCAP replay).
            if self.aggregator.real_traffic_recent():
                time.sleep(1.0)
                continue

            now = time.time()
            self._maybe_attack(now)
            self._normal_packet()
            # Jitter the cadence a little so the bandwidth line looks organic.
            time.sleep(interval * random.uniform(0.5, 1.6))

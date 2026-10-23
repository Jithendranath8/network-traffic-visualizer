FROM python:3.11-slim

WORKDIR /app

# Install system dependencies for packet capture (+ curl/ca-certificates for the GeoIP download)
RUN apt-get update && apt-get install -y \
    libpcap-dev \
    tcpdump \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Download a free IP-to-City GeoIP database (DB-IP Lite, CC-BY-4.0, MaxMind .mmdb
# format — no API key needed) so the geo map works on hosts without live capture.
# Best-effort: tries the current month then the previous one, and never fails the
# build if the download is unavailable (the app degrades gracefully to no geo).
# Cached as its own layer so it isn't re-downloaded on every code change.
RUN set -eux; \
    for ym in "$(date -u +%Y-%m)" "$(date -u -d "$(date -u +%Y-%m-01) -1 month" +%Y-%m)"; do \
        url="https://download.db-ip.com/free/dbip-city-lite-${ym}.mmdb.gz"; \
        echo "Fetching GeoIP database: $url"; \
        if curl -fsSL "$url" -o /tmp/geoip.mmdb.gz; then \
            gunzip -c /tmp/geoip.mmdb.gz > /app/GeoLite2-City.mmdb && rm -f /tmp/geoip.mmdb.gz; \
            echo "GeoIP database installed ($ym)"; \
            break; \
        fi; \
    done; \
    (test -f /app/GeoLite2-City.mmdb && echo "GeoIP ready") || echo "WARNING: GeoIP database not downloaded; geo map will be empty"

# Point the app at the downloaded database (GeoIPLookup degrades gracefully if absent)
ENV GEOIP_DB_PATH=/app/GeoLite2-City.mmdb

# Copy application code
COPY . .

# Set working directory to backend for imports
WORKDIR /app/backend

# Expose port
EXPOSE 8000

# Run with root privileges for packet capture (note: Docker containers run as root by default)
# For production, consider using capabilities: --cap-add=NET_RAW --cap-add=NET_ADMIN
CMD ["sh", "-c", "python main.py --host 0.0.0.0 --port ${PORT:-8000}"]
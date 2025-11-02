FROM python:3.11-slim

WORKDIR /app

# Install system dependencies for packet capture
RUN apt-get update && apt-get install -y \
    libpcap-dev \
    tcpdump \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Set working directory to backend for imports
WORKDIR /app/backend

# Expose port
EXPOSE 8000

# Run with root privileges for packet capture (note: Docker containers run as root by default)
# For production, consider using capabilities: --cap-add=NET_RAW --cap-add=NET_ADMIN
CMD ["python", "main.py", "--host", "0.0.0.0", "--port", "8000"]
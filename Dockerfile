# Authentication Honeypot Framework - Docker Image
# Multi-protocol honeypot with SSH, FTP, Telnet, HTTP/HTTPS, MySQL, RDP, SMB

FROM python:3.11-slim

# Metadata
LABEL maintainer="security@example.com"
LABEL description="Authentication Honeypot Framework - Multi-protocol credential capture"
LABEL version="1.0.0"

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libssl-dev \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first (for better caching)
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY src/ ./src/
COPY config.yaml .

# Note: main.py is inside src/ directory

# Create directories for logs and certificates
RUN mkdir -p logs reports

# Copy entrypoint script
COPY docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Expose all protocol ports (defaults - can be remapped in docker-compose)
# SSH, FTP, Telnet, HTTP, HTTPS, MySQL, RDP, SMB
EXPOSE 2222 2121 2323 8888 8443 3306 3389 445

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD python3 -c "import socket; s=socket.socket(); s.settimeout(2); s.connect(('localhost', 8888)); s.close()" || exit 1

# Set entrypoint
ENTRYPOINT ["docker-entrypoint.sh"]

# Default command
CMD ["python3", "-u", "src/main.py", "-c", "config.yaml"]

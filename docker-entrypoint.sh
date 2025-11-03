#!/bin/bash
# Docker entrypoint script for Authentication Honeypot Framework
# Handles initialization, configuration checks, and graceful startup

set -e

echo "=========================================="
echo "Authentication Honeypot Framework"
echo "Docker Container Starting..."
echo "=========================================="
echo ""

# Display container information
echo "Container Information:"
echo "  Hostname: $(hostname)"
echo "  User: $(whoami)"
echo "  Working Directory: $(pwd)"
echo "  Python Version: $(python3 --version)"
echo ""

# Check if config file exists
if [ ! -f "config.yaml" ]; then
    echo "ERROR: config.yaml not found!"
    echo "Please mount your config file: -v ./config.yaml:/app/config.yaml"
    exit 1
fi

echo "✓ Configuration file found: config.yaml"

# Create required directories
mkdir -p logs reports
echo "✓ Created logs and reports directories"

# Check Python dependencies
echo ""
echo "Checking Python dependencies..."
if python3 -c "import paramiko, cryptography" 2>/dev/null; then
    echo "✓ Core dependencies installed"
else
    echo "WARNING: Some dependencies may be missing"
fi

# Display configured protocols
echo ""
echo "Configured Protocols:"
python3 -c "
import yaml
try:
    with open('config.yaml', 'r') as f:
        config = yaml.safe_load(f)
    protocols = config.get('protocols', {})
    for proto, settings in protocols.items():
        if settings.get('enabled', False):
            port = settings.get('port', settings.get('https_port', 'N/A'))
            print(f'  ✓ {proto.upper():8} - Port {port}')
except Exception as e:
    print(f'  ! Error reading config: {e}')
"

# Display network information
echo ""
echo "Network Configuration:"
echo "  Container IP: $(hostname -i 2>/dev/null || echo 'N/A')"
echo "  Listening on: 0.0.0.0 (all interfaces)"

# Set up signal handling for graceful shutdown
trap 'echo ""; echo "Received SIGTERM, shutting down gracefully..."; exit 0' SIGTERM
trap 'echo ""; echo "Received SIGINT, shutting down gracefully..."; exit 0' SIGINT

echo ""
echo "=========================================="
echo "Starting Honeypot..."
echo "=========================================="
echo ""

# Execute the main command (passed as arguments to this script)
exec "$@"

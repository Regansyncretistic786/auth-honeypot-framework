# Docker Deployment Guide

Complete guide for deploying the Authentication Honeypot Framework using Docker.

## Table of Contents

1. [Quick Start](#quick-start)
2. [Deployment Options](#deployment-options)
3. [Single Container Deployment](#single-container-deployment)
4. [Multi-Container Deployment](#multi-container-deployment)
5. [Configuration](#configuration)
6. [Port Mapping](#port-mapping)
7. [Volume Management](#volume-management)
8. [Monitoring & Logs](#monitoring--logs)
9. [Troubleshooting](#troubleshooting)
10. [Production Best Practices](#production-best-practices)

---

## Quick Start

### Prerequisites

- Docker Engine 20.10+ installed
- Docker Compose 2.0+ installed
- 2GB available RAM
- Ports available (default: 2222, 2121, 2323, 8888, 8443, 3306, 3389, 445)

### Quick Deploy (Single Container)

```bash
# 1. Build the image
docker-compose build

# 2. Start the honeypot
docker-compose up -d

# 3. View logs
docker-compose logs -f

# 4. Check status
docker-compose ps
```

That's it! Your honeypot is now running and capturing attacks.

---

## Deployment Options

### Option 1: Single Container (Recommended)

**Best for:**
- Simple deployment
- Lower resource usage
- Easy management
- Most production environments

**Pros:**
- ✅ One command to start/stop
- ✅ Lower memory footprint (~500MB)
- ✅ Easier networking
- ✅ Simpler monitoring

**Cons:**
- ❌ All protocols share resources
- ❌ If container fails, all protocols down

**File:** `docker-compose.yml`

### Option 2: Multi-Container

**Best for:**
- Maximum isolation
- Independent protocol scaling
- Separate resource limits
- Advanced deployments

**Pros:**
- ✅ Protocol isolation
- ✅ Independent scaling
- ✅ Separate resource limits
- ✅ Partial failures don't affect all

**Cons:**
- ❌ More complex management
- ❌ Higher resource usage (~2GB)
- ❌ More containers to monitor

**File:** `docker-compose-multi.yml`

---

## Single Container Deployment

### 1. Build the Image

```bash
docker-compose build
```

Output:
```
[+] Building 45.2s (12/12) FINISHED
 => [1/7] FROM python:3.11-slim
 => [2/7] COPY requirements.txt .
 => [3/7] RUN pip install --no-cache-dir -r requirements.txt
 ...
 => naming to auth-honeypot:latest
```

### 2. Start the Container

```bash
# Start in background
docker-compose up -d

# Or start with logs visible
docker-compose up
```

### 3. Verify It's Running

```bash
# Check container status
docker-compose ps

# Expected output:
# NAME           STATUS         PORTS
# auth-honeypot  Up 2 minutes   0.0.0.0:2222->2222/tcp, ...

# Check logs
docker-compose logs

# Follow logs in real-time
docker-compose logs -f
```

### 4. Test the Honeypot

```bash
# Test SSH
ssh root@localhost -p 2222

# Test HTTP
curl http://localhost:8888

# Test HTTPS (self-signed cert)
curl -k https://localhost:8443
```

### 5. Stop the Honeypot

```bash
# Stop but keep data
docker-compose stop

# Stop and remove container (keeps logs/data)
docker-compose down

# Stop and remove everything including volumes
docker-compose down -v
```

---

## Multi-Container Deployment

### 1. Build the Image

```bash
docker-compose -f docker-compose-multi.yml build
```

### 2. Start All Containers

```bash
# Start all protocol containers
docker-compose -f docker-compose-multi.yml up -d

# Or start specific protocols only
docker-compose -f docker-compose-multi.yml up -d honeypot-ssh honeypot-http
```

### 3. Manage Individual Protocols

```bash
# Stop SSH honeypot only
docker-compose -f docker-compose-multi.yml stop honeypot-ssh

# Restart HTTP honeypot
docker-compose -f docker-compose-multi.yml restart honeypot-http

# View logs for specific protocol
docker-compose -f docker-compose-multi.yml logs -f honeypot-mysql

# Scale a specific protocol (if needed)
docker-compose -f docker-compose-multi.yml up -d --scale honeypot-ssh=2
```

### 4. Check Status

```bash
# List all containers
docker-compose -f docker-compose-multi.yml ps

# Check resource usage
docker stats
```

### 5. Stop Everything

```bash
docker-compose -f docker-compose-multi.yml down
```

---

## Configuration

### Edit Configuration

The honeypot uses the `config.yaml` file from your host system.

```bash
# Edit configuration
vim config.yaml

# Restart to apply changes
docker-compose restart
```

### Environment Variables

You can override settings with environment variables:

```yaml
# docker-compose.yml
services:
  honeypot:
    environment:
      - PYTHONUNBUFFERED=1
      - TZ=America/New_York
      - HONEYPOT_LOG_LEVEL=DEBUG
```

### Custom Config File

```bash
# Use a different config file
docker-compose run -v ./custom-config.yaml:/app/config.yaml honeypot
```

---

## Port Mapping

### Default Ports (Custom - No Root Needed)

```yaml
ports:
  - "2222:2222"   # SSH
  - "2121:2121"   # FTP
  - "2323:2323"   # Telnet
  - "8888:8888"   # HTTP
  - "8443:8443"   # HTTPS
  - "3306:3306"   # MySQL
  - "3389:3389"   # RDP
  - "4445:445"    # SMB (non-privileged on host)
```

### Standard Ports (Requires Root/Sudo)

To use standard ports on the host, edit `docker-compose.yml`:

```yaml
ports:
  - "22:2222"     # SSH on standard port 22
  - "21:2121"     # FTP on standard port 21
  - "23:2323"     # Telnet on standard port 23
  - "80:8888"     # HTTP on standard port 80
  - "443:8443"    # HTTPS on standard port 443
  - "445:445"     # SMB on standard port 445
```

Then run with elevated privileges:

```bash
sudo docker-compose up -d
```

### Custom Port Mapping

Map any host port to container port:

```yaml
ports:
  - "10022:2222"  # SSH on host port 10022
  - "10080:8888"  # HTTP on host port 10080
```

### Network Mode: Host

For maximum compatibility, use host networking (no port mapping needed):

```yaml
services:
  honeypot:
    network_mode: "host"
    # Remove 'ports:' section when using host mode
```

**Note:** With `host` mode, the container uses the host's network directly. Configure ports in `config.yaml` to match what you want exposed.

---

## Volume Management

### Default Volumes

```yaml
volumes:
  - ./logs:/app/logs              # Logs persist on host
  - ./reports:/app/reports        # Reports persist on host
  - ./config.yaml:/app/config.yaml:ro  # Config (read-only)
  - honeypot-certs:/app          # SSL certificates (named volume)
```

### Accessing Logs

```bash
# Logs are on your host machine
ls -la logs/

# View attack logs
cat logs/attacks_$(date +%Y%m%d).json

# View honeypot logs
tail -f logs/honeypot.log
```

### Backup Logs

```bash
# Backup logs directory
tar -czf honeypot-logs-$(date +%Y%m%d).tar.gz logs/

# Copy to remote server
scp honeypot-logs-*.tar.gz user@backup-server:/backups/
```

### Clear Old Logs

```bash
# Stop honeypot first
docker-compose stop

# Remove old logs
rm logs/attacks_*.json
rm logs/honeypot.log

# Restart
docker-compose start
```

---

## Monitoring & Logs

### View Live Logs

```bash
# All logs
docker-compose logs -f

# Last 100 lines
docker-compose logs --tail=100

# Specific service (multi-container)
docker-compose -f docker-compose-multi.yml logs -f honeypot-ssh
```

### Check Container Health

```bash
# Health status
docker-compose ps

# Detailed health check
docker inspect auth-honeypot | grep -A 10 Health
```

### Resource Usage

```bash
# Real-time stats
docker stats auth-honeypot

# All containers (multi-container)
docker stats
```

### Access Container Shell

```bash
# Open bash in running container
docker-compose exec honeypot /bin/bash

# Run one-off command
docker-compose exec honeypot ls -la logs/
```

### Monitor Attack Logs

```bash
# Watch attack logs in real-time
tail -f logs/attacks_$(date +%Y%m%d).json

# Count attacks
wc -l logs/attacks_$(date +%Y%m%d).json

# Search for specific IP
grep "192.168.1.100" logs/attacks_*.json
```

---

## Troubleshooting

### Container Won't Start

**Check logs:**
```bash
docker-compose logs
```

**Common issues:**

1. **Port already in use**
   ```
   Error: bind: address already in use
   ```
   **Solution:** Change port in `docker-compose.yml` or stop conflicting service

2. **Config file not found**
   ```
   ERROR: config.yaml not found!
   ```
   **Solution:** Ensure `config.yaml` exists in current directory

3. **Permission denied (ports < 1024)**
   ```
   PermissionError: [Errno 13] Permission denied
   ```
   **Solution:** Use `sudo docker-compose up -d`

### Container Keeps Restarting

```bash
# Check why it's restarting
docker-compose logs --tail=50

# Check exit code
docker inspect auth-honeypot | grep ExitCode
```

### Can't Access Honeypot Ports

**Check if ports are listening:**
```bash
# From host
netstat -tlnp | grep docker

# Test connection
nc -zv localhost 2222
```

**Check firewall:**
```bash
# Debian/Ubuntu
sudo ufw status
sudo ufw allow 2222/tcp

# CentOS/RHEL
sudo firewall-cmd --list-all
sudo firewall-cmd --add-port=2222/tcp --permanent
```

### High Memory Usage

**Check resource usage:**
```bash
docker stats auth-honeypot
```

**Reduce limits in `docker-compose.yml`:**
```yaml
deploy:
  resources:
    limits:
      memory: 512M  # Reduce from 1G
```

### SSL Certificate Issues

**Regenerate certificate:**
```bash
# Remove old certificate
docker-compose exec honeypot rm -f honeypot.pem honeypot.key

# Restart to regenerate
docker-compose restart
```

### Logs Not Appearing

**Check volume mounts:**
```bash
# Verify logs directory is mounted
docker-compose exec honeypot ls -la logs/

# Check permissions
ls -ld logs/
```

**Fix permissions:**
```bash
chmod 755 logs/
```

---

## Production Best Practices

### 1. Use Resource Limits

```yaml
deploy:
  resources:
    limits:
      cpus: '2.0'
      memory: 1G
    reservations:
      cpus: '0.5'
      memory: 256M
```

### 2. Set Restart Policy

```yaml
restart: unless-stopped
```

### 3. Enable Log Rotation

```yaml
logging:
  driver: "json-file"
  options:
    max-size: "10m"
    max-file: "3"
```

### 4. Run as Non-Root (When Possible)

```yaml
# Inside container (if not using privileged ports)
user: "1000:1000"
```

### 5. Use Host Network for Production

```yaml
network_mode: "host"
```

### 6. Monitor with Health Checks

```yaml
healthcheck:
  test: ["CMD", "python3", "-c", "import socket; s=socket.socket(); s.connect(('localhost', 8888))"]
  interval: 30s
  timeout: 10s
  retries: 3
```

### 7. Regular Backups

```bash
# Backup logs daily
0 2 * * * cd /path/to/honeypot && tar -czf backup-$(date +\%Y\%m\%d).tar.gz logs/
```

### 8. Automated Log Analysis

```bash
# Parse logs hourly
0 * * * * cd /path/to/honeypot && python3 analyze_logs.py
```

### 9. External Monitoring

Use tools like Prometheus + Grafana:

```yaml
# Add metrics endpoint
ports:
  - "9090:9090"  # Metrics
```

### 10. Security Hardening

```yaml
security_opt:
  - no-new-privileges:true
  - seccomp:unconfined  # Only if needed
```

---

## Docker Commands Reference

### Build & Start

```bash
# Build image
docker-compose build

# Build without cache
docker-compose build --no-cache

# Start containers
docker-compose up -d

# Start with rebuild
docker-compose up -d --build
```

### Stop & Remove

```bash
# Stop containers
docker-compose stop

# Start stopped containers
docker-compose start

# Restart containers
docker-compose restart

# Stop and remove containers
docker-compose down

# Remove containers, networks, and volumes
docker-compose down -v
```

### Logs & Monitoring

```bash
# View logs
docker-compose logs

# Follow logs
docker-compose logs -f

# Logs for specific service
docker-compose logs honeypot

# Resource usage
docker stats
```

### Maintenance

```bash
# Pull latest base images
docker-compose pull

# Remove unused images
docker image prune -a

# Remove unused volumes
docker volume prune

# Clean everything
docker system prune -a --volumes
```

---

## Advanced Configurations

### Custom Dockerfile

Create `Dockerfile.custom`:

```dockerfile
FROM auth-honeypot:latest

# Add custom dependencies
RUN pip install additional-package

# Copy custom scripts
COPY custom-script.py /app/
```

Build:
```bash
docker build -f Dockerfile.custom -t auth-honeypot:custom .
```

### Multiple Instances

Run multiple honeypots on same host:

```bash
# Instance 1 (ports 2222-2323)
docker-compose -p honeypot1 up -d

# Instance 2 (ports 3222-3323) - edit ports in docker-compose.yml
docker-compose -p honeypot2 up -d
```

### Docker Swarm Deployment

```bash
# Initialize swarm
docker swarm init

# Deploy stack
docker stack deploy -c docker-compose.yml honeypot-stack

# Check services
docker service ls

# Scale services
docker service scale honeypot-stack_honeypot=3
```

### Kubernetes Deployment

See `kubernetes/` directory for Kubernetes manifests (coming soon).

---

## Comparison: Docker vs Native

| Feature | Docker | Native |
|---------|--------|--------|
| **Setup Time** | 5 minutes | 15 minutes |
| **Isolation** | Excellent | None |
| **Portability** | Excellent | Poor |
| **Resource Usage** | +100-200MB | Baseline |
| **Updates** | Rebuild image | Manual |
| **Rollback** | Easy | Manual |
| **Multi-Instance** | Easy | Complex |
| **Learning Curve** | Docker knowledge needed | Python knowledge needed |

**Recommendation:** Use Docker for production deployments. Use native for development.

---

## Getting Help

- **Documentation:** [README.md](README.md)
- **Port Configuration:** [PORT_CONFIGURATION.md](PORT_CONFIGURATION.md)
- **Testing:** [TESTING_EVASION.md](TESTING_EVASION.md)
- **Issues:** GitHub Issues

---

## Next Steps

1. ✅ Deploy using Docker Compose
2. ✅ Configure ports in `config.yaml`
3. ✅ Test all protocols
4. ✅ Monitor logs in real-time
5. ✅ Set up log backup/rotation
6. ✅ Configure external monitoring
7. ✅ Deploy to production server

**Your honeypot is now ready to capture attacks! 🎯**

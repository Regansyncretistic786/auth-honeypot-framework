# Docker Quick Reference

One-page reference for deploying the Authentication Honeypot Framework with Docker.

---

## 🚀 Quick Start

### Single Container (Recommended)

```bash
docker-compose up -d              # Start
docker-compose logs -f            # View logs
docker-compose ps                 # Check status
docker-compose down               # Stop
```

### Multi-Container

```bash
docker-compose -f docker-compose-multi.yml up -d     # Start all
docker-compose -f docker-compose-multi.yml ps        # Status
docker-compose -f docker-compose-multi.yml down      # Stop all
```

---

## 📋 Common Commands

### Build & Start

```bash
docker-compose build              # Build image
docker-compose build --no-cache   # Rebuild from scratch
docker-compose up -d              # Start in background
docker-compose up                 # Start with logs
docker-compose up -d --build      # Rebuild and start
```

### Stop & Remove

```bash
docker-compose stop               # Stop (keep data)
docker-compose start              # Start stopped container
docker-compose restart            # Restart
docker-compose down               # Stop and remove container
docker-compose down -v            # Remove container + volumes
```

### Logs & Monitoring

```bash
docker-compose logs               # View all logs
docker-compose logs -f            # Follow logs (live)
docker-compose logs --tail=100    # Last 100 lines
docker stats                      # Resource usage
```

### Maintenance

```bash
docker-compose exec honeypot /bin/bash  # Shell access
docker-compose exec honeypot ls logs/   # Run command
docker system prune -a                  # Clean unused images
```

---

## 🔧 Configuration

### Edit Config

```bash
vim config.yaml
docker-compose restart            # Apply changes
```

### Change Ports

Edit `docker-compose.yml`:

```yaml
ports:
  - "22:2222"     # SSH on standard port 22
  - "2222:2222"   # SSH on custom port 2222
```

Then restart:
```bash
docker-compose down
docker-compose up -d
```

---

## 🧪 Testing

```bash
# Test protocols
ssh root@localhost -p 2222
curl http://localhost:8888
curl -k https://localhost:8443

# View attack logs
tail -f logs/attacks_$(date +%Y%m%d).json

# Count attacks
wc -l logs/attacks_*.json
```

---

## 🐛 Troubleshooting

### Port Already in Use

```bash
# Find what's using port
sudo netstat -tlnp | grep 2222

# Change port in docker-compose.yml
ports:
  - "2223:2222"   # Use 2223 instead
```

### Container Won't Start

```bash
docker-compose logs               # Check error
docker-compose down               # Stop
docker-compose up                 # Start with logs visible
```

### Permission Denied (Ports < 1024)

```bash
sudo docker-compose up -d         # Use sudo
```

### High Memory Usage

Edit `docker-compose.yml`:
```yaml
deploy:
  resources:
    limits:
      memory: 512M  # Reduce from 1G
```

---

## 📊 Monitoring

### Real-time Attack Monitoring

```bash
# Watch container logs
docker-compose logs -f

# Watch attack logs
tail -f logs/attacks_$(date +%Y%m%d).json

# Count by protocol
grep -o '"protocol": "[A-Z]*"' logs/attacks_*.json | sort | uniq -c
```

### Resource Usage

```bash
docker stats auth-honeypot
```

Output:
```
CONTAINER       CPU %   MEM USAGE / LIMIT   MEM %   NET I/O
auth-honeypot   5.2%    287MiB / 1GiB       28%     1.2MB / 856kB
```

---

## 🌐 Port Mappings

### Default (Custom Ports)

| Service | Host Port | Container Port |
|---------|-----------|----------------|
| SSH     | 2222      | 2222           |
| FTP     | 2121      | 2121           |
| Telnet  | 2323      | 2323           |
| HTTP    | 8888      | 8888           |
| HTTPS   | 8443      | 8443           |
| MySQL   | 3306      | 3306           |
| RDP     | 3389      | 3389           |
| SMB     | 4445      | 445            |

### Standard Ports (Requires Sudo)

| Service | Host Port | Container Port |
|---------|-----------|----------------|
| SSH     | 22        | 2222           |
| FTP     | 21        | 2121           |
| Telnet  | 23        | 2323           |
| HTTP    | 80        | 8888           |
| HTTPS   | 443       | 8443           |
| MySQL   | 3306      | 3306           |
| RDP     | 3389      | 3389           |
| SMB     | 445       | 445            |

---

## 📁 Volume Mounts

| Host Path | Container Path | Purpose |
|-----------|----------------|---------|
| `./logs` | `/app/logs` | Attack logs |
| `./reports` | `/app/reports` | Reports |
| `./config.yaml` | `/app/config.yaml` | Configuration |
| `honeypot-certs` | `/app` | SSL certificates |

---

## 🔄 Multi-Container Commands

### Manage Individual Protocols

```bash
# Start specific protocols
docker-compose -f docker-compose-multi.yml up -d honeypot-ssh honeypot-http

# Stop specific protocol
docker-compose -f docker-compose-multi.yml stop honeypot-ssh

# Restart specific protocol
docker-compose -f docker-compose-multi.yml restart honeypot-http

# Logs for specific protocol
docker-compose -f docker-compose-multi.yml logs -f honeypot-mysql

# List all containers
docker-compose -f docker-compose-multi.yml ps
```

### Available Containers

- `honeypot-ssh`
- `honeypot-ftp`
- `honeypot-telnet`
- `honeypot-http`
- `honeypot-https`
- `honeypot-mysql`
- `honeypot-rdp`
- `honeypot-smb`

---

## 🚀 Production Deployment

### Option 1: Custom Ports (No Root)

```bash
# 1. Use default config
docker-compose build
docker-compose up -d

# 2. Verify
docker-compose ps
curl http://localhost:8888

# 3. Monitor
docker-compose logs -f
```

### Option 2: Standard Ports (With Root)

```bash
# 1. Edit docker-compose.yml - uncomment standard ports
# 2. Build and start
docker-compose build
sudo docker-compose up -d

# 3. Verify
curl http://localhost  # Port 80
ssh root@localhost     # Port 22
```

---

## 📚 Documentation Links

| Document | Purpose |
|----------|---------|
| [DOCKER_DEPLOYMENT.md](DOCKER_DEPLOYMENT.md) | Complete Docker guide (850+ lines) |
| [DOCKER_IMPLEMENTATION_SUMMARY.md](DOCKER_IMPLEMENTATION_SUMMARY.md) | Implementation details |
| [DOCKER_QUICK_REFERENCE.md](DOCKER_QUICK_REFERENCE.md) | This document |
| [README.md](README.md) | Main documentation |
| [PORT_CONFIGURATION.md](PORT_CONFIGURATION.md) | Port configuration guide |

---

## ⚡ One-Liners

```bash
# Full restart
docker-compose down && docker-compose up -d

# Rebuild and restart
docker-compose up -d --build

# View logs and follow
docker-compose logs -f --tail=50

# Check container health
docker inspect auth-honeypot | grep -A 5 Health

# Backup logs
tar -czf backup-$(date +%Y%m%d).tar.gz logs/

# Clean everything
docker-compose down -v && docker system prune -a

# Multi-container: restart all
docker-compose -f docker-compose-multi.yml restart
```

---

## 🎯 Tomorrow's Deployment

### Quick Checklist

```bash
# [ ] 1. Verify files exist
ls -la Dockerfile docker-compose.yml config.yaml

# [ ] 2. Build image
docker-compose build

# [ ] 3. Start honeypot
docker-compose up -d

# [ ] 4. Check status
docker-compose ps

# [ ] 5. Test protocols
ssh root@localhost -p 2222
curl http://localhost:8888

# [ ] 6. Monitor logs
docker-compose logs -f
tail -f logs/attacks_$(date +%Y%m%d).json

# [ ] 7. Success! 🎉
```

---

**Ready to deploy! 🐳🚀**

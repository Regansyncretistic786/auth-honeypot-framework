# Dynamic Port Configuration Guide

The Authentication Honeypot Framework supports fully dynamic port configuration. All ports MUST be explicitly configured in `config.yaml`.

## Configuration Requirements

**IMPORTANT**: All ports must be defined in `config.yaml`. There are no hardcoded fallback ports. If a port is not configured and the protocol is enabled, the honeypot will fail to start with a clear error message.

## Using Standard Ports

You can configure the honeypot to use standard service ports if you want maximum realism:

```yaml
protocols:
  ssh:
    enabled: true
    port: 22              # Standard SSH port

  ftp:
    enabled: true
    port: 21              # Standard FTP port

  telnet:
    enabled: true
    port: 23              # Standard Telnet port

  http:
    enabled: true
    port: 80              # Standard HTTP port
    https_enabled: true
    https_port: 443       # Standard HTTPS port

  mysql:
    enabled: true
    port: 3306            # Standard MySQL port

  rdp:
    enabled: true
    port: 3389            # Standard RDP port

  smb:
    enabled: true
    port: 445             # Standard SMB port
```

### Running on Privileged Ports (< 1024)

Standard ports (22, 21, 23, 80, 443, etc.) require root/sudo privileges:

```bash
# Option 1: Run with sudo
sudo python3 honeypot.py

# Option 2: Grant Python capability to bind privileged ports (Linux only)
sudo setcap 'cap_net_bind_service=+ep' $(which python3)
python3 honeypot.py
```

## Using Custom Ports (No Privileges Required)

For testing or when you can't use privileged ports, use custom high ports:

```yaml
protocols:
  ssh:
    enabled: true
    port: 2222            # Custom SSH port

  ftp:
    enabled: true
    port: 2121            # Custom FTP port

  telnet:
    enabled: true
    port: 2323            # Custom Telnet port

  http:
    enabled: true
    port: 8888            # Custom HTTP port
    https_enabled: true
    https_port: 8443      # Custom HTTPS port

  mysql:
    enabled: true
    port: 3306            # MySQL already > 1024, no issue

  rdp:
    enabled: true
    port: 3389            # RDP already > 1024, no issue

  smb:
    enabled: true
    port: 4445            # Custom SMB port (standard 445 needs root)
```

## Selective Protocol Deployment

You can enable only specific protocols and disable others:

```yaml
protocols:
  ssh:
    enabled: true
    port: 22

  ftp:
    enabled: false        # FTP disabled
    # port: 2121          # Port ignored when disabled

  http:
    enabled: true
    port: 80
    https_enabled: false  # HTTP enabled, HTTPS disabled
```

## Error Handling

If you forget to configure a port for an enabled protocol, you'll see:

```
ValueError: SSH port not configured in config.yaml
```

**Solution**: Add the port configuration to `config.yaml`:

```yaml
protocols:
  ssh:
    enabled: true
    port: 2222    # Add this line
```

## Common Deployment Scenarios

### Scenario 1: Maximum Realism (Production Honeypot)
```yaml
# Use standard ports to attract maximum attention from scanners
protocols:
  ssh:
    port: 22
  ftp:
    port: 21
  telnet:
    port: 23
  http:
    port: 80
    https_port: 443
  mysql:
    port: 3306
  rdp:
    port: 3389
  smb:
    port: 445
```

**Requires**: `sudo python3 honeypot.py`

### Scenario 2: Testing/Development
```yaml
# Use high ports for testing without root privileges
protocols:
  ssh:
    port: 2222
  ftp:
    port: 2121
  telnet:
    port: 2323
  http:
    port: 8888
    https_port: 8443
  mysql:
    port: 13306
  rdp:
    port: 13389
  smb:
    port: 14445
```

**Requires**: `python3 honeypot.py` (no sudo needed)

### Scenario 3: Coexistence with Real Services
```yaml
# Run honeypot alongside real services on same server
# Real SSH on 22, honeypot SSH on 2222
protocols:
  ssh:
    port: 2222    # Real SSH already using 22
  ftp:
    port: 21      # No real FTP, use standard port
  http:
    port: 8080    # Real web server on 80
```

### Scenario 4: SSH and HTTP Only
```yaml
# Minimal deployment - only capture SSH and HTTP attacks
protocols:
  ssh:
    enabled: true
    port: 22

  ftp:
    enabled: false

  telnet:
    enabled: false

  http:
    enabled: true
    port: 80
    https_enabled: true
    https_port: 443

  mysql:
    enabled: false

  rdp:
    enabled: false

  smb:
    enabled: false
```

## Port Conflict Detection

If a port is already in use, you'll see:

```
OSError: [Errno 98] Address already in use
```

**Solutions**:
1. Stop the conflicting service: `sudo systemctl stop <service>`
2. Change the honeypot port in `config.yaml`
3. Use different ports for honeypot vs real services

## Checking What's Running

```bash
# Check if ports are in use before starting
sudo netstat -tlnp | grep ':22'
sudo netstat -tlnp | grep ':80'

# Check what honeypot ports are listening after starting
sudo netstat -tlnp | grep python3
```

## Verifying Configuration

Before starting the honeypot:

```bash
# Validate YAML syntax
python3 -c "import yaml; yaml.safe_load(open('config.yaml'))"

# Check configured ports
grep -A 1 "port:" config.yaml
```

Expected output:
```
    port: 2222
    port: 2121
    port: 2323
    port: 8888
    https_port: 8443
    port: 3389
    port: 445
    port: 3306
```

## Best Practices

1. **Production Deployments**: Use standard ports (22, 21, 80, 443, etc.) for maximum realism
2. **Testing**: Use high ports (>1024) to avoid needing sudo
3. **Security**: Never run on standard ports on a server with real services unless isolated
4. **Documentation**: Document your port choices in deployment notes
5. **Firewall Rules**: Update firewall rules to match your port configuration

## Examples

### Example 1: Full Standard Ports (Maximum Realism)
```bash
# Edit config.yaml to use standard ports
vim config.yaml

# Start with sudo
sudo python3 honeypot.py

# Verify all ports listening
sudo netstat -tlnp | grep python3
```

### Example 2: Testing Without Root
```bash
# Edit config.yaml to use high ports
sed -i 's/port: 22/port: 2222/' config.yaml
sed -i 's/port: 21/port: 2121/' config.yaml
sed -i 's/port: 80/port: 8080/' config.yaml

# Start normally
python3 honeypot.py
```

### Example 3: Changing Ports at Runtime
```bash
# Stop honeypot
pkill -f honeypot.py

# Edit configuration
vim config.yaml
# Change: port: 2222 -> port: 22

# Restart with new ports
sudo python3 honeypot.py
```

## Troubleshooting

**Problem**: `ValueError: SSH port not configured in config.yaml`
**Solution**: Add port configuration to config.yaml

**Problem**: `Permission denied` when binding to port < 1024
**Solution**: Run with `sudo` or grant capabilities

**Problem**: `Address already in use`
**Solution**: Check what's using the port with `sudo netstat -tlnp | grep :PORT` and either stop it or choose different port

**Problem**: Can't remember what ports I configured
**Solution**: `grep "port:" config.yaml`

## Security Considerations

- **Isolation**: Run honeypot on dedicated server or isolated network segment
- **Firewall**: Ensure firewall rules allow inbound connections to honeypot ports
- **Monitoring**: Monitor honeypot resource usage to prevent DoS
- **Updates**: Keep honeypot and dependencies updated
- **Analysis**: Regular review of captured credentials and attack patterns

## Related Documentation

- [README.md](README.md) - Main documentation
- [TESTING_EVASION.md](TESTING_EVASION.md) - Testing guide
- [WHAT_ATTACKERS_SEE.md](WHAT_ATTACKERS_SEE.md) - What scanners detect

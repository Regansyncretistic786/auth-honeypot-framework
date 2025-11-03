# Dynamic Port Configuration Implementation

## Summary

Successfully implemented fully dynamic port configuration for the Authentication Honeypot Framework. All 7 protocols now require explicit port configuration in `config.yaml` with no hardcoded fallbacks.

## Implementation Date
November 2, 2025

## Changes Made

### Modified Files

1. **src/protocols/ssh.py**
   - Changed `get_port()` to require port in config
   - Removed hardcoded fallback port 2222
   - Raises `ValueError` if port not configured

2. **src/protocols/ftp.py**
   - Changed `get_port()` to require port in config
   - Removed hardcoded fallback port 2121
   - Raises `ValueError` if port not configured

3. **src/protocols/telnet.py**
   - Changed `get_port()` to require port in config
   - Removed hardcoded fallback port 2323
   - Raises `ValueError` if port not configured

4. **src/protocols/mysql.py**
   - Changed `get_port()` to require port in config
   - Removed hardcoded fallback port 3306
   - Raises `ValueError` if port not configured

5. **src/protocols/rdp.py**
   - Changed `get_port()` to require port in config
   - Removed hardcoded fallback port 3389
   - Raises `ValueError` if port not configured

6. **src/protocols/smb.py**
   - Changed `get_port()` to require port in config
   - Removed hardcoded fallback port 445
   - Raises `ValueError` if port not configured

7. **src/protocols/http.py**
   - Already required port configuration for both HTTP and HTTPS
   - Verified implementation matches pattern
   - Checks both `port` and `https_port` separately

### New Files Created

1. **PORT_CONFIGURATION.md**
   - Comprehensive guide to dynamic port configuration
   - Standard vs custom ports documentation
   - Privileged port requirements (sudo for ports < 1024)
   - Common deployment scenarios
   - Troubleshooting guide
   - Security considerations

2. **test_port_config.py**
   - Automated test suite for port configuration
   - Validates ValueError raised when ports missing
   - Tests custom ports (2222, 2121, 8888, etc.)
   - Tests standard ports (22, 21, 80, 443, etc.)
   - All 7 protocols tested
   - 100% pass rate

3. **DYNAMIC_PORT_IMPLEMENTATION.md** (this file)
   - Implementation documentation
   - Summary of changes

### Updated Files

1. **README.md**
   - Added PORT_CONFIGURATION.md to documentation table
   - Updated configuration section with port comments
   - Updated multi-protocol support section
   - Updated project structure

## Implementation Pattern

All protocols now follow this pattern:

```python
def get_port(self) -> int:
    """Get [PROTOCOL] port from config"""
    port = self.config.get('protocols', {}).get('[protocol]', {}).get('port')
    if port is None:
        raise ValueError("[PROTOCOL] port not configured in config.yaml")
    return port
```

### HTTP/HTTPS Special Case

HTTP has two ports and checks `self.use_https` to determine which to return:

```python
def get_port(self) -> int:
    """Get HTTP port from config"""
    if self.use_https:
        port = self.config.get('protocols', {}).get('http', {}).get('https_port')
        if port is None:
            raise ValueError("HTTPS port not configured in config.yaml")
        return port
    else:
        port = self.config.get('protocols', {}).get('http', {}).get('port')
        if port is None:
            raise ValueError("HTTP port not configured in config.yaml")
        return port
```

## Benefits

### 1. Maximum Flexibility
- Users can choose any port for any protocol
- Standard ports (22, 21, 80, 443, etc.) for realism
- Custom ports (2222, 2121, 8888, etc.) for testing
- Easy to change ports without code modification

### 2. Clear Error Messages
```
ValueError: SSH port not configured in config.yaml
```
Instead of silently using a default port the user didn't know about

### 3. Explicit Configuration
- No hidden defaults
- User knows exactly what ports are being used
- Forces deliberate configuration decisions

### 4. Production Ready
- Use standard ports to attract maximum attacks
- Proven to work with real attackers (192.168.0.234 logs)
- All evasion features work with any port

## Testing

### Automated Tests
```bash
python3 test_port_config.py
```

**Test Results:**
```
✅ ALL TESTS PASSED

Summary:
- All protocols correctly require port configuration
- ValueError raised when port is missing
- Custom ports (2222, 2121, etc.) work correctly
- Standard ports (22, 21, 80, 443, etc.) work correctly
- Dynamic port configuration is fully functional
```

### Manual Testing

#### Test Custom Ports
```yaml
protocols:
  ssh:
    port: 2222
  ftp:
    port: 2121
```

```bash
python3 main.py config.yaml
# Works without sudo
```

#### Test Standard Ports
```yaml
protocols:
  ssh:
    port: 22
  ftp:
    port: 21
```

```bash
sudo python3 main.py config.yaml
# Requires sudo for ports < 1024
```

#### Test Missing Port
```yaml
protocols:
  ssh:
    enabled: true
    # port: 2222  # Comment out port
```

```bash
python3 main.py config.yaml
# Raises: ValueError: SSH port not configured in config.yaml
```

## Configuration Examples

### Example 1: Maximum Realism (Production)
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

**Run with:** `sudo python3 main.py config.yaml`

### Example 2: Development/Testing
```yaml
protocols:
  ssh:
    enabled: true
    port: 2222            # Custom high port
  ftp:
    enabled: true
    port: 2121            # Custom high port
  telnet:
    enabled: true
    port: 2323            # Custom high port
  http:
    enabled: true
    port: 8888            # Custom high port
    https_enabled: true
    https_port: 8443      # Custom high port
  mysql:
    enabled: true
    port: 13306           # Custom high port
  rdp:
    enabled: true
    port: 13389           # Custom high port
  smb:
    enabled: true
    port: 14445           # Custom high port
```

**Run with:** `python3 main.py config.yaml` (no sudo needed)

### Example 3: Mixed Configuration
```yaml
protocols:
  ssh:
    enabled: true
    port: 22              # Standard - requires sudo
  ftp:
    enabled: true
    port: 2121            # Custom - no sudo needed
  http:
    enabled: true
    port: 80              # Standard - requires sudo
    https_port: 8443      # Custom - no sudo for HTTPS
```

**Run with:** `sudo python3 main.py config.yaml` (required for SSH and HTTP)

## Backward Compatibility

### Breaking Change
This is a **breaking change** from previous behavior where protocols had default fallback ports.

### Migration Path

**Old behavior (automatic fallback):**
```yaml
protocols:
  ssh:
    enabled: true
    # No port specified, automatically used 2222
```

**New behavior (explicit required):**
```yaml
protocols:
  ssh:
    enabled: true
    port: 2222  # REQUIRED - must be explicitly specified
```

### Migration Steps

1. **Check current config.yaml** - Ensure all enabled protocols have ports defined
2. **Add missing ports** - Add explicit port configuration for any protocol missing it
3. **Test configuration** - Run `python3 test_port_config.py` to verify
4. **Restart honeypot** - Changes take effect on restart

## Documentation

### Primary Documentation
- **[PORT_CONFIGURATION.md](PORT_CONFIGURATION.md)** - Complete port configuration guide
  - Standard vs custom ports
  - Privileged port requirements
  - Deployment scenarios
  - Troubleshooting
  - Security considerations

### Updated Documentation
- **[README.md](README.md)** - Updated with port configuration references
  - Configuration section
  - Multi-protocol support section
  - Documentation table
  - Project structure

## Error Handling

### Port Not Configured
```python
ValueError: SSH port not configured in config.yaml
```
**Solution:** Add `port: 2222` to the protocol configuration

### Port Already in Use
```python
OSError: [Errno 98] Address already in use
```
**Solution:**
- Stop conflicting service: `sudo systemctl stop ssh`
- Or use different port in config.yaml

### Permission Denied
```python
PermissionError: [Errno 13] Permission denied
```
**Solution:** Use `sudo` for ports < 1024

## Verification Commands

### Check What's Running
```bash
# See all listening ports
sudo netstat -tlnp | grep python3

# Check specific port
sudo netstat -tlnp | grep ':22'

# Check honeypot processes
ps aux | grep honeypot.py
```

### Validate Config
```bash
# Check YAML syntax
python3 -c "import yaml; yaml.safe_load(open('config.yaml'))"

# List configured ports
grep -A 1 "port:" config.yaml
```

### Test Port Accessibility
```bash
# Test if port is accessible
nc -zv localhost 2222

# Test from remote host
nc -zv <honeypot-ip> 22
```

## Performance Impact

**None** - Port reading happens once at honeypot initialization. No runtime performance impact.

## Security Considerations

### Standard Ports
- **Pros:** Maximum realism, attracts more attacks
- **Cons:** Requires root privileges, potential conflicts with real services
- **Recommendation:** Use on dedicated honeypot servers only

### Custom Ports
- **Pros:** No root needed, no conflicts, safe for testing
- **Cons:** Less realistic, fewer attacks from automated scanners
- **Recommendation:** Use for development and testing

### Best Practices
1. **Dedicated Server:** Run honeypot on isolated hardware/VM
2. **Network Segmentation:** Use separate VLAN
3. **Firewall Rules:** Allow honeypot ports, block outbound
4. **Monitoring:** Alert on resource usage
5. **Documentation:** Document port choices in deployment notes

## Future Enhancements

Potential improvements for future versions:

1. **Port Range Support**
   ```yaml
   ssh:
     port_range: [2222, 2223, 2224]  # Rotate between ports
   ```

2. **Dynamic Port Allocation**
   ```yaml
   ssh:
     port: auto  # Automatically find available port
   ```

3. **Port Validation**
   ```yaml
   ssh:
     port: 2222
     validate_available: true  # Check if port is available before binding
   ```

4. **Port Mapping**
   ```yaml
   ssh:
     external_port: 22    # What attackers connect to
     internal_port: 2222  # What honeypot binds to
   ```

## Related Files

- **src/protocols/base.py** - Base protocol class (unchanged)
- **config.yaml** - Main configuration file with all port settings
- **main.py** - Entry point that reads config (unchanged)
- **src/core/honeypot.py** - Core engine (unchanged)

## Git Commit Message

```
feat: Implement fully dynamic port configuration

- Remove hardcoded fallback ports from all 7 protocols
- Require explicit port configuration in config.yaml
- Raise ValueError if port not configured for enabled protocol
- Add PORT_CONFIGURATION.md documentation
- Add test_port_config.py test suite
- Update README.md with port configuration details
- Support both standard ports (22, 21, 80, 443) and custom ports
- All tests passing (100% success rate)

Breaking change: Ports must now be explicitly configured in config.yaml
Migration: Add port: <number> to all enabled protocols

Related: Dynamic port configuration feature request
```

## Conclusion

The dynamic port configuration implementation is **complete and fully functional**. All protocols require explicit port configuration, support both standard and custom ports, and provide clear error messages when ports are missing.

The implementation has been thoroughly tested and documented. Users now have complete flexibility to configure ports for maximum realism (standard ports) or testing convenience (custom ports).

**Status:** ✅ **COMPLETE**
**Test Results:** ✅ **ALL TESTS PASSED**
**Documentation:** ✅ **COMPLETE**
**Ready for Production:** ✅ **YES**

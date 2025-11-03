# Honeypot Security Documentation

## Core Security Principle

**The honeypot NEVER grants access, no matter what credentials are provided.**

## How It Works

### SSH Honeypot Security

```python
def check_auth_password(self, username: str, password: str) -> int:
    """Handle password authentication - always reject but log"""
    # Log the attempt
    self.honeypot.log_auth_attempt(...)

    # Always reject - no password checking at all
    return paramiko.AUTH_FAILED  # ← HARDCODED to always fail
```

- No password database
- No valid credentials
- No password verification
- Always returns `AUTH_FAILED`
- No shell spawned
- No command execution

### FTP Honeypot Security

```python
elif cmd == 'PASS':
    # Log attempt
    self.log_auth_attempt(client_ip, username, password)

    # Always reject
    client_socket.send(b"530 Login incorrect\r\n")  # ← Always fails
```

- No user database
- No file system access
- All file commands return error
- No actual FTP operations executed

### Telnet Honeypot Security

```python
# After receiving username and password:
self.log_auth_attempt(client_ip, username, password)

# Always reject
client_socket.send(b"\r\nLogin incorrect\r\n")  # ← Always fails
```

- No shell spawned
- No command execution
- Closes after logging

## What Attackers Experience

```
Attacker tries: ssh admin@honeypot -p 2222
Honeypot logs: admin + [their password]
Honeypot responds: Permission denied
Attacker sees: "Wrong password, try another"
Reality: There is NO correct password
```

## Verification

Run the security test:
```bash
./test_security.sh
```

This verifies that:
- Common credentials are rejected
- "Clever" credentials are rejected
- ALL credentials are rejected
- No shell access is ever granted
- No file access is ever granted

## Additional Safety Measures

### 1. Rate Limiting
```yaml
rate_limiting:
  enabled: true
  max_connections_per_ip: 50
  auto_block_threshold: 100
```

Prevents abuse and resource exhaustion.

### 2. No Root Privileges Required
- Uses high ports (2222, 2121, 2323)
- Never runs as root
- No privileged operations

### 3. Isolated Logging
- Logs stored in `logs/` directory
- No system-wide access
- No database connections to real systems

### 4. Network Isolation (Recommended)
```bash
# Run in Docker for extra isolation
docker run --rm -p 2222:2222 -p 2121:2121 -p 2323:2323 honeypot

# Or use network namespace
ip netns add honeypot
ip netns exec honeypot python src/main.py
```

### 5. Firewall Rules (Recommended)
```bash
# Only allow connections from specific networks
sudo iptables -A INPUT -p tcp --dport 2222 -s 10.0.0.0/8 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 2222 -j DROP
```

## Threat Model

### What the Honeypot Protects Against:
✅ Logs credential stuffing attacks
✅ Identifies brute-force patterns
✅ Captures attacker IPs and tools
✅ No risk of actual system compromise
✅ Safe to expose to internet

### What the Honeypot Does NOT Protect Against:
❌ DDoS attacks (use rate limiting)
❌ Vulnerabilities in Python/libraries (keep updated)
❌ System compromise via other services

## Best Practices

### ✅ DO:
- Run on isolated VM/container
- Monitor resource usage
- Review logs regularly
- Keep dependencies updated
- Use rate limiting
- Deploy in DMZ if possible

### ❌ DON'T:
- Run on production servers
- Use real credentials in testing
- Expose other services on same host
- Run as root/administrator
- Connect to production databases
- Share network with sensitive systems

## Code Audit Points

If you want to audit the security yourself:

1. **SSH Handler**: `src/protocols/ssh.py:22-36`
   - Verify `return paramiko.AUTH_FAILED` is always executed
   - No password checking logic exists

2. **FTP Handler**: `src/protocols/ftp.py:48-57`
   - Verify `530 Login incorrect` is always sent
   - No file operations granted

3. **Telnet Handler**: `src/protocols/telnet.py:40-62`
   - Verify `Login incorrect` is always sent
   - No shell spawned

4. **Base Honeypot**: `src/protocols/base.py`
   - No `subprocess.Popen()` or shell execution
   - No `os.system()` calls
   - Pure logging only

## Penetration Testing

Feel free to test the honeypot:
```bash
# Try SSH
hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://localhost:2222

# Try FTP
hydra -l admin -P /usr/share/wordlists/rockyou.txt ftp://localhost:2121

# Use metasploit
use auxiliary/scanner/ssh/ssh_login
set RHOSTS localhost
set RPORT 2222
run
```

**Expected result**: ALL attempts fail, all are logged, no access granted.

## Security Updates

If you find any security issues:
1. Review the code in `src/protocols/`
2. Ensure `AUTH_FAILED` / `Login incorrect` is always returned
3. Verify no shell/file access exists
4. Update Python dependencies: `pip install -U -r requirements.txt`

## Questions?

**Q: Can an attacker guess the right password?**
A: No. There is no "right" password. All passwords are rejected.

**Q: Could there be a bug that grants access?**
A: The code has no conditional logic. It's hardcoded to reject. Run `./test_security.sh` to verify.

**Q: Is it safe to expose to the internet?**
A: Yes, but use rate limiting and monitor resources. The honeypot can't grant access, but attackers can waste resources with flood attacks.

**Q: Can attackers exploit vulnerabilities in SSH/FTP protocols?**
A: We use Python's `paramiko` library (SSH) and custom FTP implementation. Keep libraries updated. No known exploits that would grant shell access exist in our usage.

**Q: Should I run other services on the same machine?**
A: No. Isolate the honeypot on its own VM/container for defense in depth.

## Conclusion

The honeypot is designed with security as the primary concern:
- **No valid credentials exist**
- **Authentication always fails**
- **No shell access possible**
- **No file access possible**
- **Only logging occurs**

It's a one-way mirror: attackers can knock, we can watch, but they can never enter.

# Remote Testing Guide

Test your honeypot from any machine on your network - Linux, macOS, or Windows!

## Quick Start

### On Linux (Ubuntu, Debian, Kali, etc.)

```bash
# Install Python 3 if not installed
sudo apt update && sudo apt install python3 python3-pip -y

# Install dependencies
pip3 install paramiko colorama

# Run the test
python3 remote_test.py 192.168.0.165

# Test specific protocol only
python3 remote_test.py 192.168.0.165 --protocol ssh
```

### On macOS

```bash
# Python 3 comes pre-installed on modern macOS
# Install dependencies
pip3 install paramiko colorama

# Run the test
python3 remote_test.py 192.168.0.165

# Show system info
python3 remote_test.py 192.168.0.165 --verbose
```

### On Windows

```powershell
# Open PowerShell or Command Prompt

# Install dependencies
py -m pip install paramiko colorama

# Run the test
py remote_test.py 192.168.0.165

# Test specific protocol
py remote_test.py 192.168.0.165 --protocol ftp
```

## Command Line Options

```
usage: remote_test.py [-h] [--ssh-port SSH_PORT] [--ftp-port FTP_PORT]
                      [--telnet-port TELNET_PORT]
                      [--protocol {ssh,ftp,telnet,all}] [--verbose]
                      host

positional arguments:
  host                  Honeypot IP address (e.g., 192.168.0.165)

optional arguments:
  -h, --help            show this help message and exit
  --ssh-port SSH_PORT   SSH port (default: 2222)
  --ftp-port FTP_PORT   FTP port (default: 2121)
  --telnet-port TELNET_PORT
                        Telnet port (default: 2323)
  --protocol {ssh,ftp,telnet,all}
                        Which protocol to test (default: all)
  --verbose             Show system information
```

## Examples

### Test all protocols (default)
```bash
python3 remote_test.py 192.168.0.165
```

### Test only SSH
```bash
python3 remote_test.py 192.168.0.165 --protocol ssh
```

### Test FTP on custom port
```bash
python3 remote_test.py 192.168.0.165 --protocol ftp --ftp-port 2121
```

### Test with system info
```bash
python3 remote_test.py 192.168.0.165 --verbose
```

## What to Expect

The script will:
1. Connect to your honeypot at the specified IP
2. Attempt authentication with common credentials
3. Show results for each attempt:
   - ✓ Green = Rejected and logged (correct behavior)
   - ✗ Red = Connection error or timeout
   - [!] Red = Granted access (security bug!)
4. Display summary statistics
5. Remind you to check the honeypot dashboard

## Sample Output

```
╔════════════════════════════════════════════════════════════╗
║                                                            ║
║  Remote Honeypot Tester                                    ║
║  Cross-platform: Linux | macOS | Windows                   ║
║                                                            ║
╚════════════════════════════════════════════════════════════╝

Target: 192.168.0.165
Testing authentication with common credentials...

[SSH] Testing SSH honeypot on 192.168.0.165:2222
  [*] Trying admin:Password1 ... ✓ Rejected (logged)
  [*] Trying admin:Password2 ... ✓ Rejected (logged)
  [*] Trying admin:Password3 ... ✓ Rejected (logged)
  [*] Trying root:toor ... ✓ Rejected (logged)
  [*] Trying user:password123 ... ✓ Rejected (logged)

  Summary: 5/5 attempts logged

[FTP] Testing FTP honeypot on 192.168.0.165:2121
  [*] Trying admin:admin ... ✓ Rejected (logged)
  [*] Trying ftp:ftp ... ✓ Rejected (logged)
  [*] Trying anonymous:(empty) ... ✓ Rejected (logged)
  [*] Trying user:password ... ✓ Rejected (logged)

  Summary: 4/4 attempts logged

============================================================
Test Complete!
============================================================

Total attempts sent: 12
Successfully logged: 12

Check the honeypot dashboard to see these attacks!
```

## Verifying Results

After running the test, verify on your honeypot machine:

```bash
# On the honeypot (Kali machine)
cd /home/parallels/scripts/auth-honeypot-framework

# Check the live dashboard
python3 monitor.py

# Or view raw logs
cat logs/attacks_*.json | tail -20
```

You should see your test machine's IP address in the logs!

## Troubleshooting

### Connection Timeout
```
✗ Timeout
```
**Solutions:**
- Verify honeypot is running: `ps aux | grep python3`
- Check firewall rules
- Verify IP address is correct
- Test with netcat: `nc -zv 192.168.0.165 2222`

### Missing Dependencies
```
Error: Missing required dependencies: paramiko, colorama
```
**Solution:**
- Install with pip as shown in platform-specific instructions above

### Connection Refused
```
✗ Error: [Errno 111] Connection refused
```
**Solutions:**
- Honeypot might not be running
- Wrong IP address
- Wrong port number
- Firewall blocking connection

## Cross-Platform Notes

### Linux
- Works on all distributions: Ubuntu, Debian, Kali, CentOS, Fedora, Arch, etc.
- Python 3.6+ required
- May need `sudo` for pip install if not using virtual environment

### macOS
- Works on both Intel and Apple Silicon (M1/M2/M3)
- Python 3 comes pre-installed on macOS 10.15+
- On older macOS, install Python 3 from python.org

### Windows
- Works on Windows 7, 10, 11
- Use `py` command instead of `python3`
- Run from PowerShell or Command Prompt
- May need to allow Python through Windows Firewall

## Network Requirements

- Both machines must be on the same network (or routable)
- Outgoing connections allowed on testing machine
- Honeypot ports accessible (check firewall rules)
- No VPN blocking local network traffic

## Security Note

This script is designed for testing defensive security systems (honeypots) only. It should only be used to test systems you own or have explicit permission to test.

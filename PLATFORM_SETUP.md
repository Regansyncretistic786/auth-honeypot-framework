# Platform Setup - Quick Reference

Copy and paste these commands for your operating system.

---

## 🐧 Linux (Ubuntu/Debian/Kali)

```bash
# Install Python and pip
sudo apt update && sudo apt install python3 python3-pip -y

# Install dependencies
pip3 install paramiko colorama

# Test the honeypot
python3 remote_test.py 192.168.0.165
```

---

## 🐧 Linux (CentOS/RHEL/Fedora)

```bash
# Install Python and pip
sudo yum install python3 python3-pip -y

# Install dependencies
pip3 install paramiko colorama

# Test the honeypot
python3 remote_test.py 192.168.0.165
```

---

## 🍎 macOS

```bash
# Python 3 is pre-installed on modern macOS
# If not, download from: https://www.python.org/downloads/

# Install dependencies
pip3 install paramiko colorama

# Test the honeypot
python3 remote_test.py 192.168.0.165
```

### macOS Apple Silicon (M1/M2/M3)

If you encounter issues, try:
```bash
# Use Rosetta Python if needed
arch -x86_64 pip3 install paramiko colorama
arch -x86_64 python3 remote_test.py 192.168.0.165
```

---

## 🪟 Windows 10/11

### PowerShell (Recommended)

```powershell
# Install Python from: https://www.python.org/downloads/
# Make sure "Add Python to PATH" is checked during installation

# Install dependencies
py -m pip install paramiko colorama

# Test the honeypot
py remote_test.py 192.168.0.165
```

### Command Prompt

```cmd
REM Same commands as PowerShell
py -m pip install paramiko colorama
py remote_test.py 192.168.0.165
```

### Windows Subsystem for Linux (WSL)

```bash
# Follow Linux instructions above
pip3 install paramiko colorama
python3 remote_test.py 192.168.0.165
```

---

## ⚡ Quick Test Commands

```bash
# Test all protocols (default)
python3 remote_test.py 192.168.0.165

# Test SSH only
python3 remote_test.py 192.168.0.165 --protocol ssh

# Test FTP only
python3 remote_test.py 192.168.0.165 --protocol ftp

# Test Telnet only
python3 remote_test.py 192.168.0.165 --protocol telnet

# Show system info
python3 remote_test.py 192.168.0.165 --verbose

# Custom ports
python3 remote_test.py 192.168.0.165 --ssh-port 2222 --ftp-port 2121
```

---

## 🔍 Verify Installation

```bash
# Check Python version (must be 3.6+)
python3 --version

# Check pip
pip3 --version

# Test script help
python3 remote_test.py --help
```

---

## 📝 Find Your Honeypot IP

### On the honeypot machine (Linux):
```bash
# Get local IP address
ip addr show | grep "inet " | grep -v 127.0.0.1

# Or
hostname -I
```

### On macOS:
```bash
ifconfig | grep "inet " | grep -v 127.0.0.1
```

### On Windows:
```powershell
ipconfig | findstr IPv4
```

---

## 🎯 Verify Honeypot is Listening

```bash
# From testing machine, check if ports are open
nc -zv 192.168.0.165 2222    # SSH
nc -zv 192.168.0.165 2121    # FTP
nc -zv 192.168.0.165 2323    # Telnet
```

Windows (PowerShell):
```powershell
Test-NetConnection -ComputerName 192.168.0.165 -Port 2222
```

---

## 🐛 Common Issues

### "command not found: python3"
**Linux/macOS:** Install Python 3
**Windows:** Use `py` instead of `python3`

### "No module named 'paramiko'"
**Solution:** Run pip install command for your platform above

### "Connection refused"
**Solutions:**
- Honeypot not running
- Wrong IP address
- Firewall blocking connection
- Wrong port number

### Colors not working on Windows
**Solution:** Install colorama which was included in the dependencies

### Permission denied (Linux/macOS)
**Solution:** Add `--user` flag: `pip3 install --user paramiko colorama`

---

## 📊 Verify Results

On the honeypot machine:
```bash
cd /home/parallels/scripts/auth-honeypot-framework

# Live dashboard
python3 monitor.py

# Raw logs
tail -f logs/attacks_*.json
```

You should see your testing machine's IP in the logs!

---

## 🌐 Network Setup

Make sure both machines can communicate:

```bash
# From testing machine, ping honeypot
ping 192.168.0.165

# Check if on same subnet
ip route   # Linux/macOS
route print # Windows
```

Common scenarios:
- **Same WiFi network:** Should work directly
- **Ethernet/LAN:** Should work directly
- **VPN active:** May block local network access - disable VPN
- **Docker:** Use host network mode
- **VM:** Use bridged network adapter

---

## 🔐 Security Reminder

Only test systems you own or have explicit permission to test. This tool is for defensive security purposes only.

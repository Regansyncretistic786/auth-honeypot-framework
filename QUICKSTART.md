# Honeypot Quick Start Guide

## Step-by-Step: Run and Test the Honeypot

### Step 1: Install Dependencies

```bash
cd /home/parallels/scripts/auth-honeypot-framework

# Activate virtual environment
source venv/bin/activate

# Install required packages
pip install -r requirements.txt
```

### Step 2: Check Your Network IP

```bash
# Find your Kali VM's IP address
ip addr show | grep "inet " | grep -v 127.0.0.1
```

Note your IP (e.g., `192.168.1.100`)

### Step 3: Start the Honeypot

```bash
# Run the honeypot
python src/main.py
```

You should see:
```
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   Authentication Honeypot Framework                           ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝

Starting Honeypot Services...

Enabled Services:
  • SSH        on port 2222
  • FTP        on port 2121
  • TELNET     on port 2323
```

**Leave this terminal open!** The honeypot is now running.

### Step 4: Test from Another Terminal

Open a **new terminal** and test the honeypot:

#### Test SSH Honeypot
```bash
# Try to connect
ssh admin@localhost -p 2222

# When prompted for password, type anything:
# Password: wrongpassword123

# It will reject you - that's correct!
```

#### Test FTP Honeypot
```bash
# Connect with FTP client
ftp localhost 2121

# At the login prompt:
# Name: admin
# Password: password123

# It will reject - that's working correctly!
```

#### Test Telnet Honeypot
```bash
# Connect via telnet
telnet localhost 2323

# Enter credentials when prompted:
# login: root
# Password: admin

# It will reject - perfect!
```

### Step 5: Check the Logs

In another terminal:

```bash
cd /home/parallels/scripts/auth-honeypot-framework

# View the attack log
cat logs/attacks_$(date +%Y%m%d).json

# Pretty print with jq (if installed)
cat logs/attacks_$(date +%Y%m%d).json | jq .
```

You should see JSON entries like:
```json
{
  "protocol": "SSH",
  "source_ip": "127.0.0.1",
  "username": "admin",
  "password": "wrongpassword123",
  "success": false,
  "event_type": "auth_attempt",
  "timestamp": "2025-11-01T10:30:45.123456"
}
```

---

## Testing with Docker (Simulated Attacker)

### Step 1: Create Test Script

I'll create a script that simulates an attacker trying common credentials.

### Step 2: Run Attacker Container

```bash
# Pull a simple Linux container
docker pull alpine:latest

# Run interactive container
docker run -it --rm alpine sh

# Inside the container, install SSH client
apk add openssh-client

# Try to attack the honeypot (use your Kali VM's IP)
# Replace 192.168.1.100 with your actual IP
ssh admin@192.168.1.100 -p 2222
ssh root@192.168.1.100 -p 2222
ssh test@192.168.1.100 -p 2222
```

### Step 3: Automated Attack Simulation

Run this from your Kali VM to simulate a brute-force attack:

```bash
cd /home/parallels/scripts/auth-honeypot-framework

# Run the test script (I'll create this)
./test_attack.sh
```

---

## Testing with Another VM

### If you have another VM on the same network:

1. **Find your Kali IP:**
   ```bash
   hostname -I
   ```

2. **From the other VM:**
   ```bash
   # Test SSH
   ssh admin@<KALI_IP> -p 2222

   # Test FTP
   ftp <KALI_IP> 2121

   # Test Telnet
   telnet <KALI_IP> 2323
   ```

3. **Check logs on Kali:**
   ```bash
   tail -f /home/parallels/scripts/auth-honeypot-framework/logs/attacks_*.json
   ```

---

## View Real-Time Attack Activity

```bash
# In another terminal, watch the log file
cd /home/parallels/scripts/auth-honeypot-framework
tail -f logs/attacks_$(date +%Y%m%d).json
```

Now when you test from Docker/another VM, you'll see attacks appear in real-time!

---

## Generate Intelligence Report

After collecting some attack data:

```bash
cd /home/parallels/scripts/auth-honeypot-framework
source venv/bin/activate

# Create a simple report script
python3 << 'EOF'
from src.core.analyzer import AttackAnalyzer
from src.core.reporter import Reporter
import yaml

# Load config
with open('config.yaml') as f:
    config = yaml.safe_load(f)

# Analyze attacks
analyzer = AttackAnalyzer('logs')
analysis = analyzer.analyze(days=1)

# Print summary
print("\n" + "="*70)
print(analyzer.get_summary(analysis))
print("="*70 + "\n")

# Generate reports
reporter = Reporter(config)
reporter.generate_report(days=1, formats=['json', 'html', 'text'])
EOF
```

View the HTML report:
```bash
xdg-open reports/report_*.html
```

---

## Stop the Honeypot

Press `Ctrl+C` in the terminal running the honeypot.

---

## Next Steps

1. **Deploy on Internet-Facing VM**: Expose ports and collect real attack data
2. **Analyze Patterns**: Review common usernames/passwords attackers use
3. **Share Intelligence**: Use findings to improve your real server security
4. **Automate Reports**: Set up cron job to generate daily reports

## Troubleshooting

**Port already in use:**
```bash
# Check what's using the port
sudo lsof -i :2222

# Kill the process or change port in config.yaml
```

**Permission denied:**
```bash
# Make sure you're using high ports (>1024)
# Ports 2222, 2121, 2323 don't need sudo
```

**No attacks logged:**
```bash
# Check logs directory exists
ls -la logs/

# Check honeypot is running
ps aux | grep main.py

# Verify you can connect
nc -zv localhost 2222
```

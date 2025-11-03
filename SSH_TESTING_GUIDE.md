# SSH Honeypot Testing Guide

## The SSH Timeout Issue - FIXED ✓

### What Was Happening

The SSH honeypot was experiencing timeouts when tested with simple tools like `netcat` (nc):

```
paramiko.ssh_exception.SSHException: Error reading SSH protocol banner
SSH negotiation failed from 127.0.0.1: Error reading SSH protocol banner
```

**Why this happened:**
- Netcat opens a TCP connection but doesn't complete the SSH protocol handshake
- Paramiko (SSH library) waits for the client to send SSH protocol data
- When the client doesn't respond properly, it times out
- **The connection was NOT being logged** - this is a problem for honeypot intelligence!

### The Fix

Modified `/home/parallels/scripts/auth-honeypot-framework/src/protocols/ssh.py` to:

1. **Log failed SSH negotiations as reconnaissance attempts**
   - When a client connects but doesn't complete the SSH handshake, it's logged as `ssh_probe`
   - Useful for detecting port scanners and reconnaissance tools

2. **Log all SSH connection errors**
   - Any unexpected errors are now logged with details
   - Helps identify scanning patterns and attack attempts

### What Gets Logged Now

#### Scenario 1: Port Scanner (netcat, nmap, etc.)
```json
{
  "timestamp": "2025-11-02T07:30:00",
  "protocol": "SSH",
  "source_ip": "127.0.0.1",
  "username": "Unknown",
  "success": false,
  "event_type": "auth_attempt",
  "scan_type": "ssh_probe",
  "error": "negotiation_failed",
  "description": "Client connected but failed SSH protocol negotiation"
}
```

#### Scenario 2: Proper SSH Authentication Attempt
```json
{
  "timestamp": "2025-11-02T07:30:00",
  "protocol": "SSH",
  "source_ip": "192.168.1.100",
  "username": "admin",
  "password": "password123",
  "success": false,
  "event_type": "auth_attempt"
}
```

---

## How to Test SSH Properly

### Method 1: Use ssh-keyscan (Best for Banner Testing)

Test banner variation:
```bash
for i in {1..5}; do
    ssh-keyscan -p 2222 localhost 2>&1 | grep "SSH-"
    sleep 0.5
done
```

**Expected output** (if banners are randomized):
```
# localhost:2222 SSH-2.0-OpenSSH_9.3p1 Ubuntu-1ubuntu3
# localhost:2222 SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4
# localhost:2222 SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.9
```

### Method 2: Use sshpass (Best for Auth Testing)

Install sshpass:
```bash
sudo apt install sshpass
```

Test authentication attempts:
```bash
# Single attempt
sshpass -p "wrongpass" ssh -o StrictHostKeyChecking=no testuser@localhost -p 2222

# Multiple attempts to test timing
for i in {1..3}; do
    echo "Attempt $i:"
    time sshpass -p "password$i" ssh -o StrictHostKeyChecking=no user$i@localhost -p 2222
    sleep 1
done
```

### Method 3: Use Python paramiko (Most Accurate)

```python
import paramiko
import time

def test_ssh_auth(host, port, username, password):
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        start = time.time()
        client.connect(host, port=port, username=username, password=password, timeout=5)
        elapsed = time.time() - start
        print(f"Connected in {elapsed:.2f}s")
    except paramiko.AuthenticationException:
        elapsed = time.time() - start
        print(f"Auth failed in {elapsed:.2f}s (expected)")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        client.close()

# Test multiple attempts
for i in range(3):
    print(f"\nAttempt {i+1}:")
    test_ssh_auth("localhost", 2222, f"user{i}", f"pass{i}")
    time.sleep(0.5)
```

### Method 4: Quick Test Script

Use the provided script:
```bash
./test_ssh_properly.sh
```

---

## Testing Different Scenarios

### Test 1: Banner Randomization

Remove/comment banner from config.yaml:
```yaml
protocols:
  ssh:
    enabled: true
    port: 2222
    # banner: "SSH-2.0-OpenSSH_8.2"  # Comment this out
    max_auth_attempts: 3
```

Then restart honeypot and run:
```bash
for i in {1..10}; do
    ssh-keyscan -p 2222 localhost 2>&1 | grep "SSH-" | awk '{print $3}'
done | sort | uniq -c
```

**Good result:** Should see multiple different versions
```
      2 SSH-2.0-OpenSSH_8.2p1
      3 SSH-2.0-OpenSSH_8.9p1
      2 SSH-2.0-OpenSSH_9.0p1
      3 SSH-2.0-OpenSSH_9.3p1
```

### Test 2: Port Scanner Detection

Simulate port scanner with netcat:
```bash
# These should be logged as ssh_probe
for i in {1..5}; do
    echo "Probe $i:"
    timeout 1 nc localhost 2222 < /dev/null
    sleep 0.5
done
```

Check logs:
```bash
# Should see ssh_probe entries
cat logs/attacks_$(date +%Y%m%d).json | jq 'select(.scan_type == "ssh_probe")'
```

### Test 3: Authentication Timing

Test that auth has realistic delays (100-400ms):
```bash
for i in {1..5}; do
    echo "Attempt $i:"
    time sshpass -p "test" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 test@localhost -p 2222 2>&1 | head -1
done
```

**Good result:** Times should vary (not identical)

### Test 4: Brute Force Attack Simulation

Simulate a brute force attack:
```bash
# Create small wordlist
cat > /tmp/test_passwords.txt << EOF
admin
password
12345
root123
test
EOF

# Test with hydra (if installed)
hydra -l admin -P /tmp/test_passwords.txt ssh://localhost:2222

# Or with custom script
while read pass; do
    echo "Trying: $pass"
    sshpass -p "$pass" ssh -o StrictHostKeyChecking=no admin@localhost -p 2222 2>&1 | grep -i "denied"
    sleep 0.3
done < /tmp/test_passwords.txt
```

---

## Monitoring SSH Activity

### Real-time monitoring

Watch all SSH activity:
```bash
tail -f logs/honeypot.log | grep SSH
```

Watch SSH authentication attempts:
```bash
tail -f logs/attacks_$(date +%Y%m%d).json | jq 'select(.protocol == "SSH")'
```

Watch SSH probes/scans:
```bash
tail -f logs/attacks_$(date +%Y%m%d).json | jq 'select(.scan_type == "ssh_probe")'
```

### Analysis queries

Count total SSH attempts:
```bash
cat logs/attacks_$(date +%Y%m%d).json | jq 'select(.protocol == "SSH")' | wc -l
```

Count SSH probes vs real attempts:
```bash
echo "SSH Probes:"
cat logs/attacks_$(date +%Y%m%d).json | jq -s '[.[] | select(.scan_type == "ssh_probe")] | length'

echo "SSH Auth Attempts:"
cat logs/attacks_$(date +%Y%m%d).json | jq -s '[.[] | select(.protocol == "SSH" and .scan_type == null)] | length'
```

Top usernames attempted:
```bash
cat logs/attacks_$(date +%Y%m%d).json | jq -r 'select(.protocol == "SSH" and .username != "Unknown") | .username' | sort | uniq -c | sort -rn | head -10
```

---

## Expected Behavior

| Test Type | Expected Result |
|-----------|----------------|
| **ssh-keyscan** | Shows SSH banner, varies if config doesn't override |
| **sshpass auth** | "Permission denied" after 100-400ms delay |
| **netcat probe** | Connection closes, logged as `ssh_probe` |
| **nmap scan** | Detects SSH service, logged as `ssh_probe` |
| **Brute force** | All attempts logged with usernames/passwords |
| **Rate limiting** | Blocks after 50 attempts in 5 minutes |

---

## Troubleshooting

### Still getting timeouts

**Issue:** Timeouts still occurring after fix

**Solution:** Restart the honeypot to load the updated code:
```bash
# Find and kill existing process
pkill -f "python3.*main.py"

# Start fresh
cd /home/parallels/scripts/auth-honeypot-framework
python3 main.py config.yaml
```

### Probes not being logged

**Issue:** netcat connections not appearing in logs

**Solution:**
1. Check if honeypot is running: `ps aux | grep honeypot`
2. Check log file permissions: `ls -la logs/`
3. Check for errors: `tail logs/honeypot.log`

### Same banner every time

**Issue:** Banner doesn't vary

**Solution:** Remove hardcoded banner from config.yaml:
```yaml
protocols:
  ssh:
    enabled: true
    port: 2222
    # Remove or comment out the banner line
```

---

## Why This Matters for Honeypots

**Intelligence Value:**

1. **Port Scanners**: Detecting reconnaissance is just as valuable as catching login attempts
2. **Automated Tools**: Many attack tools do quick checks before attempting auth
3. **Pattern Analysis**: Failed negotiations can reveal scanning patterns
4. **Attribution**: Different tools have different negotiation behaviors

**Example Attack Flow:**
```
1. Attacker scans port 2222 (logged as ssh_probe)
2. Scanner detects SSH service
3. Attacker launches brute force (logged as auth_attempts)
4. All activity attributed to same IP
```

This comprehensive logging helps build a complete picture of attack attempts!

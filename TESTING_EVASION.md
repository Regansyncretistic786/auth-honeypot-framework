# Testing Evasion & Realism Features

This guide shows you how to test all the evasion and realism features implemented in the honeypot.

## Quick Start

### 1. Start the Honeypot (if not running)

```bash
cd /home/parallels/scripts/auth-honeypot-framework
python3 main.py config.yaml
```

### 2. Run Simple Tests (in another terminal)

```bash
cd /home/parallels/scripts/auth-honeypot-framework
./test_evasion_simple.sh
```

This tests:
- ✓ SSH banner variation
- ✓ FTP banner variation
- ✓ HTTP Server header variation
- ✓ HTTP scanner detection (python-requests, curl, nikto, headless browsers)
- ✓ FTP authentication timing delays
- ✓ MySQL version variation

### 3. Run Full Python Test Suite

```bash
python3 test_evasion.py
```

Or test a specific protocol:
```bash
python3 test_evasion.py ssh
python3 test_evasion.py http
python3 test_evasion.py ftp
```

---

## Feature Testing Details

### 1. Banner Randomization

**What it does:** Each connection gets a different, realistic version banner to avoid fingerprinting.

**Test manually:**

```bash
# SSH - should show different OpenSSH versions
for i in {1..5}; do nc localhost 2222 | head -1; sleep 0.5; done

# FTP - should show different FTP server types
for i in {1..5}; do timeout 1 nc localhost 2121 | head -1; sleep 0.5; done

# HTTP - should show different Server headers
for i in {1..5}; do
    echo -e "GET / HTTP/1.1\r\nHost: test\r\n\r\n" | nc localhost 8080 | grep "^Server:"
    sleep 0.5
done
```

**Expected result:** Different banners on each connection (e.g., "OpenSSH_9.3p1", "OpenSSH_8.9p1", etc.)

---

### 2. Realistic Timing Delays

**What it does:** Adds realistic delays to avoid instant responses that reveal honeypot nature.

**Test timing variation:**

```bash
# Run multiple connections and observe timing
for i in {1..5}; do
    time timeout 1 nc localhost 2222 > /dev/null 2>&1
done
```

**Expected result:**
- Connection delays: 50-150ms
- Auth delays: 100-400ms
- Variation between attempts (not identical times)

---

### 3. HTTP Browser Fingerprinting

**What it does:** Detects scanners, bots, and headless browsers based on User-Agent and headers.

**Test scanner detection:**

```bash
# Normal browser (should NOT be flagged)
echo -e "GET / HTTP/1.1\r\nHost: test\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\nAccept: text/html\r\n\r\n" | nc localhost 8080 > /dev/null

# Python requests (SHOULD be flagged)
echo -e "GET / HTTP/1.1\r\nHost: test\r\nUser-Agent: python-requests/2.28.0\r\n\r\n" | nc localhost 8080 > /dev/null

# cURL (SHOULD be flagged)
echo -e "GET / HTTP/1.1\r\nHost: test\r\nUser-Agent: curl/7.68.0\r\n\r\n" | nc localhost 8080 > /dev/null

# Nikto scanner (SHOULD be flagged)
echo -e "GET / HTTP/1.1\r\nHost: test\r\nUser-Agent: Mozilla/5.00 (Nikto/2.1.6)\r\n\r\n" | nc localhost 8080 > /dev/null

# Headless Chrome (SHOULD be flagged)
echo -e "GET / HTTP/1.1\r\nHost: test\r\nUser-Agent: HeadlessChrome/90.0\r\n\r\n" | nc localhost 8080 > /dev/null
```

**Check logs for detection:**

```bash
# Watch for SUSPICIOUS CLIENT warnings in real-time
tail -f logs/honeypot.log | grep "SUSPICIOUS"

# Or check attack logs
tail logs/attacks_$(date +%Y%m%d).json | jq 'select(.scan_type == "suspicious_client")'
```

**Expected result:** Logs should show:
```
WARNING SUSPICIOUS CLIENT detected from 127.0.0.1: Scanner=True, Confidence=0.9, Indicators=scanner_pattern:python-requests
```

---

### 4. Response Variation

**What it does:** Varies error messages slightly to avoid fingerprinting patterns.

**Test error message variation:**

```bash
# FTP - try multiple failed auth attempts
for i in {1..5}; do
    (echo "USER test"; sleep 0.2; echo "PASS wrong") | nc localhost 2121 | grep "530"
    sleep 0.5
done
```

**Expected result:** Should see variations like:
- "530 Login incorrect."
- "530 Authentication failed."
- "530 Login authentication failed"

---

## Testing with Real Tools

### With nmap (service detection)

```bash
# Scan multiple times and check if service versions vary
nmap -sV -p 2222,2121,8080 localhost
sleep 5
nmap -sV -p 2222,2121,8080 localhost
```

### With Nikto (web scanner)

```bash
nikto -host http://localhost:8080
```

Then check logs for scanner detection:
```bash
grep "SUSPICIOUS" logs/honeypot.log
```

### With Hydra (brute force)

```bash
# Test SSH
hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://localhost:2222

# Test FTP
hydra -l admin -P /usr/share/wordlists/rockyou.txt ftp://localhost:2121
```

---

## Monitoring Logs

### Real-time monitoring for suspicious clients:

```bash
# Watch honeypot.log for warnings
tail -f logs/honeypot.log | grep --color=always -E "SUSPICIOUS|WARNING"

# Watch attacks in JSON format
tail -f logs/attacks_$(date +%Y%m%d).json | jq 'select(.scan_type == "suspicious_client")'

# Watch all HTTP attacks
tail -f logs/attacks_$(date +%Y%m%d).json | jq 'select(.protocol == "HTTP")'
```

### Analyzing results:

```bash
# Count scanner detections
cat logs/attacks_$(date +%Y%m%d).json | jq 'select(.scan_type == "suspicious_client")' | wc -l

# See unique user agents detected as scanners
cat logs/attacks_$(date +%Y%m%d).json | jq -r 'select(.user_agent) | .user_agent' | sort | uniq

# Show detection confidence scores
cat logs/attacks_$(date +%Y%m%d).json | jq 'select(.detection) | {ip: .source_ip, confidence: .detection.confidence, scanner: .detection.is_scanner}'
```

---

## Expected Behavior Summary

| Feature | Expected Result |
|---------|----------------|
| **Banner Variation** | Different version strings on each connection |
| **Timing Delays** | 50-300ms variation between connections |
| **Auth Delays** | 100-400ms delay before auth response |
| **Scanner Detection** | python-requests, curl, nikto flagged with confidence 0.7-0.9 |
| **Headless Detection** | HeadlessChrome, PhantomJS flagged with confidence 0.8+ |
| **Bot Detection** | Requests missing common headers flagged with confidence 0.6+ |
| **Error Variation** | Different error messages (30% variation rate) |

---

## Troubleshooting

### Issue: Same banner every time

**Cause:** Config file has hardcoded banner
**Solution:** Remove banner settings from config.yaml to use random banners

### Issue: No scanner detection in logs

**Cause:** May not be looking at correct log file
**Solution:**
```bash
# Check if HTTP honeypot is running
ps aux | grep honeypot

# Check latest log file
ls -lt logs/
tail logs/attacks_$(date +%Y%m%d).json
```

### Issue: Timing too fast (< 50ms)

**Cause:** Evasion engine not being called
**Solution:** Check that protocol's handle_client() calls `self.evasion.add_realistic_delay()`

---

## Success Indicators

✅ **Evasion is working well if you see:**
- Different banners across 5+ connections
- Response times vary by >50ms between connections
- Scanner user-agents logged as "SUSPICIOUS CLIENT"
- Different error messages on repeated failed auth attempts

❌ **Needs attention if you see:**
- Identical banners every time
- Consistent timing (no variation)
- Scanner tools NOT being flagged in logs
- Identical error messages every time

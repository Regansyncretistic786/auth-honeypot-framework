#!/bin/bash
# Test SSH honeypot with proper SSH clients

HOST="localhost"
PORT="2222"

echo "=========================================="
echo "SSH Honeypot Testing"
echo "=========================================="
echo ""

echo "1. Testing SSH Banner Variation with proper SSH client"
echo "   (Using ssh-keyscan which properly negotiates SSH protocol)"
echo ""

for i in {1..5}; do
    echo -n "   Attempt $i: "
    ssh-keyscan -p $PORT $HOST 2>&1 | grep "SSH-" | head -1
    sleep 0.5
done

echo ""
echo "2. Testing Authentication with sshpass (if available)"
if command -v sshpass &> /dev/null; then
    echo "   Attempting authentication attempts..."
    for i in {1..3}; do
        echo "   Attempt $i:"
        timeout 5 sshpass -p "testpass" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null testuser@$HOST -p $PORT 2>&1 | grep -i "denied\|failed\|password" | head -1
        sleep 0.5
    done
else
    echo "   sshpass not installed. Install with: sudo apt install sshpass"
    echo "   Or test manually with: ssh testuser@$HOST -p $PORT"
fi

echo ""
echo "3. Testing Port Scanner Detection (with netcat)"
echo "   These should be logged as reconnaissance/probes..."
for i in {1..3}; do
    echo "   Probe $i: Connecting with netcat (non-SSH client)"
    timeout 1 nc $HOST $PORT < /dev/null 2>&1 | head -1
    sleep 0.5
done

echo ""
echo "4. Testing with nmap (if available)"
if command -v nmap &> /dev/null; then
    echo "   Running nmap service detection..."
    nmap -sV -p $PORT $HOST 2>&1 | grep -E "PORT|ssh|$PORT"
else
    echo "   nmap not installed. Install with: sudo apt install nmap"
fi

echo ""
echo "=========================================="
echo "Check Logs:"
echo "=========================================="
echo "  1. SSH authentication attempts:"
echo "     cat logs/attacks_\$(date +%Y%m%d).json | jq 'select(.protocol == \"SSH\")'"
echo ""
echo "  2. SSH probes/scans:"
echo "     cat logs/attacks_\$(date +%Y%m%d).json | jq 'select(.scan_type == \"ssh_probe\")'"
echo ""
echo "  3. All SSH activity:"
echo "     tail logs/honeypot.log | grep SSH"

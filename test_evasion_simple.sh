#!/bin/bash
# Simple evasion feature testing using common CLI tools

HOST="localhost"

echo "=========================================="
echo "Quick Evasion Feature Tests"
echo "=========================================="
echo ""

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${YELLOW}1. Testing SSH Banner Variation${NC}"
echo "   Connecting to SSH 5 times to check for banner randomization..."
for i in {1..5}; do
    echo -n "   Attempt $i: "
    timeout 2 nc localhost 2222 2>/dev/null | head -1
    sleep 0.5
done
echo ""

echo -e "${YELLOW}2. Testing FTP Banner Variation${NC}"
echo "   Connecting to FTP 5 times to check for banner randomization..."
for i in {1..5}; do
    echo -n "   Attempt $i: "
    timeout 2 nc localhost 2121 2>/dev/null | head -1
    sleep 0.5
done
echo ""

echo -e "${YELLOW}3. Testing HTTP Server Header Variation${NC}"
echo "   Sending HTTP requests to check Server header randomization..."
for i in {1..5}; do
    echo -n "   Attempt $i: "
    echo -e "GET / HTTP/1.1\r\nHost: test\r\n\r\n" | nc localhost 8888 2>/dev/null | grep -i "^Server:" || echo "No Server header"
    sleep 0.5
done
echo ""

echo -e "${YELLOW}4. Testing HTTP Scanner Detection${NC}"
echo "   Testing with suspicious User-Agent strings..."

echo "   A. Normal browser (should NOT be flagged):"
echo -e "GET / HTTP/1.1\r\nHost: test\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n\r\n" | timeout 2 nc localhost 8888 > /dev/null 2>&1
echo "      Request sent. Check logs for result."

echo "   B. python-requests (should be flagged as scanner):"
echo -e "GET / HTTP/1.1\r\nHost: test\r\nUser-Agent: python-requests/2.28.0\r\n\r\n" | timeout 2 nc localhost 8888 > /dev/null 2>&1
echo "      Request sent. Check logs for 'SUSPICIOUS CLIENT' warning."

echo "   C. curl (should be flagged as scanner):"
echo -e "GET / HTTP/1.1\r\nHost: test\r\nUser-Agent: curl/7.68.0\r\n\r\n" | timeout 2 nc localhost 8888 > /dev/null 2>&1
echo "      Request sent. Check logs for 'SUSPICIOUS CLIENT' warning."

echo "   D. Nikto scanner (should be flagged):"
echo -e "GET / HTTP/1.1\r\nHost: test\r\nUser-Agent: Mozilla/5.00 (Nikto/2.1.6)\r\n\r\n" | timeout 2 nc localhost 8888 > /dev/null 2>&1
echo "      Request sent. Check logs for 'SUSPICIOUS CLIENT' warning."

echo "   E. Headless Chrome (should be flagged):"
echo -e "GET / HTTP/1.1\r\nHost: test\r\nUser-Agent: HeadlessChrome/90.0\r\n\r\n" | timeout 2 nc localhost 8888 > /dev/null 2>&1
echo "      Request sent. Check logs for 'SUSPICIOUS CLIENT' warning."

echo "   F. No User-Agent (should be flagged):"
echo -e "GET / HTTP/1.1\r\nHost: test\r\n\r\n" | timeout 2 nc localhost 8888 > /dev/null 2>&1
echo "      Request sent. Check logs for 'SUSPICIOUS CLIENT' warning."

echo ""
echo -e "${YELLOW}5. Testing FTP Authentication Timing${NC}"
echo "   Testing if auth has realistic delays (100-400ms expected)..."
for i in {1..3}; do
    echo "   Attempt $i:"
    (
        sleep 0.1
        echo "USER testuser"
        sleep 0.1
        echo "PASS testpass"
        sleep 0.5
    ) | timeout 5 nc localhost 2121 2>/dev/null | tail -2
done
echo ""

echo -e "${YELLOW}6. Testing MySQL Version Banner Variation${NC}"
echo "   Connecting to MySQL 3 times (checking greeting packet)..."
for i in {1..3}; do
    echo -n "   Attempt $i: "
    # MySQL greeting contains version string - just show we're connecting
    timeout 2 nc localhost 3306 > /dev/null 2>&1 && echo "Connected (check packet for version)" || echo "Failed"
    sleep 0.5
done
echo ""

echo "=========================================="
echo "Test Summary"
echo "=========================================="
echo ""
echo "✓ Banner variation tests completed"
echo "✓ HTTP fingerprinting tests completed"
echo "✓ Timing tests completed"
echo ""
echo -e "${GREEN}Next Steps:${NC}"
echo "  1. Check logs for SUSPICIOUS CLIENT warnings:"
echo "     tail -f logs/honeypot.log | grep SUSPICIOUS"
echo ""
echo "  2. Check attack logs for detection details:"
echo "     tail logs/attacks_*.json | jq '.detection'"
echo ""
echo "  3. Run full Python test suite:"
echo "     python3 test_evasion.py"
echo ""
echo "  4. Test with real scanners (if installed):"
echo "     nmap -sV -p 2222,2121,8080 localhost"
echo "     nikto -host http://localhost:8080"
echo ""

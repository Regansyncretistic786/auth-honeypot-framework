#!/bin/bash
# Security Test - Verify honeypot NEVER grants access

echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║                                                               ║"
echo "║  Honeypot Security Verification Test                         ║"
echo "║                                                               ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""
echo "This test verifies the honeypot NEVER grants access,"
echo "no matter what credentials are used."
echo ""

# Check if honeypot is running
if ! nc -zv localhost 2222 2>&1 | grep -q succeeded; then
    echo "[!] Honeypot not running on port 2222"
    echo "[i] Start it first: python src/main.py"
    exit 1
fi

echo "[✓] Honeypot is running"
echo ""

TOTAL_TESTS=0
PASSED_TESTS=0

test_ssh_auth() {
    local user=$1
    local pass=$2

    echo -n "[TEST] SSH auth $user:$pass ... "

    # Try to authenticate and execute a command
    # If successful, command will execute and return 0
    # If failed, will return non-zero
    timeout 3 sshpass -p "$pass" ssh -o StrictHostKeyChecking=no \
        -o ConnectTimeout=2 \
        "$user@localhost" -p 2222 "echo COMPROMISED" 2>/dev/null

    RESULT=$?

    ((TOTAL_TESTS++))

    if [ $RESULT -ne 0 ]; then
        echo "✓ REJECTED (secure)"
        ((PASSED_TESTS++))
        return 0
    else
        echo "✗ GRANTED ACCESS (SECURITY BREACH!)"
        return 1
    fi
}

test_ftp_auth() {
    local user=$1
    local pass=$2

    echo -n "[TEST] FTP auth $user:$pass ... "

    # Try to login and list files
    RESULT=$(timeout 3 ftp -n localhost 2121 <<EOF 2>/dev/null
user $user
$pass
ls
quit
EOF
)

    ((TOTAL_TESTS++))

    # Check if we got a file listing or other success indicator
    if echo "$RESULT" | grep -q "Login successful\|226\|150\|drwx"; then
        echo "✗ GRANTED ACCESS (SECURITY BREACH!)"
        return 1
    else
        echo "✓ REJECTED (secure)"
        ((PASSED_TESTS++))
        return 0
    fi
}

echo "══════════════════════════════════════════════════════════════"
echo "Testing SSH Honeypot"
echo "══════════════════════════════════════════════════════════════"

# Test common credentials
test_ssh_auth "admin" "admin"
test_ssh_auth "root" "root"
test_ssh_auth "admin" "password"
test_ssh_auth "user" "123456"

# Test "clever" credentials
test_ssh_auth "honeypot" "honeypot"
test_ssh_auth "admin" "correcthorsebatterystaple"
test_ssh_auth "root" "toor"

echo ""
echo "══════════════════════════════════════════════════════════════"
echo "Testing FTP Honeypot"
echo "══════════════════════════════════════════════════════════════"

test_ftp_auth "admin" "admin"
test_ftp_auth "root" "root"
test_ftp_auth "ftp" "ftp"
test_ftp_auth "anonymous" ""

echo ""
echo "══════════════════════════════════════════════════════════════"
echo "Security Test Results"
echo "══════════════════════════════════════════════════════════════"
echo ""
echo "Total Tests:  $TOTAL_TESTS"
echo "Passed:       $PASSED_TESTS (authentication rejected)"
echo "Failed:       $((TOTAL_TESTS - PASSED_TESTS)) (SECURITY BREACH!)"
echo ""

if [ $PASSED_TESTS -eq $TOTAL_TESTS ]; then
    echo "✓✓✓ ALL TESTS PASSED ✓✓✓"
    echo ""
    echo "The honeypot correctly rejected ALL authentication attempts."
    echo "No matter what credentials are used, access is NEVER granted."
    echo "The honeypot is SECURE - it only logs attacks, never grants access."
    echo ""
    exit 0
else
    echo "✗✗✗ SECURITY BREACH DETECTED ✗✗✗"
    echo ""
    echo "WARNING: The honeypot granted access with some credentials!"
    echo "This should NEVER happen. Review the code immediately."
    echo ""
    exit 1
fi

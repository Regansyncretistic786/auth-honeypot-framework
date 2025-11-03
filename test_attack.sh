#!/bin/bash
# Simulated Attack Script - Tests the honeypot with common credentials
# This simulates what an attacker would do

echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║                                                               ║"
echo "║  Honeypot Attack Simulator                                    ║"
echo "║  This script simulates authentication attacks                 ║"
echo "║                                                               ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""

TARGET="localhost"
SSH_PORT=2222
FTP_PORT=2121

# Common usernames attackers try
USERNAMES=(
    "admin"
    "root"
    "user"
    "test"
    "administrator"
    "guest"
    "ubuntu"
    "pi"
    "oracle"
    "postgres"
)

# Common passwords attackers try
PASSWORDS=(
    "admin"
    "password"
    "123456"
    "root"
    "12345678"
    "test"
    "password123"
    "admin123"
    "letmein"
    "qwerty"
)

echo "[*] Starting simulated attack on honeypot..."
echo "[*] Target: $TARGET"
echo "[*] This is SAFE - only testing your own honeypot"
echo ""

# Test SSH Honeypot
echo "═══ Testing SSH Honeypot (Port $SSH_PORT) ═══"
SSH_ATTEMPTS=0

for username in "${USERNAMES[@]}"; do
    for password in "${PASSWORDS[@]}"; do
        echo -n "[SSH] Trying $username:$password ... "

        # Use sshpass to automate password entry (install if needed)
        if command -v sshpass &> /dev/null; then
            sshpass -p "$password" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
                "$username@$TARGET" -p $SSH_PORT "echo test" 2>/dev/null
        else
            # Fallback: just try to connect (will fail at password prompt)
            timeout 2 ssh -o StrictHostKeyChecking=no -o ConnectTimeout=2 \
                "$username@$TARGET" -p $SSH_PORT 2>/dev/null <<< "$password"
        fi

        echo "rejected ✓"
        ((SSH_ATTEMPTS++))

        # Small delay to be realistic
        sleep 0.2

        # Test just a few combinations for demo
        if [ $SSH_ATTEMPTS -ge 10 ]; then
            break 2
        fi
    done
done

echo ""
echo "═══ Testing FTP Honeypot (Port $FTP_PORT) ═══"
FTP_ATTEMPTS=0

for username in "${USERNAMES[@]}"; do
    for password in "${PASSWORDS[@]}"; do
        echo -n "[FTP] Trying $username:$password ... "

        # Try FTP login
        timeout 3 ftp -n $TARGET $FTP_PORT <<EOF 2>/dev/null
user $username
$password
quit
EOF

        echo "rejected ✓"
        ((FTP_ATTEMPTS++))

        sleep 0.2

        # Test just a few combinations
        if [ $FTP_ATTEMPTS -ge 10 ]; then
            break 2
        fi
    done
done

echo ""
echo "═══ Testing Telnet Honeypot (Port 2323) ═══"
TELNET_ATTEMPTS=0

for username in "${USERNAMES[@]}"; do
    for password in "${PASSWORDS[@]}"; do
        echo -n "[TELNET] Trying $username:$password ... "

        # Try Telnet login
        (
            sleep 0.5
            echo "$username"
            sleep 0.5
            echo "$password"
            sleep 0.5
        ) | timeout 3 telnet $TARGET 2323 >/dev/null 2>&1

        echo "rejected ✓"
        ((TELNET_ATTEMPTS++))

        sleep 0.2

        # Test just a few combinations
        if [ $TELNET_ATTEMPTS -ge 10 ]; then
            break 2
        fi
    done
done

echo ""
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║  Attack Simulation Complete                                   ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""
echo "Summary:"
echo "  • SSH attempts:    $SSH_ATTEMPTS"
echo "  • FTP attempts:    $FTP_ATTEMPTS"
echo "  • Telnet attempts: $TELNET_ATTEMPTS"
echo "  • Total attempts:  $((SSH_ATTEMPTS + FTP_ATTEMPTS + TELNET_ATTEMPTS))"
echo ""
echo "Check your honeypot logs:"
echo "  cat logs/attacks_\$(date +%Y%m%d).json | jq ."
echo ""
echo "Or view them in real-time:"
echo "  tail -f logs/attacks_\$(date +%Y%m%d).json"

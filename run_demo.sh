#!/bin/bash
# Complete Demo Script - Run Honeypot and Test It

set -e

cd "$(dirname "$0")"

echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║                                                               ║"
echo "║  Authentication Honeypot - Interactive Demo                  ║"
echo "║                                                               ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""

# Check if venv exists
if [ ! -d "venv" ]; then
    echo "[!] Virtual environment not found. Creating..."
    python3 -m venv venv
fi

# Activate venv
echo "[*] Activating virtual environment..."
source venv/bin/activate

# Install dependencies
echo "[*] Installing dependencies..."
pip install -q -r requirements.txt

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  Setup Complete!"
echo "═══════════════════════════════════════════════════════════════"
echo ""
echo "What would you like to do?"
echo ""
echo "  1) Start the honeypot (run in background)"
echo "  2) Start the honeypot (run in foreground)"
echo "  3) Test the honeypot with simulated attacks"
echo "  4) View attack logs"
echo "  5) Generate intelligence report"
echo "  6) Stop the honeypot"
echo "  0) Exit"
echo ""
read -p "Enter your choice [0-6]: " choice

case $choice in
    1)
        echo ""
        echo "[*] Starting honeypot in background..."
        nohup python src/main.py > honeypot.log 2>&1 &
        HONEYPOT_PID=$!
        echo $HONEYPOT_PID > honeypot.pid
        echo "[✓] Honeypot started with PID: $HONEYPOT_PID"
        echo "[i] Logs: tail -f honeypot.log"
        echo "[i] Stop: kill $HONEYPOT_PID"
        sleep 2
        echo ""
        echo "[*] Testing if honeypot is running..."
        if nc -zv localhost 2222 2>&1 | grep -q succeeded; then
            echo "[✓] SSH honeypot is running on port 2222"
        fi
        if nc -zv localhost 2121 2>&1 | grep -q succeeded; then
            echo "[✓] FTP honeypot is running on port 2121"
        fi
        if nc -zv localhost 2323 2>&1 | grep -q succeeded; then
            echo "[✓] Telnet honeypot is running on port 2323"
        fi
        echo ""
        echo "Run './run_demo.sh' again to test or view logs"
        ;;

    2)
        echo ""
        echo "[*] Starting honeypot in foreground..."
        echo "[i] Press Ctrl+C to stop"
        echo ""
        python src/main.py
        ;;

    3)
        echo ""
        echo "[*] Checking if honeypot is running..."
        if ! nc -zv localhost 2222 2>&1 | grep -q succeeded; then
            echo "[!] Honeypot doesn't appear to be running!"
            echo "[i] Start it first with option 1 or 2"
            exit 1
        fi

        echo "[✓] Honeypot is running"
        echo ""
        echo "[*] Launching simulated attack..."
        echo "[i] This will try common usernames/passwords"
        echo ""

        if [ -f "test_attack.sh" ]; then
            ./test_attack.sh
        else
            echo "[!] test_attack.sh not found"
            echo "[i] Running basic test instead..."

            for user in admin root test; do
                for pass in admin password 123456; do
                    echo "[*] Trying $user:$pass on SSH..."
                    timeout 2 ssh -o StrictHostKeyChecking=no \
                        -o ConnectTimeout=2 \
                        $user@localhost -p 2222 2>/dev/null <<< "$pass" || true
                    sleep 0.5
                done
            done
        fi

        echo ""
        echo "[✓] Attack simulation complete!"
        echo "[i] Check logs with option 4"
        ;;

    4)
        echo ""
        echo "═══════════════════════════════════════════════════════════════"
        echo "  Recent Attack Logs"
        echo "═══════════════════════════════════════════════════════════════"
        echo ""

        LOG_FILE="logs/attacks_$(date +%Y%m%d).json"

        if [ ! -f "$LOG_FILE" ]; then
            echo "[!] No attacks logged yet for today"
            echo "[i] Run option 3 to simulate attacks"
        else
            ATTACK_COUNT=$(wc -l < "$LOG_FILE")
            echo "Total attacks today: $ATTACK_COUNT"
            echo ""

            if command -v jq &> /dev/null; then
                echo "Last 5 attacks:"
                echo ""
                tail -5 "$LOG_FILE" | jq -r '
                    "[\(.timestamp)] \(.protocol) from \(.source_ip) - \(.username):\(.password)"
                '
            else
                echo "Last 5 attacks (install jq for better formatting):"
                echo ""
                tail -5 "$LOG_FILE"
            fi

            echo ""
            echo "Top usernames tried:"
            if command -v jq &> /dev/null; then
                cat "$LOG_FILE" | jq -r '.username' | sort | uniq -c | sort -rn | head -5
            else
                echo "(install jq for analysis)"
            fi

            echo ""
            echo "Full log: cat $LOG_FILE | jq ."
        fi
        ;;

    5)
        echo ""
        echo "[*] Generating threat intelligence report..."

        python3 << 'EOF'
from src.core.analyzer import AttackAnalyzer
from src.core.reporter import Reporter
import yaml
import sys

try:
    with open('config.yaml') as f:
        config = yaml.safe_load(f)

    analyzer = AttackAnalyzer('logs')
    analysis = analyzer.analyze(days=1)

    print("\n" + "="*70)
    print(analyzer.get_summary(analysis))
    print("="*70 + "\n")

    reporter = Reporter(config)
    reporter.generate_report(days=1, formats=['json', 'html', 'text'])

    print("\n[✓] Reports generated in reports/ directory")
    print("[i] View HTML report: xdg-open reports/report_*.html")
except Exception as e:
    print(f"[!] Error generating report: {e}")
    sys.exit(1)
EOF
        ;;

    6)
        echo ""
        echo "[*] Stopping honeypot..."

        if [ -f "honeypot.pid" ]; then
            PID=$(cat honeypot.pid)
            if kill $PID 2>/dev/null; then
                echo "[✓] Honeypot stopped (PID: $PID)"
                rm honeypot.pid
            else
                echo "[!] Process $PID not found (may have already stopped)"
                rm honeypot.pid
            fi
        else
            echo "[!] No honeypot.pid file found"
            echo "[i] Searching for honeypot processes..."
            pkill -f "python.*main.py" && echo "[✓] Honeypot stopped" || echo "[!] No running honeypot found"
        fi
        ;;

    0)
        echo ""
        echo "Goodbye!"
        ;;

    *)
        echo ""
        echo "[!] Invalid choice"
        ;;
esac

echo ""

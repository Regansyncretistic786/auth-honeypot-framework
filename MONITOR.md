# Honeypot Live Monitor

Real-time dashboard for monitoring honeypot activity.

## Features

- 🎯 **Live Statistics** - Total attacks, protocol breakdown with visual bars
- 📊 **Top Lists** - Most common usernames, passwords, and source IPs
- 🔴 **Status Indicator** - Shows if honeypot is running or stopped
- 📝 **Recent Activity** - Last 10 attacks in table format
- 🎨 **Beautiful UI** - Cyan-themed terminal dashboard
- ⚡ **Auto-refresh** - Updates every 2 seconds

## Usage

### Start the Monitor

```bash
cd ~/scripts/auth-honeypot-framework
source venv/bin/activate
python monitor.py
```

Or run directly:
```bash
./monitor.py
```

### Three-Terminal Setup (Recommended)

**Terminal 1:** Run Honeypot
```bash
python src/main.py
```

**Terminal 2:** Monitor Dashboard
```bash
./monitor.py
```

**Terminal 3:** Run Attacks
```bash
./test_protocols.py
```

## Dashboard Layout

```
╔════════════════════════════════════════════════════════════════════════════╗
║                                                                            ║
║              Authentication Honeypot - Live Monitor                        ║
║                                                                            ║
║                        2025-11-02 14:30:45                                 ║
║                                                                            ║
╚════════════════════════════════════════════════════════════════════════════╝

┌─ Honeypot Status ─────────────────────────────────────────────────────────┐
│  Status: ● RUNNING                                                         │
└───────────────────────────────────────────────────────────────────────────┘

┌─ Attack Summary (Today) ──────────────────────────────────────────────────┐
│  Total Attacks: 156                                                        │
│                                                                            │
│  By Protocol:                                                              │
│    SSH      ████████████████████████████████████████   89 ( 57.1%)        │
│    FTP      █████████████████████                      45 ( 28.8%)        │
│    TELNET   ██████████                                 22 ( 14.1%)        │
└───────────────────────────────────────────────────────────────────────────┘

┌─ Top 5 Usernames ─────────────────────────────────────────────────────────┐
│  1. admin                                                   45             │
│  2. root                                                    32             │
│  3. user                                                    18             │
│  4. test                                                    12             │
│  5. administrator                                            8             │
└───────────────────────────────────────────────────────────────────────────┘

┌─ Top 5 Passwords ─────────────────────────────────────────────────────────┐
│  1. admin                                                   23             │
│  2. password                                                19             │
│  3. 123456                                                  15             │
│  4. admin123                                                12             │
│  5. root                                                    10             │
└───────────────────────────────────────────────────────────────────────────┘

┌─ Top 5 Source IPs ────────────────────────────────────────────────────────┐
│  1. 192.168.1.50                                            89             │
│  2. 10.0.0.25                                               45             │
│  3. 127.0.0.1                                               22             │
└───────────────────────────────────────────────────────────────────────────┘

┌─ Recent Attacks (Last 10) ────────────────────────────────────────────────┐
│  Time     Proto  Source IP       Username        Password                 │
│  ──────────────────────────────────────────────────────────────────────── │
│  14:30:42 SSH    192.168.1.50    admin           password123              │
│  14:30:39 FTP    192.168.1.50    ftp             ftp                      │
│  14:30:36 SSH    10.0.0.25       root            toor                     │
│  14:30:33 TELNET 127.0.0.1       user            test123                  │
│  14:30:30 SSH    192.168.1.50    admin           admin                    │
└───────────────────────────────────────────────────────────────────────────┘

──────────────────────────────────────────────────────────────────────────────
  Press Ctrl+C to exit  •  Refreshes every 2 seconds
```

## What You'll See

### Status Indicators

- **● RUNNING** (Green) - Honeypot is active
- **● STOPPED** (Red) - Honeypot is not running

### Statistics

- **Total Attacks** - Count of all authentication attempts today
- **Protocol Breakdown** - Visual bars showing SSH/FTP/Telnet distribution
- **Top 5 Lists** - Most attempted usernames, passwords, and attacking IPs
- **Recent Attacks** - Live feed of the last 10 attempts

### Real-Time Updates

The dashboard refreshes every 2 seconds, showing:
- New attacks as they happen
- Updated statistics
- Current honeypot status

## Keyboard Controls

- **Ctrl+C** - Exit monitor
- Monitor runs until manually stopped

## Tips

### Long-Running Monitor

For a permanent dashboard, use `tmux` or `screen`:

```bash
# Start tmux session
tmux new -s honeypot-monitor

# Run monitor
./monitor.py

# Detach: Ctrl+b then d
# Reattach: tmux attach -t honeypot-monitor
```

### Custom Refresh Rate

Edit `monitor.py` line 323:
```python
time.sleep(2)  # Change to 1, 5, 10, etc. (seconds)
```

### Monitor Remote Honeypot

```bash
# SSH to honeypot server
ssh user@honeypot-server

# Run monitor
cd /path/to/honeypot
./monitor.py
```

## Troubleshooting

**"logs directory not found"**
```bash
# Make sure you're in the honeypot root directory
cd ~/scripts/auth-honeypot-framework
./monitor.py
```

**Monitor shows "● STOPPED" but honeypot is running**
```bash
# The monitor looks for 'python.*main.py' process
# If you renamed main.py, update line 44 in monitor.py
```

**No attacks showing**
```bash
# Check if log file exists
ls -la logs/attacks_*.json

# Run test attacks
./test_protocols.py
```

**Unicode/color issues**
```bash
# Make sure colorama is installed
pip install colorama

# Your terminal supports UTF-8
export LANG=en_US.UTF-8
```

## Integration with Other Tools

### Export Dashboard Data

Monitor data is read from `logs/attacks_YYYYMMDD.json`, so you can:

- Parse logs with other tools
- Feed into SIEM systems
- Create custom dashboards
- Generate reports

### Alerting

Add webhook notifications by editing the `render_dashboard()` function to check thresholds:

```python
if stats['total'] > 100:
    send_alert("High attack volume detected!")
```

## Advanced Usage

### Filter by Protocol

Modify `load_attacks()` to filter:
```python
attacks = [a for a in attacks if a.get('protocol') == 'SSH']
```

### Show Hourly Activity Graph

The stats already track hourly data in `stats['hourly']`. You can display it as a graph in the dashboard.

### Multiple Honeypots

Monitor multiple honeypots by pointing to different log directories:
```bash
./monitor.py --log-dir /path/to/honeypot1/logs
```

## Performance

- **CPU Usage**: ~1-2% (refresh every 2 seconds)
- **Memory**: ~20-30 MB
- **Disk I/O**: Minimal (reads log file every 2 seconds)

Safe to run 24/7 on production honeypots.

---

**Enjoy your beautiful honeypot dashboard!** 🍯🐝

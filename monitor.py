#!/usr/bin/env python3
"""
Honeypot Monitoring Dashboard
Real-time display of honeypot activity and statistics
"""
import json
import time
import os
import sys
from datetime import datetime
from pathlib import Path
from collections import Counter, defaultdict
from colorama import init, Fore, Style, Back

# Initialize colorama
init(autoreset=True)

class HoneypotMonitor:
    """Real-time honeypot monitoring dashboard"""

    def __init__(self, log_dir='logs'):
        self.log_dir = Path(log_dir)
        self.running = True

    def clear_screen(self):
        """Clear the terminal screen"""
        os.system('clear' if os.name != 'nt' else 'cls')

    def get_today_log_file(self):
        """Get today's attack log file"""
        today = datetime.now().strftime('%Y%m%d')
        return self.log_dir / f"attacks_{today}.json"

    def load_attacks(self):
        """Load all attacks from today's log"""
        log_file = self.get_today_log_file()
        attacks = []

        if not log_file.exists():
            return attacks

        try:
            with open(log_file, 'r') as f:
                for line in f:
                    try:
                        attack = json.loads(line.strip())
                        attacks.append(attack)
                    except json.JSONDecodeError:
                        continue
        except Exception:
            pass

        return attacks

    def check_honeypot_status(self):
        """Check if honeypot is running"""
        try:
            import subprocess
            result = subprocess.run(
                ['pgrep', '-f', 'python.*main.py'],
                capture_output=True,
                text=True
            )
            return result.returncode == 0
        except Exception:
            return False

    def get_stats(self, attacks):
        """Calculate statistics from attacks"""
        if not attacks:
            return {
                'total': 0,
                'by_protocol': {},
                'top_usernames': [],
                'top_passwords': [],
                'top_sources': [],
                'recent': []
            }

        # Count by protocol
        by_protocol = Counter(a.get('protocol', 'unknown') for a in attacks)

        # Top usernames
        usernames = [a.get('username', '') for a in attacks if a.get('username')]
        top_usernames = Counter(usernames).most_common(5)

        # Top passwords
        passwords = [a.get('password', '') for a in attacks if a.get('password')]
        top_passwords = Counter(passwords).most_common(5)

        # Top source IPs
        sources = [a.get('source_ip', '') for a in attacks if a.get('source_ip')]
        top_sources = Counter(sources).most_common(5)

        # Recent attacks (last 10)
        recent = attacks[-10:] if len(attacks) >= 10 else attacks

        # Attacks per hour
        hourly = defaultdict(int)
        for attack in attacks:
            try:
                timestamp = attack.get('timestamp', '')
                hour = timestamp[11:13] if len(timestamp) >= 13 else 'unknown'
                hourly[hour] += 1
            except Exception:
                pass

        return {
            'total': len(attacks),
            'by_protocol': dict(by_protocol),
            'top_usernames': top_usernames,
            'top_passwords': top_passwords,
            'top_sources': top_sources,
            'recent': recent,
            'hourly': dict(sorted(hourly.items()))
        }

    def print_header(self):
        """Print dashboard header"""
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        print(f"{Fore.CYAN}╔{'═'*76}╗{Style.RESET_ALL}")
        print(f"{Fore.CYAN}║{' '*76}║{Style.RESET_ALL}")
        print(f"{Fore.CYAN}║{Fore.YELLOW}{'Authentication Honeypot - Live Monitor'.center(76)}{Fore.CYAN}║{Style.RESET_ALL}")
        print(f"{Fore.CYAN}║{' '*76}║{Style.RESET_ALL}")
        print(f"{Fore.CYAN}║{Fore.WHITE}  {now.center(72)}  {Fore.CYAN}║{Style.RESET_ALL}")
        print(f"{Fore.CYAN}║{' '*76}║{Style.RESET_ALL}")
        print(f"{Fore.CYAN}╚{'═'*76}╝{Style.RESET_ALL}")
        print()

    def print_status(self, is_running):
        """Print honeypot status"""
        if is_running:
            status = f"{Fore.GREEN}● RUNNING{Style.RESET_ALL}"
        else:
            status = f"{Fore.RED}● STOPPED{Style.RESET_ALL}"

        print(f"{Fore.CYAN}┌─ Honeypot Status ─────────────────────────────────────────────────────────┐{Style.RESET_ALL}")
        print(f"{Fore.CYAN}│{Style.RESET_ALL}  Status: {status}                                                              {Fore.CYAN}│{Style.RESET_ALL}")
        print(f"{Fore.CYAN}└───────────────────────────────────────────────────────────────────────────┘{Style.RESET_ALL}")
        print()

    def print_summary(self, stats):
        """Print attack summary"""
        total = stats['total']
        protocols = stats['by_protocol']

        print(f"{Fore.CYAN}┌─ Attack Summary (Today) ──────────────────────────────────────────────────┐{Style.RESET_ALL}")
        print(f"{Fore.CYAN}│{Style.RESET_ALL}  Total Attacks: {Fore.YELLOW}{total}{Style.RESET_ALL}".ljust(87) + f"{Fore.CYAN}│{Style.RESET_ALL}")
        print(f"{Fore.CYAN}│{Style.RESET_ALL}                                                                          {Fore.CYAN}│{Style.RESET_ALL}")

        if protocols:
            print(f"{Fore.CYAN}│{Style.RESET_ALL}  {Fore.WHITE}By Protocol:{Style.RESET_ALL}".ljust(87) + f"{Fore.CYAN}│{Style.RESET_ALL}")
            for proto, count in sorted(protocols.items(), key=lambda x: x[1], reverse=True):
                bar_length = min(40, int((count / total) * 40)) if total > 0 else 0
                bar = '█' * bar_length
                percentage = (count / total * 100) if total > 0 else 0
                print(f"{Fore.CYAN}│{Style.RESET_ALL}    {proto:8s} {Fore.GREEN}{bar:40s}{Style.RESET_ALL} {count:4d} ({percentage:5.1f}%)      {Fore.CYAN}│{Style.RESET_ALL}")
        else:
            print(f"{Fore.CYAN}│{Style.RESET_ALL}  {Fore.YELLOW}No attacks recorded yet{Style.RESET_ALL}".ljust(87) + f"{Fore.CYAN}│{Style.RESET_ALL}")

        print(f"{Fore.CYAN}└───────────────────────────────────────────────────────────────────────────┘{Style.RESET_ALL}")
        print()

    def print_top_items(self, title, items, show_count=True):
        """Print top items table"""
        print(f"{Fore.CYAN}┌─ {title} ─────────────────────────────────────────────────────────────┐{Style.RESET_ALL}")

        if not items:
            print(f"{Fore.CYAN}│{Style.RESET_ALL}  {Fore.YELLOW}No data yet{Style.RESET_ALL}".ljust(87) + f"{Fore.CYAN}│{Style.RESET_ALL}")
        else:
            for i, (item, count) in enumerate(items, 1):
                item_display = item if item else '(empty)'
                if len(item_display) > 50:
                    item_display = item_display[:47] + '...'

                if show_count:
                    line = f"  {Fore.YELLOW}{i}.{Style.RESET_ALL} {item_display:50s} {Fore.GREEN}{count:4d}{Style.RESET_ALL}"
                else:
                    line = f"  {Fore.YELLOW}{i}.{Style.RESET_ALL} {item_display}"

                print(f"{Fore.CYAN}│{Style.RESET_ALL}{line}".ljust(87) + f"{Fore.CYAN}│{Style.RESET_ALL}")

        print(f"{Fore.CYAN}└───────────────────────────────────────────────────────────────────────────┘{Style.RESET_ALL}")
        print()

    def print_recent_attacks(self, recent):
        """Print recent attacks table"""
        print(f"{Fore.CYAN}┌─ Recent Attacks (Last 10) ────────────────────────────────────────────────┐{Style.RESET_ALL}")

        if not recent:
            print(f"{Fore.CYAN}│{Style.RESET_ALL}  {Fore.YELLOW}No attacks yet{Style.RESET_ALL}".ljust(87) + f"{Fore.CYAN}│{Style.RESET_ALL}")
        else:
            # Header
            header = f"  {'Time':<8} {'Proto':<6} {'Source IP':<15} {'Username':<15} {'Password':<15}"
            print(f"{Fore.CYAN}│{Style.RESET_ALL}{Fore.WHITE}{header}{Style.RESET_ALL}".ljust(87) + f"{Fore.CYAN}│{Style.RESET_ALL}")
            print(f"{Fore.CYAN}│{Style.RESET_ALL}  {Fore.CYAN}{'─'*74}{Style.RESET_ALL}".ljust(87) + f"{Fore.CYAN}│{Style.RESET_ALL}")

            for attack in reversed(recent):
                try:
                    timestamp = attack.get('timestamp', '')
                    time_str = timestamp[11:19] if len(timestamp) >= 19 else 'unknown'

                    protocol = attack.get('protocol', '?')[:6]
                    source = attack.get('source_ip', '?')[:15]
                    username = attack.get('username', '')[:15]
                    password = attack.get('password', '')[:15]

                    if not username:
                        username = '(empty)'
                    if not password:
                        password = '(empty)'

                    line = f"  {time_str:<8} {protocol:<6} {source:<15} {username:<15} {password:<15}"
                    print(f"{Fore.CYAN}│{Style.RESET_ALL}  {line}".ljust(87) + f"{Fore.CYAN}│{Style.RESET_ALL}")
                except Exception:
                    continue

        print(f"{Fore.CYAN}└───────────────────────────────────────────────────────────────────────────┘{Style.RESET_ALL}")
        print()

    def print_footer(self):
        """Print dashboard footer"""
        print(f"{Fore.CYAN}{'─'*78}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}  Press Ctrl+C to exit  •  Refreshes every 2 seconds{Style.RESET_ALL}")
        print()

    def render_dashboard(self):
        """Render the complete dashboard"""
        self.clear_screen()

        # Load data
        attacks = self.load_attacks()
        stats = self.get_stats(attacks)
        is_running = self.check_honeypot_status()

        # Print dashboard
        self.print_header()
        self.print_status(is_running)
        self.print_summary(stats)

        # Print statistics in two columns
        if stats['total'] > 0:
            self.print_top_items("Top 5 Usernames", stats['top_usernames'])
            self.print_top_items("Top 5 Passwords", stats['top_passwords'])
            self.print_top_items("Top 5 Source IPs", stats['top_sources'])

        # Recent attacks
        self.print_recent_attacks(stats['recent'])

        # Footer
        self.print_footer()

    def run(self):
        """Run the monitoring dashboard"""
        print(f"{Fore.GREEN}Starting Honeypot Monitor...{Style.RESET_ALL}")
        time.sleep(1)

        try:
            while self.running:
                self.render_dashboard()
                time.sleep(2)  # Refresh every 2 seconds

        except KeyboardInterrupt:
            self.clear_screen()
            print(f"\n{Fore.YELLOW}Monitor stopped.{Style.RESET_ALL}\n")
            sys.exit(0)


def main():
    """Main entry point"""
    # Check if logs directory exists
    if not Path('logs').exists():
        print(f"{Fore.RED}Error: 'logs' directory not found!{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Run this script from the honeypot root directory.{Style.RESET_ALL}")
        sys.exit(1)

    monitor = HoneypotMonitor()
    monitor.run()


if __name__ == '__main__':
    main()

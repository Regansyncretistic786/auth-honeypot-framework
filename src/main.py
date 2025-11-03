#!/usr/bin/env python3
"""
Authentication Honeypot Framework
Main entry point with CLI interface
"""
import argparse
import sys
import yaml
import signal
import threading
from pathlib import Path
from colorama import init, Fore, Style

# Initialize colorama
init(autoreset=True)

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.core.logger import HoneypotLogger
from src.protocols.ssh import SSHHoneypot
from src.protocols.ftp import FTPHoneypot
from src.protocols.telnet import TelnetHoneypot
from src.protocols.http import HTTPHoneypot
from src.protocols.rdp import RDPHoneypot
from src.protocols.smb import SMBHoneypot
from src.protocols.mysql import MySQLHoneypot


def print_banner():
    """Print ASCII banner"""
    banner = f"""
{Fore.CYAN}╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   {Fore.YELLOW}Authentication Honeypot Framework{Fore.CYAN}                         ║
║                                                               ║
║   {Fore.GREEN}Detect. Analyze. Defend.{Fore.CYAN}                                  ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}

{Fore.RED}⚠ FOR DEFENSIVE SECURITY USE ONLY ⚠{Style.RESET_ALL}

This tool is designed for authorized security research and
threat intelligence gathering on networks you own or manage.

{Fore.YELLOW}Purpose:{Style.RESET_ALL}
  • Detect authentication attacks in real-time
  • Capture attacker tools, techniques, and credentials
  • Generate threat intelligence for defense improvement
  • Research emerging attack patterns

"""
    print(banner)


def load_config(config_path: str) -> dict:
    """Load configuration from YAML file"""
    try:
        with open(config_path, 'r') as f:
            return yaml.safe_load(f)
    except FileNotFoundError:
        print(f"{Fore.RED}Error: Config file not found: {config_path}{Style.RESET_ALL}")
        sys.exit(1)
    except yaml.YAMLError as e:
        print(f"{Fore.RED}Error parsing config file: {e}{Style.RESET_ALL}")
        sys.exit(1)


def print_status(config: dict, logger):
    """Print startup status"""
    print(f"\n{Fore.GREEN}Starting Honeypot Services...{Style.RESET_ALL}\n")

    protocols = config.get('protocols', {})
    enabled_services = []

    for protocol_name, protocol_config in protocols.items():
        if protocol_config.get('enabled', False):
            port = protocol_config.get('port', 'N/A')
            enabled_services.append((protocol_name.upper(), port))

    if enabled_services:
        print(f"{Fore.CYAN}Enabled Services:{Style.RESET_ALL}")
        for name, port in enabled_services:
            print(f"  • {Fore.YELLOW}{name:<10}{Style.RESET_ALL} on port {Fore.GREEN}{port}{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}Warning: No services enabled in configuration{Style.RESET_ALL}")

    log_dir = Path(config.get('logging', {}).get('log_dir', 'logs'))
    report_dir = Path(config.get('reporting', {}).get('report_dir', 'reports'))

    print(f"\n{Fore.CYAN}Configuration:{Style.RESET_ALL}")
    print(f"  • Log directory:    {Fore.GREEN}{log_dir}{Style.RESET_ALL}")
    print(f"  • Report directory: {Fore.GREEN}{report_dir}{Style.RESET_ALL}")

    rate_limiting = config.get('rate_limiting', {})
    if rate_limiting.get('enabled', True):
        max_conns = rate_limiting.get('max_connections_per_ip', 50)
        print(f"  • Rate limiting:    {Fore.GREEN}Enabled{Style.RESET_ALL} (max {max_conns} conn/IP)")
    else:
        print(f"  • Rate limiting:    {Fore.RED}Disabled{Style.RESET_ALL}")

    print(f"\n{Fore.YELLOW}Press Ctrl+C to stop...{Style.RESET_ALL}\n")


class HoneypotManager:
    """Manage multiple honeypot services"""

    def __init__(self, config: dict):
        self.config = config
        self.logger = HoneypotLogger(config)
        self.honeypots = []
        self.threads = []
        self.running = False

    def start(self):
        """Start all enabled honeypot services"""
        protocols = self.config.get('protocols', {})

        # Create honeypot instances
        if protocols.get('ssh', {}).get('enabled', False):
            self.honeypots.append(SSHHoneypot(self.config, self.logger))

        if protocols.get('ftp', {}).get('enabled', False):
            self.honeypots.append(FTPHoneypot(self.config, self.logger))

        if protocols.get('telnet', {}).get('enabled', False):
            self.honeypots.append(TelnetHoneypot(self.config, self.logger))

        if protocols.get('http', {}).get('enabled', False):
            self.honeypots.append(HTTPHoneypot(self.config, self.logger))

        if protocols.get('rdp', {}).get('enabled', False):
            self.honeypots.append(RDPHoneypot(self.config, self.logger))

        if protocols.get('smb', {}).get('enabled', False):
            self.honeypots.append(SMBHoneypot(self.config, self.logger))

        if protocols.get('mysql', {}).get('enabled', False):
            self.honeypots.append(MySQLHoneypot(self.config, self.logger))

        if not self.honeypots:
            self.logger.error("No honeypots enabled. Check configuration.")
            return

        # Start each honeypot in its own thread
        self.running = True
        for honeypot in self.honeypots:
            thread = threading.Thread(target=honeypot.start, daemon=True)
            thread.start()
            self.threads.append(thread)

        self.logger.info(f"Started {len(self.honeypots)} honeypot service(s)")

    def stop(self):
        """Stop all honeypot services"""
        self.running = False
        self.logger.info("Shutting down honeypots...")

        for honeypot in self.honeypots:
            honeypot.stop()

        self.logger.info("All honeypots stopped")

    def wait(self):
        """Wait for honeypots to finish"""
        try:
            while self.running:
                # Check if any threads died unexpectedly (only while running)
                if self.running:  # Double-check we're still running
                    for thread in self.threads:
                        if not thread.is_alive():
                            # Only log if we're still supposed to be running
                            if self.running:
                                self.logger.error("A honeypot thread died unexpectedly")
                                # Remove dead thread to avoid repeated logging
                                self.threads.remove(thread)

                # Sleep a bit
                import time
                time.sleep(1)
        except KeyboardInterrupt:
            pass


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Authentication Honeypot Framework - Defensive Security Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument(
        '-c', '--config',
        default='config.yaml',
        help='Path to configuration file (default: config.yaml)'
    )

    parser.add_argument(
        '--no-banner',
        action='store_true',
        help='Suppress banner display'
    )

    parser.add_argument(
        '-v', '--version',
        action='version',
        version='Authentication Honeypot Framework v1.0.0'
    )

    args = parser.parse_args()

    # Print banner
    if not args.no_banner:
        print_banner()

    # Load configuration
    config = load_config(args.config)

    # Create manager
    manager = HoneypotManager(config)

    # Print status
    print_status(config, manager.logger)

    # Setup signal handler
    def signal_handler(sig, frame):
        print(f"\n\n{Fore.YELLOW}Received shutdown signal...{Style.RESET_ALL}")
        manager.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Start honeypots
    try:
        manager.start()
        manager.wait()
    except Exception as e:
        manager.logger.error(f"Fatal error: {e}")
        manager.stop()
        sys.exit(1)


if __name__ == '__main__':
    main()

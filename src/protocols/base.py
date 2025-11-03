"""
Base class for all protocol honeypots
"""
import socket
import threading
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
from datetime import datetime
from src.core.evasion import EvasionEngine


class BaseHoneypot(ABC):
    """Base class for protocol-specific honeypots"""

    def __init__(self, config: Dict[str, Any], logger):
        self.config = config
        self.logger = logger
        self.protocol_name = self.__class__.__name__.replace('Honeypot', '').upper()
        self.running = False
        self.server_socket: Optional[socket.socket] = None
        self.threads = []

        # Rate limiting tracking
        self.connection_counts = {}  # IP -> (count, first_seen)
        self.blocked_ips = set()

        # Evasion engine
        self.evasion = EvasionEngine()

        # Track attempt counts per IP for behavioral variation
        self.attempt_counts = {}  # IP -> count

    @abstractmethod
    def get_port(self) -> int:
        """Return the port this honeypot listens on"""
        pass

    @abstractmethod
    def handle_client(self, client_socket: socket.socket, address: tuple):
        """Handle an individual client connection"""
        pass

    def start(self):
        """Start the honeypot server"""
        port = self.get_port()
        bind_address = self.config.get('server', {}).get('bind_address', '0.0.0.0')

        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((bind_address, port))
            self.server_socket.listen(5)

            self.running = True
            self.logger.info(
                f"{self.protocol_name} honeypot started on {bind_address}:{port}"
            )

            # Accept connections in a loop
            while self.running:
                try:
                    self.server_socket.settimeout(1.0)
                    client_socket, address = self.server_socket.accept()

                    # Check rate limiting
                    if self._should_block(address[0]):
                        self.logger.warning(
                            f"Blocked {address[0]} due to rate limiting"
                        )
                        client_socket.close()
                        continue

                    # Log connection
                    self.logger.log_connection(
                        self.protocol_name,
                        address[0],
                        address[1]
                    )

                    # Handle in new thread
                    thread = threading.Thread(
                        target=self._handle_client_wrapper,
                        args=(client_socket, address),
                        daemon=True
                    )
                    thread.start()
                    self.threads.append(thread)

                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:
                        self.logger.error(f"Error accepting connection: {e}")

        except Exception as e:
            self.logger.error(f"Failed to start {self.protocol_name} honeypot: {e}")
        finally:
            self.stop()

    def stop(self):
        """Stop the honeypot server"""
        self.running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
        self.logger.info(f"{self.protocol_name} honeypot stopped")

    def _handle_client_wrapper(self, client_socket: socket.socket, address: tuple):
        """Wrapper to handle exceptions in client threads"""
        try:
            self.handle_client(client_socket, address)
        except Exception as e:
            self.logger.error(
                f"Error handling {self.protocol_name} client {address[0]}: {e}"
            )
        finally:
            try:
                client_socket.close()
            except:
                pass

    def _should_block(self, ip: str) -> bool:
        """Check if an IP should be blocked based on rate limiting"""
        if not self.config.get('rate_limiting', {}).get('enabled', True):
            return False

        if ip in self.blocked_ips:
            return True

        rate_config = self.config.get('rate_limiting', {})
        max_conns = rate_config.get('max_connections_per_ip', 50)
        time_window = rate_config.get('time_window_seconds', 300)
        auto_block = rate_config.get('auto_block_threshold', 100)

        now = datetime.now()

        # Update connection count
        if ip in self.connection_counts:
            count, first_seen = self.connection_counts[ip]
            elapsed = (now - first_seen).total_seconds()

            if elapsed > time_window:
                # Reset counter
                self.connection_counts[ip] = (1, now)
                return False

            # Increment counter
            count += 1
            self.connection_counts[ip] = (count, first_seen)

            # Check if should block
            if count >= auto_block:
                self.blocked_ips.add(ip)
                self.logger.warning(f"Auto-blocked {ip} after {count} connections")
                return True

            if count >= max_conns:
                return True

        else:
            self.connection_counts[ip] = (1, now)

        return False

    def log_auth_attempt(self, source_ip: str, username: str, password: str, success: bool = False, metadata: Optional[Dict[str, Any]] = None):
        """Log an authentication attempt"""
        event_data = {
            'protocol': self.protocol_name,
            'source_ip': source_ip,
            'username': username,
            'success': success,
            'event_type': 'auth_attempt'
        }

        # Only log password if configured
        if self.config.get('logging', {}).get('capture_passwords', True):
            event_data['password'] = password

        # Add optional metadata (for HTTP: user-agent, referer, etc.)
        if metadata:
            event_data.update(metadata)

        self.logger.log_attack(event_data)

"""
Telnet Honeypot implementation
"""
import socket
from typing import Dict, Any
from .base import BaseHoneypot


class TelnetHoneypot(BaseHoneypot):
    """Telnet protocol honeypot"""

    def get_port(self) -> int:
        """Get Telnet port from config"""
        port = self.config.get('protocols', {}).get('telnet', {}).get('port')
        if port is None:
            raise ValueError("Telnet port not configured in config.yaml")
        return port

    def handle_client(self, client_socket: socket.socket, address: tuple):
        """Handle Telnet client connection"""
        client_ip = address[0]

        try:
            # Set socket timeout to prevent hanging
            client_socket.settimeout(30)

            # Add realistic connection delay
            self.evasion.add_realistic_delay('connection')

            # Send welcome banner - use configured or generic banner
            banner = self.config.get('protocols', {}).get('telnet', {}).get(
                'banner', 'Welcome to Telnet Server'
            )
            client_socket.send(f"{banner}\r\n".encode())

            # Prompt for login
            client_socket.send(b"login: ")

            # Read username
            username_data = b""
            while True:
                try:
                    char = client_socket.recv(1)
                    if not char or char == b'\n' or char == b'\r':
                        break
                    if char.isalnum() or char in b'.-_@':
                        username_data += char
                        client_socket.send(char)  # Echo back
                except socket.timeout:
                    return

            username = username_data.decode('utf-8', errors='ignore').strip()

            if not username:
                return

            # Prompt for password
            client_socket.send(b"\r\nPassword: ")

            # Read password (no echo)
            password_data = b""
            while True:
                try:
                    char = client_socket.recv(1)
                    if not char or char == b'\n' or char == b'\r':
                        break
                    password_data += char
                    # Don't echo password
                except socket.timeout:
                    return

            password = password_data.decode('utf-8', errors='ignore').strip()

            # Add realistic delay before authentication check
            self.evasion.add_realistic_delay('auth_check')

            # Log the authentication attempt
            self.log_auth_attempt(client_ip, username, password)

            # Always reject
            client_socket.send(b"\r\nLogin incorrect\r\n")

        except socket.timeout:
            self.logger.debug(f"Telnet timeout from {client_ip}")
            # Log timeout as probe/scan
            self.log_auth_attempt(
                client_ip,
                "Unknown",
                "[Telnet probe/timeout]",
                success=False,
                metadata={
                    'scan_type': 'telnet_probe',
                    'error': 'timeout',
                    'description': 'Client connected but did not complete login sequence'
                }
            )
        except Exception as e:
            self.logger.debug(f"Telnet connection error from {client_ip}: {e}")
            # Log unexpected errors
            self.log_auth_attempt(
                client_ip,
                "Unknown",
                "[Telnet connection error]",
                success=False,
                metadata={
                    'scan_type': 'telnet_error',
                    'error': str(e),
                    'description': 'Telnet connection attempt with error'
                }
            )
        finally:
            try:
                client_socket.close()
            except:
                pass

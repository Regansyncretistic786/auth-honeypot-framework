"""
SSH Honeypot implementation
"""
import socket
import paramiko
import threading
from io import StringIO
from typing import Dict, Any
from .base import BaseHoneypot


class SSHServer(paramiko.ServerInterface):
    """SSH server interface for honeypot"""

    def __init__(self, honeypot, client_ip: str):
        self.honeypot = honeypot
        self.client_ip = client_ip
        self.event = threading.Event()
        self.username = None
        self.password = None

    def check_auth_password(self, username: str, password: str) -> int:
        """Handle password authentication - always reject but log"""
        self.username = username
        self.password = password

        # Add realistic delay before authentication check
        self.honeypot.evasion.add_realistic_delay('auth_check')

        # Log the attempt
        self.honeypot.log_auth_attempt(
            self.client_ip,
            username,
            password,
            success=False
        )

        # Always reject
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username: str, key) -> int:
        """Reject public key auth"""
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username: str) -> str:
        """Advertise password auth"""
        return 'password'

    def check_channel_request(self, kind: str, chanid: int) -> int:
        """Allow session channel requests"""
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED


class SSHHoneypot(BaseHoneypot):
    """SSH protocol honeypot"""

    def __init__(self, config: Dict[str, Any], logger):
        super().__init__(config, logger)
        self.host_key = self._generate_host_key()

    def _generate_host_key(self) -> paramiko.RSAKey:
        """Generate RSA host key"""
        key_file = StringIO()
        key = paramiko.RSAKey.generate(2048)
        key.write_private_key(key_file)
        key_file.seek(0)
        return paramiko.RSAKey.from_private_key(key_file)

    def get_port(self) -> int:
        """Get SSH port from config"""
        port = self.config.get('protocols', {}).get('ssh', {}).get('port')
        if port is None:
            raise ValueError("SSH port not configured in config.yaml")
        return port

    def handle_client(self, client_socket: socket.socket, address: tuple):
        """Handle SSH client connection"""
        client_ip = address[0]
        transport = None
        negotiation_failed = False

        try:
            # Setup SSH transport
            transport = paramiko.Transport(client_socket)
            transport.add_server_key(self.host_key)

            # Set server version/banner - use realistic random banner
            config_banner = self.config.get('protocols', {}).get('ssh', {}).get('banner')
            if config_banner:
                banner = config_banner
            else:
                # Use evasion engine to get realistic random banner
                banner = self.evasion.get_random_banner('ssh')
            transport.local_version = banner

            # Add realistic connection delay
            self.evasion.add_realistic_delay('connection')

            # Create server interface
            server = SSHServer(self, client_ip)

            try:
                transport.start_server(server=server)
            except paramiko.SSHException as e:
                self.logger.debug(f"SSH negotiation failed from {client_ip}: {e}")
                negotiation_failed = True
                # Don't return yet - log this as a reconnaissance attempt

            # If negotiation failed, log as reconnaissance
            if negotiation_failed:
                self.log_auth_attempt(
                    client_ip,
                    "Unknown",
                    "[SSH scan/probe]",
                    success=False,
                    metadata={
                        'scan_type': 'ssh_probe',
                        'error': 'negotiation_failed',
                        'description': 'Client connected but failed SSH protocol negotiation'
                    }
                )
                return

            # Wait for auth - give them a few attempts
            max_attempts = self.config.get('protocols', {}).get('ssh', {}).get(
                'max_auth_attempts', 3
            )

            for _ in range(max_attempts):
                try:
                    channel = transport.accept(timeout=20)
                    if channel is None:
                        continue

                    # They shouldn't get here (auth always fails)
                    # But if they do, close immediately
                    channel.close()

                except Exception:
                    pass

        except Exception as e:
            self.logger.debug(f"SSH connection error from {client_ip}: {e}")
            # Log unexpected errors as reconnaissance attempts
            self.log_auth_attempt(
                client_ip,
                "Unknown",
                "[SSH connection error]",
                success=False,
                metadata={
                    'scan_type': 'ssh_error',
                    'error': str(e),
                    'description': 'SSH connection attempt with error'
                }
            )
        finally:
            if transport:
                try:
                    transport.close()
                except:
                    pass

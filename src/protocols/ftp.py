"""
FTP Honeypot implementation
"""
import socket
from typing import Dict, Any
from .base import BaseHoneypot


class FTPHoneypot(BaseHoneypot):
    """FTP protocol honeypot"""

    def get_port(self) -> int:
        """Get FTP port from config"""
        port = self.config.get('protocols', {}).get('ftp', {}).get('port')
        if port is None:
            raise ValueError("FTP port not configured in config.yaml")
        return port

    def handle_client(self, client_socket: socket.socket, address: tuple):
        """Handle FTP client connection"""
        client_ip = address[0]

        try:
            # Add realistic connection delay
            self.evasion.add_realistic_delay('connection')

            # Send welcome banner - use realistic random banner if not configured
            config_banner = self.config.get('protocols', {}).get('ftp', {}).get('banner')
            if config_banner:
                banner = config_banner
            else:
                # Use evasion engine to get realistic random banner
                banner = self.evasion.get_random_banner('ftp')
            client_socket.send(f"{banner}\r\n".encode())

            username = None

            # Process FTP commands
            while True:
                try:
                    data = client_socket.recv(1024)
                    if not data:
                        break

                    command = data.decode('utf-8', errors='ignore').strip()
                    self.logger.debug(f"FTP command from {client_ip}: {command}")

                    # Parse command
                    parts = command.split(' ', 1)
                    cmd = parts[0].upper()
                    arg = parts[1] if len(parts) > 1 else ''

                    if cmd == 'USER':
                        username = arg
                        client_socket.send(b"331 Password required\r\n")

                    elif cmd == 'PASS':
                        password = arg
                        if username:
                            # Add realistic delay before authentication check
                            self.evasion.add_realistic_delay('auth_check')

                            # Log the authentication attempt
                            self.log_auth_attempt(client_ip, username, password)

                        # Always reject - vary error message slightly
                        error_msg = self.evasion.vary_error_message('530 Login incorrect.', 'ftp')
                        client_socket.send(f"{error_msg}\r\n".encode())
                        # Reset username for next attempt
                        username = None

                    elif cmd == 'QUIT':
                        client_socket.send(b"221 Goodbye\r\n")
                        break

                    elif cmd == 'SYST':
                        client_socket.send(b"215 UNIX Type: L8\r\n")

                    elif cmd == 'FEAT':
                        client_socket.send(
                            b"211-Features:\r\n"
                            b" SIZE\r\n"
                            b" MDTM\r\n"
                            b"211 End\r\n"
                        )

                    elif cmd == 'PWD':
                        client_socket.send(b'257 "/" is current directory\r\n')

                    elif cmd == 'TYPE':
                        client_socket.send(b"200 Type set\r\n")

                    elif cmd in ['LIST', 'NLST', 'CWD', 'RETR', 'STOR']:
                        # Need to be authenticated
                        client_socket.send(b"530 Please login with USER and PASS\r\n")

                    else:
                        client_socket.send(b"502 Command not implemented\r\n")

                except socket.timeout:
                    break
                except Exception as e:
                    self.logger.debug(f"FTP protocol error from {client_ip}: {e}")
                    break

        except Exception as e:
            self.logger.debug(f"FTP connection error from {client_ip}: {e}")
        finally:
            try:
                client_socket.close()
            except:
                pass

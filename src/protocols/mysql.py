"""
MySQL Honeypot
Simulates MySQL database server to capture database authentication attempts
"""
import socket
import struct
import hashlib
import secrets
from typing import Dict, Any
from .base import BaseHoneypot


class MySQLHoneypot(BaseHoneypot):
    """MySQL protocol honeypot - Port 3306"""

    def get_port(self) -> int:
        """Get MySQL port from config"""
        port = self.config.get('protocols', {}).get('mysql', {}).get('port')
        if port is None:
            raise ValueError("MySQL port not configured in config.yaml")
        return port

    def handle_client(self, client_socket: socket.socket, address: tuple):
        """Handle MySQL client connection"""
        client_ip = address[0]
        username = ""
        database = ""

        try:
            client_socket.settimeout(10)

            # Add realistic connection delay
            self.evasion.add_realistic_delay('connection')

            # Send MySQL server greeting
            salt = secrets.token_bytes(20)
            try:
                greeting = self._build_server_greeting(salt)
                client_socket.sendall(greeting)
            except Exception as e:
                self.logger.error(f"MySQL: Error sending greeting to {client_ip}: {e}")
                # Still try to log the attempt
                self.log_auth_attempt(
                    client_ip,
                    "Unknown",
                    "[MySQL connection]",
                    success=False,
                    metadata={'error': 'greeting_failed', 'database': ''}
                )
                return

            # Receive login request
            login_data = client_socket.recv(4096)
            if not login_data or len(login_data) < 4:
                # Log even if we didn't get login data
                self.log_auth_attempt(
                    client_ip,
                    "Unknown",
                    "[MySQL connection attempt]",
                    success=False,
                    metadata={'error': 'no_login_data', 'database': ''}
                )
                return

            # Parse login packet
            username, database, auth_response = self._parse_login_packet(login_data)

            self.logger.info(
                f"MySQL connection from {client_ip}: user={username}, db={database}"
            )

            # Add realistic delay before authentication check
            self.evasion.add_realistic_delay('auth_check')

            # Send authentication error - vary message slightly
            error_msg = self.evasion.vary_error_message(
                f"Access denied for user '{username}'@'{client_ip}' (using password: YES)",
                'mysql'
            )
            try:
                error_response = self._build_error_response(
                    1045,
                    "28000",
                    error_msg
                )
                client_socket.sendall(error_response)
            except:
                pass

        except socket.timeout:
            self.logger.debug(f"MySQL: Timeout from {client_ip}")
        except Exception as e:
            self.logger.error(f"MySQL: Error from {client_ip}: {e}")
            import traceback
            self.logger.debug(f"MySQL traceback: {traceback.format_exc()}")
        finally:
            # Always log the attempt
            self.log_auth_attempt(
                client_ip,
                username or "root",
                "[MySQL auth hash]",
                success=False,
                metadata={
                    'database': database or '',
                    'auth_plugin': 'mysql_native_password',
                    'protocol': 'MySQL'
                }
            )

            try:
                client_socket.close()
            except:
                pass

    def _build_server_greeting(self, salt: bytes) -> bytes:
        """Build MySQL server greeting packet"""
        # Protocol version
        protocol_version = 10

        # Server version string - use realistic random version from evasion engine
        config_version = self.config.get('protocols', {}).get('mysql', {}).get('version')
        if config_version:
            server_version = config_version.encode() + b'\x00'
        else:
            # Use evasion engine to get realistic random version
            version = self.evasion.get_random_banner('mysql')
            server_version = version.encode() + b'\x00'

        # Thread ID
        thread_id = secrets.randbits(32)

        # Auth plugin data part 1 (8 bytes)
        salt_part1 = salt[:8]

        # Filler
        filler = b'\x00'

        # Capability flags (lower 2 bytes) - Standard MySQL capabilities
        # CLIENT_LONG_PASSWORD(1) | CLIENT_FOUND_ROWS(2) | CLIENT_LONG_FLAG(4) |
        # CLIENT_CONNECT_WITH_DB(8) | CLIENT_NO_SCHEMA(16) | CLIENT_PROTOCOL_41(512) |
        # CLIENT_TRANSACTIONS(8192) | CLIENT_SECURE_CONNECTION(32768)
        # = 1 + 2 + 4 + 8 + 16 + 512 + 8192 + 32768 = 41503 = 0xa21f
        capabilities_lower = 0xa21f

        # Character set (utf8_general_ci = 33)
        charset = 0x21

        # Status flags (SERVER_STATUS_AUTOCOMMIT)
        status_flags = 0x0002

        # Capability flags (upper 2 bytes)
        # CLIENT_PLUGIN_AUTH(524288) | CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA(2097152)
        # Upper 16 bits: (524288 + 2097152) >> 16 = 40 = 0x0028
        capabilities_upper = 0x0028

        # Auth plugin data length (13 bytes + null terminator)
        auth_plugin_data_len = 21

        # Reserved (10 bytes of zeros)
        reserved = b'\x00' * 10

        # Auth plugin data part 2 (12 bytes + null terminator)
        salt_part2 = salt[8:20]

        # Auth plugin name
        auth_plugin_name = b'mysql_native_password\x00'

        # Build payload
        payload = struct.pack('<B', protocol_version)
        payload += server_version
        payload += struct.pack('<I', thread_id)
        payload += salt_part1
        payload += filler
        payload += struct.pack('<H', capabilities_lower)
        payload += struct.pack('<B', charset)
        payload += struct.pack('<H', status_flags)
        payload += struct.pack('<H', capabilities_upper)
        payload += struct.pack('<B', auth_plugin_data_len)
        payload += reserved
        payload += salt_part2
        payload += b'\x00'  # Null terminator for salt_part2
        payload += auth_plugin_name

        # Add packet header (3-byte length + 1-byte sequence)
        packet_length = len(payload)
        header = struct.pack('<I', packet_length)[:3]  # Take first 3 bytes
        header += b'\x00'  # Sequence number = 0

        return header + payload

    def _parse_login_packet(self, data: bytes) -> tuple:
        """Parse MySQL login packet to extract username and database"""
        try:
            # Skip packet header (4 bytes)
            if len(data) < 36:
                return "", "", b""

            offset = 4

            # Client capabilities (4 bytes)
            offset += 4

            # Max packet size (4 bytes)
            offset += 4

            # Character set (1 byte)
            offset += 1

            # Reserved (23 bytes)
            offset += 23

            # Username (null-terminated string)
            username = ""
            while offset < len(data) and data[offset] != 0:
                username += chr(data[offset])
                offset += 1
            offset += 1  # Skip null terminator

            # Auth response length (1 byte)
            if offset < len(data):
                auth_len = data[offset]
                offset += 1

                # Auth response
                auth_response = data[offset:offset + auth_len]
                offset += auth_len
            else:
                auth_response = b""

            # Database name (null-terminated string)
            database = ""
            if offset < len(data):
                while offset < len(data) and data[offset] != 0:
                    database += chr(data[offset])
                    offset += 1

            return username, database, auth_response

        except Exception as e:
            self.logger.debug(f"MySQL: Error parsing login packet: {e}")
            return "", "", b""

    def _extract_client_version(self, data: bytes) -> str:
        """Extract MySQL client version from login packet"""
        try:
            # Client version is usually near the end of the packet
            data_str = data.decode('latin-1', errors='ignore')
            if 'mysql' in data_str.lower():
                # Try to find version pattern
                parts = data_str.split('\x00')
                for part in parts:
                    if 'mysql' in part.lower() or any(c.isdigit() for c in part):
                        clean = part.strip()
                        if len(clean) > 3 and len(clean) < 50:
                            return clean
        except:
            pass

        return "Unknown"

    def _build_error_response(self, error_code: int, sql_state: str, message: str) -> bytes:
        """Build MySQL error response packet"""
        # Error marker
        payload = b'\xff'

        # Error code (2 bytes, little-endian)
        payload += struct.pack('<H', error_code)

        # SQL state marker
        payload += b'#'

        # SQL state (5 bytes)
        payload += sql_state.encode('latin-1')

        # Error message
        payload += message.encode('utf-8')

        # Add packet header
        packet_length = len(payload)
        header = struct.pack('<I', packet_length)[0:3]
        header += b'\x02'  # Sequence number

        return header + payload

    def _build_ok_response(self) -> bytes:
        """Build MySQL OK response packet (not used for failed auth)"""
        payload = b'\x00'  # OK marker
        payload += b'\x00'  # Affected rows
        payload += b'\x00'  # Insert ID
        payload += struct.pack('<H', 0x0002)  # Status flags
        payload += struct.pack('<H', 0x0000)  # Warnings

        packet_length = len(payload)
        header = struct.pack('<I', packet_length)[0:3]
        header += b'\x01'

        return header + payload

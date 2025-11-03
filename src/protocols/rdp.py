"""
RDP (Remote Desktop Protocol) Honeypot
Simulates Windows Remote Desktop to capture RDP authentication attempts
"""
import socket
import struct
from typing import Dict, Any
from .base import BaseHoneypot


class RDPHoneypot(BaseHoneypot):
    """RDP protocol honeypot - Port 3389"""

    def get_port(self) -> int:
        """Get RDP port from config"""
        port = self.config.get('protocols', {}).get('rdp', {}).get('port')
        if port is None:
            raise ValueError("RDP port not configured in config.yaml")
        return port

    def handle_client(self, client_socket: socket.socket, address: tuple):
        """Handle RDP client connection"""
        client_ip = address[0]
        username = ""
        domain = ""

        try:
            # Set shorter timeout
            client_socket.settimeout(5)

            # Add realistic connection delay
            self.evasion.add_realistic_delay('connection')

            # Receive initial connection request
            data = client_socket.recv(4096)
            if not data or len(data) < 10:
                return

            self.logger.info(f"RDP connection attempt from {client_ip}, received {len(data)} bytes")

            # Debug: Log hex dump of first packet for analysis
            if len(data) > 0:
                hex_preview = data[:100].hex() if len(data) >= 100 else data.hex()
                self.logger.debug(f"RDP first packet hex: {hex_preview}")

            # Try to extract any username/domain from initial packet
            username = self._extract_username(data)
            domain = self._extract_domain(data)

            # Send X.224 Connection Confirm
            try:
                connection_confirm = self._build_connection_confirm()
                client_socket.sendall(connection_confirm)
            except:
                pass

            # Try to receive more data with credentials
            try:
                for i in range(5):  # Try up to 5 more packets to catch Client Info PDU
                    more_data = client_socket.recv(4096)
                    if not more_data:
                        break

                    # Debug: Log packet content
                    self.logger.debug(f"RDP packet {i+2} from {client_ip}: {len(more_data)} bytes")
                    if len(more_data) > 0:
                        hex_preview = more_data[:100].hex() if len(more_data) >= 100 else more_data.hex()
                        self.logger.debug(f"RDP packet {i+2} hex: {hex_preview}")

                    # Check for NTLMSSP (CredSSP with NTLM)
                    if b'NTLMSSP\x00' in more_data:
                        self.logger.debug(f"RDP: Found NTLMSSP in packet {i+2}")
                        ntlm_user, ntlm_domain = self._extract_ntlm_credentials(more_data)
                        if ntlm_user:
                            username = ntlm_user
                            self.logger.info(f"RDP: Extracted username '{username}' from NTLM")
                        if ntlm_domain:
                            domain = ntlm_domain
                            self.logger.info(f"RDP: Extracted domain '{domain}' from NTLM")

                    # Try to extract from additional packets
                    extracted_user = self._extract_username(more_data)
                    extracted_domain = self._extract_domain(more_data)

                    if extracted_user and not username:
                        username = extracted_user
                        self.logger.info(f"RDP: Extracted username '{username}' from packet {i+2}")
                    if extracted_domain and not domain:
                        domain = extracted_domain
                        self.logger.info(f"RDP: Extracted domain '{domain}' from packet {i+2}")

                    # Send some response to keep connection alive
                    try:
                        if i == 0:
                            client_socket.sendall(self._build_mcs_response())
                        else:
                            client_socket.sendall(self._build_auth_failure())
                    except:
                        break

            except socket.timeout:
                pass
            except Exception as e:
                self.logger.debug(f"RDP: Error in extended handshake: {e}")

        except socket.timeout:
            self.logger.debug(f"RDP: Timeout from {client_ip}")
        except Exception as e:
            self.logger.debug(f"RDP: Connection error from {client_ip}: {e}")
        finally:
            # Always log the attempt, even if we couldn't extract credentials
            full_username = f"{domain}\\{username}" if domain and username else username if username else "Unknown"

            self.log_auth_attempt(
                client_ip,
                full_username,
                "[RDP authentication data]",
                success=False,
                metadata={
                    'domain': domain or 'N/A',
                    'protocol_version': 'RDP',
                    'connection_type': 'RDP'
                }
            )

            try:
                client_socket.close()
            except:
                pass

    def _extract_username(self, data: bytes) -> str:
        """Extract username from RDP packet (best effort)"""
        try:
            # Method 1: Try UTF-16-LE decoding (common in RDP)
            try:
                data_str = data.decode('utf-16-le', errors='ignore')
                words = [w.strip() for w in data_str.split('\x00') if w.strip()]

                for word in words:
                    # Skip very short or very long strings
                    if not (3 <= len(word) <= 40):
                        continue

                    # Skip strings with too many non-printable chars
                    printable_count = sum(1 for c in word if c.isprintable())
                    if printable_count < len(word) * 0.8:
                        continue

                    # Check if it looks like a username
                    clean = word.replace('_', '').replace('-', '').replace('.', '').replace('@', '')
                    if clean.isalnum() and any(c.isalpha() for c in word):
                        # Filter out common false positives
                        lower_word = word.lower()
                        if lower_word not in ['cookie', 'mstsc', 'rdp', 'client', 'server',
                                              'windows', 'microsoft', 'protocol', 'connection']:
                            return word
            except:
                pass

            # Method 2: Try ASCII with null bytes
            try:
                # RDP sometimes uses ASCII with null byte separators
                ascii_str = data.decode('ascii', errors='ignore')
                words = [w.strip() for w in ascii_str.split('\x00') if w.strip()]

                for word in words:
                    if 3 <= len(word) <= 40:
                        clean = word.replace('_', '').replace('-', '').replace('.', '').replace('@', '')
                        if clean.isalnum() and any(c.isalpha() for c in word):
                            lower_word = word.lower()
                            if lower_word not in ['cookie', 'mstsc', 'rdp', 'client', 'server']:
                                return word
            except:
                pass

            # Method 3: Look for patterns like "user=", "username=", etc.
            try:
                data_lower = data.lower()
                patterns = [b'user=', b'username=', b'login=', b'account=']
                for pattern in patterns:
                    if pattern in data_lower:
                        idx = data_lower.index(pattern) + len(pattern)
                        # Extract up to 40 bytes after the pattern
                        user_data = data[idx:idx+40]
                        # Try to decode
                        try:
                            username = user_data.decode('utf-8', errors='ignore').split('\x00')[0].strip()
                            if 3 <= len(username) <= 40 and username.replace('_', '').replace('-', '').isalnum():
                                return username
                        except:
                            pass
            except:
                pass

        except Exception as e:
            pass

        return ""

    def _extract_domain(self, data: bytes) -> str:
        """Extract domain from RDP packet (best effort)"""
        try:
            data_str = data.decode('utf-16-le', errors='ignore')

            # Look for domain indicators
            for marker in ['Domain', 'DOMAIN', 'domain']:
                if marker in data_str:
                    idx = data_str.index(marker)
                    domain = ''
                    for char in data_str[idx + len(marker):idx + len(marker) + 40]:
                        if char.isprintable() and char not in ['\x00', '\n', '\r', '\t']:
                            domain += char
                        elif domain:
                            break
                    if domain and len(domain) > 2:
                        return domain.strip()
        except:
            pass

        return ""

    def _extract_ntlm_credentials(self, data: bytes) -> tuple:
        """Extract username and domain from NTLM messages in RDP"""
        username = ""
        domain = ""

        try:
            import struct

            if b'NTLMSSP\x00' not in data:
                return username, domain

            ntlm_pos = data.find(b'NTLMSSP\x00')

            # Check message type
            if ntlm_pos + 12 < len(data):
                msg_type = struct.unpack('<I', data[ntlm_pos+8:ntlm_pos+12])[0]

                # Type 3 = AUTHENTICATE_MESSAGE
                if msg_type == 3:
                    try:
                        # Domain name fields at offset 28-36
                        domain_len = struct.unpack('<H', data[ntlm_pos+28:ntlm_pos+30])[0]
                        domain_offset = struct.unpack('<I', data[ntlm_pos+32:ntlm_pos+36])[0]

                        # Username fields at offset 36-44
                        user_len = struct.unpack('<H', data[ntlm_pos+36:ntlm_pos+38])[0]
                        user_offset = struct.unpack('<I', data[ntlm_pos+40:ntlm_pos+44])[0]

                        # Extract username (UTF-16LE)
                        if user_offset + user_len <= len(data):
                            username_bytes = data[ntlm_pos + user_offset:ntlm_pos + user_offset + user_len]
                            username = username_bytes.decode('utf-16-le', errors='ignore')

                        # Extract domain (UTF-16LE)
                        if domain_offset + domain_len <= len(data):
                            domain_bytes = data[ntlm_pos + domain_offset:ntlm_pos + domain_offset + domain_len]
                            domain = domain_bytes.decode('utf-16-le', errors='ignore')
                    except:
                        pass

        except:
            pass

        return username, domain

    def _build_connection_confirm(self) -> bytes:
        """Build X.224 Connection Confirm packet"""
        # Minimal X.224 Connection Confirm response
        tpkt_header = struct.pack('>BBH', 3, 0, 11)  # TPKT: version=3, reserved=0, length=11
        x224_header = struct.pack('BBH', 6, 0xD0, 0)  # X.224: length=6, code=0xD0 (CC)
        return tpkt_header + x224_header

    def _build_mcs_response(self) -> bytes:
        """Build MCS Connect Response packet"""
        # Minimal MCS Connect Response
        tpkt_header = struct.pack('>BBH', 3, 0, 19)  # TPKT
        x224_data = struct.pack('BB', 2, 0xF0)  # X.224 Data
        # MCS Connect Response with rejection
        mcs_data = b'\x7f\x65\x82\x00\x08\x00\x05\x00\x14\x7c\x00\x01'
        return tpkt_header + x224_data + mcs_data

    def _build_auth_failure(self) -> bytes:
        """Build authentication failure response"""
        # Simple disconnection packet
        tpkt_header = struct.pack('>BBH', 3, 0, 9)
        x224_disconnect = struct.pack('BBH', 2, 0x80, 0)  # Disconnect request
        return tpkt_header + x224_disconnect

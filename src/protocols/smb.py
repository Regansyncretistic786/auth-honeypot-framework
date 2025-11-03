"""
SMB/CIFS Honeypot
Simulates Windows file sharing to capture SMB authentication attempts
Very common in ransomware and lateral movement attacks
"""
import socket
import struct
from typing import Dict, Any
from .base import BaseHoneypot


class SMBHoneypot(BaseHoneypot):
    """SMB/CIFS protocol honeypot - Port 445"""

    def get_port(self) -> int:
        """Get SMB port from config"""
        port = self.config.get('protocols', {}).get('smb', {}).get('port')
        if port is None:
            raise ValueError("SMB port not configured in config.yaml")
        return port

    def handle_client(self, client_socket: socket.socket, address: tuple):
        """Handle SMB client connection"""
        client_ip = address[0]

        try:
            client_socket.settimeout(10)

            # Add realistic connection delay
            self.evasion.add_realistic_delay('connection')

            # Receive SMB negotiation request
            data = client_socket.recv(4096)
            if not data or len(data) < 4:
                return

            self.logger.info(f"SMB connection attempt from {client_ip}")

            # Debug: Log hex dump of first packet
            hex_preview = data[:100].hex() if len(data) >= 100 else data.hex()
            self.logger.debug(f"SMB packet from {client_ip}: {len(data)} bytes, hex: {hex_preview}")

            # Check if client is requesting SMB2/3 in the negotiate dialects
            # Modern clients send SMB1 negotiate with SMB2 dialects embedded
            if b'SMB 2' in data or b'\x02\x02' in data or b'\x00\x02\x02' in data:
                self.logger.debug(f"SMB: Client {client_ip} requesting SMB2/3")
                self._handle_smb2(client_socket, client_ip, data)
            elif b'\xfeSMB' in data:
                self.logger.debug(f"SMB: Pure SMB2 from {client_ip}")
                self._handle_smb2(client_socket, client_ip, data)
            elif b'\xffSMB' in data:
                self.logger.debug(f"SMB: SMB1 only from {client_ip}")
                self._handle_smb1(client_socket, client_ip, data)
            else:
                self.logger.debug(f"SMB: Unknown protocol from {client_ip}")

        except socket.timeout:
            self.logger.debug(f"SMB: Timeout from {client_ip}")
        except Exception as e:
            self.logger.error(f"SMB: Error from {client_ip}: {e}")
        finally:
            try:
                client_socket.close()
            except:
                pass

    def _handle_smb1(self, client_socket: socket.socket, client_ip: str, initial_data: bytes):
        """Handle SMB1 (legacy) connection"""
        try:
            # Send SMB1 Negotiate Response
            negotiate_response = self._build_smb1_negotiate_response()
            self.logger.debug(f"SMB1: Sending negotiate response to {client_ip}: {len(negotiate_response)} bytes, hex: {negotiate_response[:60].hex()}")
            client_socket.sendall(negotiate_response)

            # Wait for Session Setup AndX Request
            session_data = client_socket.recv(4096)
            if session_data:
                username, domain = self._extract_smb1_credentials(session_data)

                # Log the attempt
                full_username = f"{domain}\\{username}" if domain else username
                self.log_auth_attempt(
                    client_ip,
                    full_username or "Anonymous",
                    "[SMB encrypted]",
                    success=False,
                    metadata={
                        'protocol': 'SMB1',
                        'domain': domain or '',
                        'smb_version': '1.0'
                    }
                )

                # Send access denied
                error_response = self._build_smb1_error_response()
                client_socket.sendall(error_response)

        except Exception as e:
            self.logger.debug(f"SMB1: Error handling connection from {client_ip}: {e}")

    def _handle_smb2(self, client_socket: socket.socket, client_ip: str, initial_data: bytes):
        """Handle SMB2/SMB3 connection"""
        try:
            # Send SMB2 Negotiate Response
            negotiate_response = self._build_smb2_negotiate_response()
            self.logger.debug(f"SMB2: Sending negotiate response to {client_ip}: {len(negotiate_response)} bytes, hex: {negotiate_response[:80].hex()}")
            client_socket.sendall(negotiate_response)

            # Wait for Session Setup Request
            session_data = client_socket.recv(4096)
            if session_data:
                username, domain = self._extract_smb2_credentials(session_data)

                # Determine SMB version
                smb_version = "2.1"
                if b'\x03\x00' in initial_data:
                    smb_version = "3.0"
                elif b'\x02\x02' in initial_data:
                    smb_version = "2.1"

                # Log the attempt
                full_username = f"{domain}\\{username}" if domain else username
                self.log_auth_attempt(
                    client_ip,
                    full_username or "Anonymous",
                    "[SMB encrypted]",
                    success=False,
                    metadata={
                        'protocol': f'SMB{smb_version}',
                        'domain': domain or '',
                        'smb_version': smb_version
                    }
                )

                # Send access denied
                error_response = self._build_smb2_error_response()
                client_socket.sendall(error_response)

        except Exception as e:
            self.logger.debug(f"SMB2: Error handling connection from {client_ip}: {e}")

    def _extract_smb1_credentials(self, data: bytes) -> tuple:
        """Extract username and domain from SMB1 packet"""
        username = ""
        domain = ""

        try:
            # SMB1 uses various encodings, try to find strings
            data_str = data.decode('utf-16-le', errors='ignore')

            # Look for username patterns
            words = [w.strip() for w in data_str.split('\x00') if w.strip()]
            for word in words:
                if 3 <= len(word) <= 30 and word.replace('_', '').replace('-', '').isalnum():
                    if not username and any(c.isalpha() for c in word):
                        username = word
                    elif not domain and '.' in word:
                        domain = word
                    if username and domain:
                        break

        except:
            pass

        return username, domain

    def _extract_smb2_credentials(self, data: bytes) -> tuple:
        """Extract username and domain from SMB2/3 packet"""
        username = ""
        domain = ""

        try:
            # Look for NTLMSSP signature (indicates NTLM authentication)
            if b'NTLMSSP\x00' in data:
                self.logger.debug(f"SMB2: Found NTLMSSP in packet")

                # Find NTLMSSP position
                ntlm_pos = data.find(b'NTLMSSP\x00')

                # Check message type (byte at offset 8)
                if ntlm_pos + 12 < len(data):
                    msg_type = struct.unpack('<I', data[ntlm_pos+8:ntlm_pos+12])[0]
                    self.logger.debug(f"SMB2: NTLM message type: {msg_type}")

                    # Type 3 = AUTHENTICATE_MESSAGE (contains username)
                    if msg_type == 3:
                        # Parse NTLM Type 3 message
                        # Username is at a variable offset, indicated by fields at fixed positions
                        # Structure: [signature][type][lm_response][ntlm_response][domain][username][workstation]

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
                                self.logger.debug(f"SMB2: Extracted username from NTLM: {username}")

                            # Extract domain (UTF-16LE)
                            if domain_offset + domain_len <= len(data):
                                domain_bytes = data[ntlm_pos + domain_offset:ntlm_pos + domain_offset + domain_len]
                                domain = domain_bytes.decode('utf-16-le', errors='ignore')
                                self.logger.debug(f"SMB2: Extracted domain from NTLM: {domain}")
                        except Exception as e:
                            self.logger.debug(f"SMB2: Error parsing NTLM Type 3: {e}")

            # Fallback: Try UTF-16-LE decoding for non-NTLM or if NTLM parsing failed
            if not username:
                data_str = data.decode('utf-16-le', errors='ignore')
                words = [w.strip() for w in data_str.split('\x00') if w.strip()]
                for word in words:
                    if 3 <= len(word) <= 30:
                        clean_word = word.replace('_', '').replace('-', '').replace('.', '')
                        if clean_word.isalnum():
                            if not username and any(c.isalpha() for c in word):
                                username = word
                            elif not domain:
                                domain = word
                            if username and domain:
                                break

        except Exception as e:
            self.logger.debug(f"SMB2: Error in credential extraction: {e}")

        return username, domain

    def _build_smb1_negotiate_response(self) -> bytes:
        """Build SMB1 Negotiate Protocol Response"""

        # SMB Header (32 bytes)
        smb_header = b'\xffSMB'  # Protocol (4 bytes)
        smb_header += b'\x72'  # Command: Negotiate (1 byte)
        smb_header += struct.pack('<I', 0x00000000)  # NT Status: SUCCESS (4 bytes)
        smb_header += b'\x98'  # Flags (1 byte)
        smb_header += struct.pack('<H', 0xC853)  # Flags2 (2 bytes)
        smb_header += struct.pack('<H', 0)  # PID High (2 bytes)
        smb_header += b'\x00' * 8  # Signature (8 bytes)
        smb_header += struct.pack('<H', 0)  # Reserved (2 bytes)
        smb_header += struct.pack('<H', 0)  # TID (2 bytes)
        smb_header += struct.pack('<H', 0)  # PID (2 bytes)
        smb_header += struct.pack('<H', 0)  # UID (2 bytes)
        smb_header += struct.pack('<H', 0)  # MID (2 bytes)

        # Word count and parameters (each word is 2 bytes)
        # Count: dialect(2) + secmode(1) + maxmpx(2) + maxvcs(2) + maxbuf(4) +
        #        maxraw(4) + sesskey(4) + caps(4) + systime(8) + tz(2) + keylen(1) = 34 bytes / 2 = 17 words
        word_count = 17
        params = struct.pack('<B', word_count)  # Word count
        params += struct.pack('<H', 0)  # Dialect index (0 = first dialect = "PC NETWORK PROGRAM 1.0")
        params += struct.pack('<B', 3)  # Security mode (user level, encrypted)
        params += struct.pack('<H', 50)  # Max multiplex count
        params += struct.pack('<H', 1)  # Max VCs
        params += struct.pack('<I', 16644)  # Max buffer size
        params += struct.pack('<I', 65536)  # Max raw size
        params += struct.pack('<I', 0)  # Session key
        params += struct.pack('<I', 0x0000f001)  # Server capabilities (unicode, nt status, rpc, nt smbs)
        params += struct.pack('<Q', 0)  # System time (NT time format)
        params += struct.pack('<h', 0)  # Server timezone
        params += struct.pack('<B', 8)  # Key length (challenge length)

        # Byte count section
        challenge = b'\x01\x02\x03\x04\x05\x06\x07\x08'  # 8-byte challenge
        server_name = b''  # Empty for now

        byte_count = len(challenge) + len(server_name)
        byte_count_data = struct.pack('<H', byte_count)
        byte_count_data += challenge
        byte_count_data += server_name

        # Complete SMB packet
        smb_packet = smb_header + params + byte_count_data

        # NetBIOS Session Service header
        netbios_length = len(smb_packet)
        netbios_header = struct.pack('>I', netbios_length)

        return netbios_header + smb_packet

    def _build_smb2_negotiate_response(self) -> bytes:
        """Build SMB2 Negotiate Protocol Response"""

        # SMB2 Header (64 bytes)
        smb2_header = b'\xfeSMB'  # Protocol ID (4 bytes)
        smb2_header += struct.pack('<H', 64)  # Structure size (2 bytes) - always 64
        smb2_header += struct.pack('<H', 1)  # Credit charge (2 bytes)
        smb2_header += struct.pack('<I', 0x00000000)  # Status (4 bytes) - SUCCESS
        smb2_header += struct.pack('<H', 0)  # Command (2 bytes) - 0 = Negotiate
        smb2_header += struct.pack('<H', 1)  # Credits granted (2 bytes)
        smb2_header += struct.pack('<I', 0x00000001)  # Flags (4 bytes) - SERVER_TO_REDIR
        smb2_header += struct.pack('<I', 0)  # NextCommand (4 bytes)
        smb2_header += struct.pack('<Q', 0)  # MessageId (8 bytes)
        smb2_header += struct.pack('<I', 0)  # Reserved (4 bytes)
        smb2_header += struct.pack('<I', 0)  # TreeId (4 bytes)
        smb2_header += struct.pack('<Q', 0)  # SessionId (8 bytes)
        smb2_header += b'\x00' * 16  # Signature (16 bytes)

        # Negotiate Response body
        import random
        server_guid = bytes([random.randint(0, 255) for _ in range(16)])

        body = struct.pack('<H', 65)  # StructureSize (2 bytes) - must be 65
        body += struct.pack('<H', 1)  # SecurityMode (2 bytes) - signing enabled
        body += struct.pack('<H', 0x0210)  # DialectRevision (2 bytes) - SMB 2.1
        body += struct.pack('<H', 0)  # NegotiateContextCount (2 bytes)
        body += server_guid  # ServerGuid (16 bytes)
        body += struct.pack('<I', 0x0000007f)  # Capabilities (4 bytes) - DFS, LEASING, etc
        body += struct.pack('<I', 0x100000)  # MaxTransactSize (4 bytes) - 1MB
        body += struct.pack('<I', 0x100000)  # MaxReadSize (4 bytes) - 1MB
        body += struct.pack('<I', 0x100000)  # MaxWriteSize (4 bytes) - 1MB
        body += struct.pack('<Q', 0)  # SystemTime (8 bytes) - NT time
        body += struct.pack('<Q', 0)  # ServerStartTime (8 bytes) - NT time
        body += struct.pack('<H', 0x80)  # SecurityBufferOffset (2 bytes) - 128 (0x80)
        body += struct.pack('<H', 0)  # SecurityBufferLength (2 bytes) - no security blob
        body += struct.pack('<I', 0)  # NegotiateContextOffset (4 bytes)

        full_packet = smb2_header + body

        # Add NetBIOS Session Service header
        netbios = struct.pack('>I', len(full_packet))

        return netbios + full_packet

    def _build_smb1_error_response(self) -> bytes:
        """Build SMB1 error response (Access Denied)"""
        netbios = struct.pack('>I', 0x00000023)
        smb_header = b'\xffSMB\x73'  # Session Setup AndX Response
        smb_header += struct.pack('<I', 0xC000006D)  # NT Status: LOGON_FAILURE
        smb_header += b'\x98'
        smb_header += struct.pack('<H', 0xC853)
        smb_header += b'\x00' * 12

        return netbios + smb_header + b'\x00\x00\x00'

    def _build_smb2_error_response(self) -> bytes:
        """Build SMB2 error response (Access Denied)"""
        netbios = struct.pack('>I', 0x00000048)
        smb2_header = b'\xfeSMB'
        smb2_header += struct.pack('<H', 64)
        smb2_header += struct.pack('<H', 0)
        smb2_header += struct.pack('<I', 0xC000006D)  # STATUS_LOGON_FAILURE
        smb2_header += struct.pack('<H', 1)  # Command: Session Setup
        smb2_header += struct.pack('<H', 0)
        smb2_header += struct.pack('<I', 0)
        smb2_header += struct.pack('<I', 0)
        smb2_header += struct.pack('<Q', 1)
        smb2_header += struct.pack('<Q', 0)
        smb2_header += struct.pack('<Q', 0)

        return netbios + smb2_header + b'\x09\x00\x00\x00'

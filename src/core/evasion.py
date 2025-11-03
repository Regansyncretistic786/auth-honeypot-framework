"""
Evasion and Realism Module
Provides techniques to make the honeypot harder to detect and more realistic
"""
import random
import time
import hashlib
from typing import Optional, Dict, Any
from datetime import datetime


class EvasionEngine:
    """Engine for implementing evasion and realism techniques"""

    def __init__(self):
        # Realistic service banners (updated versions as of 2024)
        self.banners = {
            'ssh': [
                'SSH-2.0-OpenSSH_9.3p1 Ubuntu-1ubuntu3',
                'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4',
                'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.9',
                'SSH-2.0-OpenSSH_9.0p1 Debian-1+deb12u1',
            ],
            'ftp': [
                '220 ProFTPD 1.3.8 Server (Debian)',
                '220 (vsFTPd 3.0.5)',
                '220 Microsoft FTP Service',
                '220 FileZilla Server 1.7.3',
            ],
            'http': [
                'Apache/2.4.57 (Ubuntu)',
                'nginx/1.24.0',
                'Microsoft-IIS/10.0',
                'Apache/2.4.54 (Debian)',
            ],
            'mysql': [
                '5.7.42-log',
                '8.0.35-0ubuntu0.22.04.1',
                '10.11.4-MariaDB-1~deb12u1',
            ]
        }

        # Timing variations (milliseconds)
        self.timing_min = 50
        self.timing_max = 300

        # Browser fingerprinting patterns
        self.suspicious_ua_patterns = [
            'python-requests',
            'curl/',
            'wget/',
            'scanner',
            'nikto',
            'sqlmap',
            'nmap',
            'masscan',
            'metasploit',
            'havij',
            'acunetix',
            'nessus',
            'openvas',
            'arachni',
            'w3af',
            'burpsuite',
        ]

        # Headless browser detection
        self.headless_indicators = [
            'HeadlessChrome',
            'PhantomJS',
            'Selenium',
            'webdriver',
            'headless',
        ]

    def get_random_banner(self, protocol: str) -> str:
        """Get a realistic random banner for a protocol"""
        if protocol.lower() in self.banners:
            return random.choice(self.banners[protocol.lower()])
        return ""

    def add_realistic_delay(self, operation: str = "default") -> None:
        """Add realistic timing delay to avoid instant responses"""
        # Different operations have different realistic delays
        delays = {
            'connection': (50, 150),      # Connection acceptance
            'auth_check': (100, 400),     # Authentication verification
            'database': (80, 250),        # Database queries
            'file_access': (60, 200),     # File system access
            'default': (50, 300),         # Default
        }

        min_delay, max_delay = delays.get(operation, delays['default'])
        delay_ms = random.randint(min_delay, max_delay)
        time.sleep(delay_ms / 1000.0)

    def vary_error_message(self, base_message: str, protocol: str) -> str:
        """Vary error messages slightly to avoid fingerprinting"""
        # Add slight variations to error messages
        variations = {
            'ssh': [
                'Permission denied',
                'Authentication failed',
                'Access denied',
            ],
            'ftp': [
                '530 Login incorrect.',
                '530 Authentication failed.',
                '530 Login authentication failed',
            ],
            'mysql': [
                "Access denied for user '{user}'@'{host}' (using password: YES)",
                "Access denied for user '{user}'@'{host}'",
            ]
        }

        if protocol in variations and random.random() < 0.3:
            return random.choice(variations[protocol])

        return base_message

    def detect_suspicious_client(self, user_agent: Optional[str],
                                 headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """Detect suspicious clients (scanners, bots, headless browsers)"""
        result = {
            'is_suspicious': False,
            'is_scanner': False,
            'is_headless': False,
            'is_bot': False,
            'confidence': 0.0,
            'indicators': []
        }

        if not user_agent:
            result['is_suspicious'] = True
            result['confidence'] = 0.6
            result['indicators'].append('no_user_agent')
            return result

        ua_lower = user_agent.lower()

        # Check for known scanner patterns
        for pattern in self.suspicious_ua_patterns:
            if pattern.lower() in ua_lower:
                result['is_suspicious'] = True
                result['is_scanner'] = True
                result['confidence'] = 0.9
                result['indicators'].append(f'scanner_pattern:{pattern}')

        # Check for headless browsers
        for indicator in self.headless_indicators:
            if indicator.lower() in ua_lower:
                result['is_suspicious'] = True
                result['is_headless'] = True
                result['confidence'] = max(result['confidence'], 0.8)
                result['indicators'].append(f'headless:{indicator}')

        # Check for bot indicators in headers
        if headers:
            # Missing common headers
            common_headers = ['Accept', 'Accept-Language', 'Accept-Encoding']
            missing_headers = [h for h in common_headers if h not in headers]
            if len(missing_headers) >= 2:
                result['is_suspicious'] = True
                result['is_bot'] = True
                result['confidence'] = max(result['confidence'], 0.6)
                result['indicators'].append('missing_common_headers')

            # Suspicious header combinations
            if 'User-Agent' in headers and 'Accept' not in headers:
                result['is_suspicious'] = True
                result['confidence'] = max(result['confidence'], 0.7)
                result['indicators'].append('suspicious_header_combo')

        return result

    def generate_realistic_server_header(self, protocol: str) -> str:
        """Generate realistic server identification headers"""
        if protocol == 'http':
            server = self.get_random_banner('http')
            # Sometimes omit minor version details
            if random.random() < 0.2:
                server = server.split('/')[0]
            return server
        return ""

    def should_respond_differently(self, ip: str, attempt_count: int) -> bool:
        """Determine if we should vary behavior based on repeated attempts"""
        # After multiple attempts, occasionally change behavior slightly
        if attempt_count > 5:
            return random.random() < 0.3
        return False

    def generate_session_token(self, ip: str, timestamp: float) -> str:
        """Generate realistic-looking session tokens"""
        # Mix of random and deterministic for consistency within a session
        data = f"{ip}{timestamp}{random.random()}".encode()
        token = hashlib.sha256(data).hexdigest()[:32]
        return token

    def add_honeypot_indicators(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Add subtle indicators that this is a honeypot (for research tracking)"""
        # Add a hidden watermark that researchers can use to identify our honeypot
        # This helps distinguish our data in threat intelligence feeds
        data['_honeypot_id'] = self._generate_honeypot_id()
        return data

    def _generate_honeypot_id(self) -> str:
        """Generate a consistent but non-obvious honeypot identifier"""
        # Use a deterministic hash so it's consistent across restarts
        identifier = "auth-honeypot-framework-v1.0"
        return hashlib.md5(identifier.encode()).hexdigest()[:16]

    def mimic_server_errors(self, protocol: str) -> Optional[str]:
        """Occasionally simulate realistic server errors"""
        if random.random() < 0.05:  # 5% chance
            errors = {
                'ssh': 'Connection reset by peer',
                'ftp': '421 Service not available, closing control connection',
                'http': '503 Service Temporarily Unavailable',
                'mysql': 'ERROR 2013 (HY000): Lost connection to MySQL server',
            }
            return errors.get(protocol)
        return None

    def get_realistic_port_behavior(self, port: int) -> Dict[str, Any]:
        """Determine realistic behavior based on port"""
        behaviors = {
            22: {'protocol': 'ssh', 'timeout': 120, 'banner_delay': 0.1},
            21: {'protocol': 'ftp', 'timeout': 300, 'banner_delay': 0.05},
            23: {'protocol': 'telnet', 'timeout': 120, 'banner_delay': 0.2},
            80: {'protocol': 'http', 'timeout': 30, 'banner_delay': 0.0},
            443: {'protocol': 'https', 'timeout': 30, 'banner_delay': 0.0},
            3389: {'protocol': 'rdp', 'timeout': 60, 'banner_delay': 0.15},
            445: {'protocol': 'smb', 'timeout': 90, 'banner_delay': 0.1},
            3306: {'protocol': 'mysql', 'timeout': 120, 'banner_delay': 0.08},
        }
        return behaviors.get(port, {'protocol': 'unknown', 'timeout': 60, 'banner_delay': 0.1})

    def anti_fingerprint_tcp_timing(self) -> float:
        """Vary TCP timing to avoid fingerprinting"""
        # Add jitter to prevent timing-based detection
        base_delay = random.uniform(0.001, 0.01)
        jitter = random.uniform(-0.002, 0.002)
        return max(0, base_delay + jitter)

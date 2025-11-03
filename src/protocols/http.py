"""
HTTP/HTTPS Honeypot implementation
Simulates web login pages to capture credential-based attacks
"""
import socket
import ssl
import json
import random
from typing import Dict, Any
from datetime import datetime
from urllib.parse import parse_qs, unquote
from .base import BaseHoneypot


class HTTPHoneypot(BaseHoneypot):
    """HTTP/HTTPS protocol honeypot"""

    def __init__(self, config: Dict[str, Any], logger):
        super().__init__(config, logger)
        self.templates = LoginTemplates()
        self.use_https = config.get('protocols', {}).get('http', {}).get('https_enabled', False)

        # Override protocol_name to distinguish HTTP vs HTTPS
        if self.use_https:
            self.protocol_name = "HTTPS"
            self.ssl_context = self._create_ssl_context()
        else:
            self.protocol_name = "HTTP"
            self.ssl_context = None

    def _create_ssl_context(self):
        """Create SSL context with self-signed certificate"""
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

        # Try to load existing cert, otherwise create self-signed
        cert_file = self.config.get('protocols', {}).get('http', {}).get('cert_file', 'honeypot.pem')
        key_file = self.config.get('protocols', {}).get('http', {}).get('key_file', 'honeypot.key')

        try:
            context.load_cert_chain(cert_file, key_file)
        except FileNotFoundError:
            # Generate self-signed certificate
            self.logger.info("SSL cert not found, using self-signed certificate")
            self._generate_self_signed_cert(cert_file, key_file)
            context.load_cert_chain(cert_file, key_file)

        return context

    def _generate_self_signed_cert(self, cert_file: str, key_file: str):
        """Generate self-signed SSL certificate"""
        try:
            from cryptography import x509
            from cryptography.x509.oid import NameOID
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.hazmat.primitives import serialization
            import datetime

            # Generate private key
            key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )

            # Generate certificate
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Honeypot"),
                x509.NameAttribute(NameOID.COMMON_NAME, u"localhost"),
            ])

            cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.datetime.utcnow()
            ).not_valid_after(
                datetime.datetime.utcnow() + datetime.timedelta(days=365)
            ).add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName(u"localhost"),
                    x509.DNSName(u"*.localhost"),
                ]),
                critical=False,
            ).sign(key, hashes.SHA256())

            # Write private key
            with open(key_file, "wb") as f:
                f.write(key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                ))

            # Write certificate
            with open(cert_file, "wb") as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))

            self.logger.info(f"Generated self-signed certificate: {cert_file}")
        except ImportError:
            self.logger.warning("cryptography library not available, HTTPS disabled")
            raise

    def get_port(self) -> int:
        """Get HTTP port from config"""
        if self.use_https:
            port = self.config.get('protocols', {}).get('http', {}).get('https_port')
            if port is None:
                raise ValueError("HTTPS port not configured in config.yaml")
            return port
        else:
            port = self.config.get('protocols', {}).get('http', {}).get('port')
            if port is None:
                raise ValueError("HTTP port not configured in config.yaml")
            return port

    def handle_client(self, client_socket: socket.socket, address: tuple):
        """Handle HTTP/HTTPS client connection"""
        client_ip = address[0]

        # Wrap socket with SSL if HTTPS is enabled
        if self.use_https and self.ssl_context:
            try:
                client_socket = self.ssl_context.wrap_socket(client_socket, server_side=True)
            except ssl.SSLError as e:
                self.logger.debug(f"SSL handshake failed from {client_ip}: {e}")
                return
            except Exception as e:
                self.logger.debug(f"SSL error from {client_ip}: {e}")
                return

        try:
            # Read HTTP request
            request_data = b""
            while True:
                try:
                    chunk = client_socket.recv(4096)
                    if not chunk:
                        break
                    request_data += chunk

                    # Check if we have complete headers
                    if b"\r\n\r\n" in request_data:
                        # Check if there's a body
                        headers_end = request_data.index(b"\r\n\r\n") + 4
                        headers = request_data[:headers_end].decode('utf-8', errors='ignore')

                        # Check Content-Length
                        content_length = 0
                        for line in headers.split('\r\n'):
                            if line.lower().startswith('content-length:'):
                                try:
                                    content_length = int(line.split(':', 1)[1].strip())
                                except:
                                    pass

                        # If we have all the body data, break
                        body_received = len(request_data) - headers_end
                        if body_received >= content_length:
                            break
                except socket.timeout:
                    break

            if not request_data:
                return

            # Parse the HTTP request
            request = self._parse_http_request(request_data, client_ip)

            # Route the request
            response = self._route_request(request, client_ip)
            client_socket.sendall(response.encode('utf-8'))

        except Exception as e:
            self.logger.debug(f"HTTP connection error from {client_ip}: {e}")
        finally:
            try:
                client_socket.close()
            except:
                pass

    def _parse_http_request(self, request_data: bytes, client_ip: str) -> Dict[str, Any]:
        """Parse HTTP request"""
        try:
            request_str = request_data.decode('utf-8', errors='ignore')
        except:
            request_str = str(request_data)

        lines = request_str.split('\r\n')

        # Parse request line
        request_line = lines[0].split(' ')
        method = request_line[0] if len(request_line) > 0 else 'GET'
        path = request_line[1] if len(request_line) > 1 else '/'

        # Parse headers
        headers = {}
        body_start = 0
        for i, line in enumerate(lines[1:], 1):
            if line == '':
                body_start = i + 1
                break
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip().lower()] = value.strip()

        # Parse body (for POST requests)
        body = ''
        if body_start < len(lines):
            body = '\r\n'.join(lines[body_start:])

        return {
            'method': method,
            'path': path,
            'headers': headers,
            'body': body,
            'user_agent': headers.get('user-agent', ''),
            'client_ip': client_ip
        }

    def _route_request(self, request: Dict[str, Any], client_ip: str) -> str:
        """Route HTTP requests to appropriate handlers"""
        path = request['path']
        method = request['method']

        # Detect suspicious clients (scanners, bots, headless browsers)
        detection_result = self.evasion.detect_suspicious_client(
            request['user_agent'],
            request['headers']
        )

        if detection_result['is_suspicious']:
            self.logger.warning(
                f"SUSPICIOUS CLIENT detected from {client_ip}: "
                f"Scanner={detection_result['is_scanner']}, "
                f"Headless={detection_result['is_headless']}, "
                f"Bot={detection_result['is_bot']}, "
                f"Confidence={detection_result['confidence']:.2f}, "
                f"Indicators={','.join(detection_result['indicators'])}"
            )
            # Log this as a recon attempt
            self.log_auth_attempt(
                client_ip,
                username='',
                password='',
                success=False,
                metadata={
                    'scan_type': 'suspicious_client',
                    'detection': detection_result,
                    'user_agent': request['user_agent'],
                    'path': path
                }
            )

        # Add realistic delay
        self.evasion.add_realistic_delay('connection')

        # Log the access attempt
        self.logger.info(f"HTTP {method} {path} from {client_ip} - UA: {request['user_agent'][:50]}")

        # API Endpoints (catch automated scanners/bots)
        if path.startswith('/api/'):
            return self._handle_api_request(request, client_ip)

        # Fake sensitive files (honeytokens)
        if path in ['/.env', '/.git/config', '/config.php', '/wp-config.php',
                    '/database.yml', '/.aws/credentials', '/id_rsa', '/.ssh/id_rsa']:
            return self._handle_honeytoken_file(request, client_ip, path)

        # robots.txt (reveals fake structure)
        if path == '/robots.txt':
            return self._generate_robots_txt()

        # Common admin panels
        if path in ['/admin', '/admin/', '/administrator', '/wp-admin', '/wp-admin/',
                    '/phpmyadmin', '/phpMyAdmin', '/cpanel', '/cPanel']:
            return self._generate_login_page(request)

        # Dashboard (after "successful" login)
        if path == '/dashboard' or path == '/portal':
            return self._generate_fake_dashboard(request)

        # Dashboard search endpoint
        if path == '/dashboard/search' and method == 'POST':
            return self._handle_dashboard_search(request, client_ip)

        # Dashboard sub-pages (permission denied)
        if path in ['/subscribers', '/reports', '/settings', '/account', '/billing', '/support']:
            self.logger.info(f"Access attempt to {path} from {client_ip}")
            return self._generate_permission_denied(request, path)

        # Logout page
        if path == '/logout':
            self.logger.info(f"User logged out from {client_ip}")
            return self._generate_logout_page(request)

        # Login page
        if path == '/' or path.startswith('/login'):
            return self._generate_login_page(request)

        # Authentication endpoint
        if method == 'POST' and '/auth' in path:
            fake_success = self._handle_login_attempt(request, client_ip)
            if fake_success:
                # Redirect to dashboard for fake successful login
                return self._generate_fake_success_redirect(request)
            else:
                # Show loading page that expires
                return self._generate_success_page(request)

        # Static resources
        if '/static/' in path or path.endswith(('.css', '.js', '.ico')):
            return self._handle_static_resource(request)

        # Default: 404 but log it
        self.logger.info(f"404 path scanned: {path} from {client_ip}")
        return self._generate_404(path)

    def _handle_api_request(self, request: Dict[str, Any], client_ip: str) -> str:
        """Handle API endpoint requests (catch bots)"""
        path = request['path']
        method = request['method']

        # Log API access attempt
        metadata = {
            'api_endpoint': path,
            'user_agent': request['user_agent'],
            'method': method,
            'referer': request['headers'].get('referer', ''),
            'scan_type': 'api_enumeration'
        }

        # Log as reconnaissance attempt
        self.log_auth_attempt(
            client_ip,
            username='',
            password='',
            success=False,
            metadata=metadata
        )

        # Return fake API responses
        if path == '/api/login' and method == 'POST':
            # Parse credentials from API call
            self._handle_login_attempt(request, client_ip)
            return self._generate_api_response({'error': 'Invalid credentials', 'code': 401}, 401)

        elif path == '/api/users':
            return self._generate_api_response({'error': 'Unauthorized', 'code': 403}, 403)

        elif path == '/api/config':
            return self._generate_api_response({'error': 'Access denied', 'code': 403}, 403)

        else:
            return self._generate_api_response({'error': 'Endpoint not found', 'code': 404}, 404)

    def _handle_honeytoken_file(self, request: Dict[str, Any], client_ip: str, filepath: str) -> str:
        """Handle requests for fake sensitive files"""
        # Log honeytoken access
        metadata = {
            'honeytoken_file': filepath,
            'user_agent': request['user_agent'],
            'scan_type': 'sensitive_file_scan'
        }

        self.log_auth_attempt(
            client_ip,
            username='',
            password='',
            success=False,
            metadata=metadata
        )

        self.logger.warning(f"HONEYTOKEN ACCESSED: {filepath} by {client_ip}")

        # Return fake sensitive content
        fake_content = self._generate_fake_file_content(filepath)

        response = "HTTP/1.1 200 OK\r\n"
        response += "Content-Type: text/plain\r\n"
        response += f"Content-Length: {len(fake_content)}\r\n"
        response += "Connection: close\r\n"
        response += "\r\n"
        response += fake_content

        return response

    def _generate_fake_file_content(self, filepath: str) -> str:
        """Generate fake sensitive file content"""
        if filepath == '/.env':
            return """APP_NAME=StationNetwork
APP_ENV=production
APP_KEY=base64:HONEYPOT_DO_NOT_USE_abc123
APP_DEBUG=false
APP_URL=http://portal.stationnetwork.com

DB_CONNECTION=mysql
DB_HOST=172.16.0.10
DB_PORT=3306
DB_DATABASE=station_prod
DB_USERNAME=station_user
DB_PASSWORD=FAKE_PASSWORD_HONEYPOT

AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
"""
        elif '/.git/config' in filepath:
            return """[core]
        repositoryformatversion = 0
        filemode = true
[remote "origin"]
        url = https://github.com/stationnetwork/portal.git
        fetch = +refs/heads/*:refs/remotes/origin/*
[user]
        name = admin
        email = admin@stationnetwork.com
"""
        elif 'wp-config.php' in filepath:
            return """<?php
define('DB_NAME', 'station_wordpress');
define('DB_USER', 'wp_user');
define('DB_PASSWORD', 'FAKE_WP_PASS_123');
define('DB_HOST', 'localhost');
define('AUTH_KEY', 'HONEYPOT_KEY_DO_NOT_USE');
?>"""
        elif 'id_rsa' in filepath:
            return """-----BEGIN RSA PRIVATE KEY-----
HONEYPOT - THIS IS NOT A REAL KEY
MIIEpAIBAAKCAQEA... [FAKE KEY CONTENT]
-----END RSA PRIVATE KEY-----"""
        else:
            return "# Sensitive configuration file - HONEYPOT"

    def _generate_api_response(self, data: dict, status_code: int = 200) -> str:
        """Generate JSON API response"""
        json_data = json.dumps(data)

        status_text = {
            200: 'OK',
            401: 'Unauthorized',
            403: 'Forbidden',
            404: 'Not Found'
        }.get(status_code, 'OK')

        response = f"HTTP/1.1 {status_code} {status_text}\r\n"
        response += "Content-Type: application/json\r\n"
        response += f"Content-Length: {len(json_data)}\r\n"
        response += "Server: nginx/1.18.0\r\n"
        response += "Connection: close\r\n"
        response += "\r\n"
        response += json_data

        return response

    def _generate_robots_txt(self) -> str:
        """Generate fake robots.txt to reveal fake structure"""
        content = """User-agent: *
Disallow: /admin/
Disallow: /api/
Disallow: /config/
Disallow: /backup/
Disallow: /private/
Disallow: /.env
Disallow: /uploads/sensitive/
Disallow: /dashboard/
Allow: /
"""
        response = "HTTP/1.1 200 OK\r\n"
        response += "Content-Type: text/plain\r\n"
        response += f"Content-Length: {len(content)}\r\n"
        response += "Connection: close\r\n"
        response += "\r\n"
        response += content

        return response

    def _generate_logout_page(self, request: Dict[str, Any]) -> str:
        """Generate logout confirmation page with session clearing"""
        html = """<!DOCTYPE html>
<html>
<head>
    <title>Logged Out - Station Network</title>
    <meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate">
    <meta http-equiv="Pragma" content="no-cache">
    <meta http-equiv="Expires" content="0">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            padding: 20px;
        }
        .logout-container {
            background: white;
            border-radius: 12px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            width: 100%;
            max-width: 500px;
            padding: 50px 40px;
            text-align: center;
        }
        .icon {
            font-size: 80px;
            margin-bottom: 30px;
        }
        .title {
            font-size: 28px;
            color: #333;
            margin-bottom: 15px;
            font-weight: 700;
        }
        .message {
            font-size: 16px;
            color: #666;
            line-height: 1.6;
            margin-bottom: 30px;
        }
        .info-box {
            background: #e3f2fd;
            border-left: 4px solid #2196f3;
            padding: 15px;
            border-radius: 6px;
            text-align: left;
            margin-bottom: 30px;
        }
        .info-box p {
            color: #1565c0;
            font-size: 14px;
            margin: 0;
        }
        .login-button {
            display: inline-block;
            padding: 14px 40px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            text-decoration: none;
            border-radius: 6px;
            font-weight: 600;
            font-size: 16px;
            transition: transform 0.2s, box-shadow 0.2s;
        }
        .login-button:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 20px rgba(102, 126, 234, 0.4);
        }
        .footer {
            margin-top: 30px;
            font-size: 13px;
            color: #999;
        }
    </style>
    <script>
        // Prevent going back to authenticated pages
        (function() {
            // Clear any cached data
            if (window.history && window.history.pushState) {
                // Replace current state
                window.history.pushState(null, '', window.location.href);

                // Prevent back button
                window.onpopstate = function() {
                    window.history.pushState(null, '', window.location.href);
                };
            }

            // Clear session storage
            try {
                sessionStorage.clear();
                localStorage.removeItem('auth_token');
            } catch(e) {}
        })();

        // Auto-redirect after 5 seconds
        setTimeout(function() {
            window.location.href = '/';
        }, 5000);
    </script>
</head>
<body>
    <div class="logout-container">
        <div class="icon">👋</div>
        <div class="title">Successfully Logged Out</div>
        <div class="message">
            Your session has been terminated and you have been logged out of the Station Network portal.
        </div>

        <div class="info-box">
            <p><strong>✓ Session Cleared</strong><br>
            All authentication tokens have been removed. You will need to log in again to access the portal.</p>
        </div>

        <a href="/" class="login-button">Return to Login</a>

        <div class="footer">
            You will be automatically redirected in 5 seconds...
        </div>
    </div>
</body>
</html>"""

        response = "HTTP/1.1 200 OK\r\n"
        response += "Content-Type: text/html; charset=utf-8\r\n"
        response += f"Content-Length: {len(html)}\r\n"
        response += "Cache-Control: no-cache, no-store, must-revalidate\r\n"
        response += "Pragma: no-cache\r\n"
        response += "Expires: 0\r\n"
        response += "Connection: close\r\n"
        response += "\r\n"
        response += html

        return response

    def _generate_permission_denied(self, request: Dict[str, Any], page_path: str) -> str:
        """Generate permission denied page for restricted sections"""
        page_name = page_path.strip('/').capitalize()

        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Access Denied - Station Network</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #f5f7fa;
            min-height: 100vh;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px 40px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .header h1 {{
            font-size: 24px;
            font-weight: 600;
        }}
        .header .subtitle {{
            font-size: 14px;
            opacity: 0.9;
            margin-top: 5px;
        }}
        .nav {{
            background: white;
            padding: 15px 40px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            display: flex;
            gap: 30px;
        }}
        .nav a {{
            color: #667eea;
            text-decoration: none;
            font-weight: 500;
            font-size: 14px;
            padding: 5px 0;
        }}
        .container {{
            max-width: 800px;
            margin: 80px auto;
            padding: 0 40px;
        }}
        .access-denied-card {{
            background: white;
            padding: 60px 40px;
            border-radius: 12px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.1);
            text-align: center;
        }}
        .icon {{
            font-size: 80px;
            margin-bottom: 30px;
        }}
        .title {{
            font-size: 32px;
            color: #d32f2f;
            margin-bottom: 20px;
            font-weight: 700;
        }}
        .message {{
            font-size: 18px;
            color: #555;
            margin-bottom: 15px;
            line-height: 1.6;
        }}
        .submessage {{
            font-size: 15px;
            color: #777;
            margin-bottom: 40px;
            line-height: 1.6;
        }}
        .info-box {{
            background: #fff3cd;
            border-left: 4px solid #ff9800;
            padding: 20px;
            border-radius: 6px;
            margin-bottom: 30px;
            text-align: left;
        }}
        .info-box p {{
            color: #856404;
            font-size: 14px;
            line-height: 1.6;
            margin: 0;
        }}
        .button-group {{
            display: flex;
            gap: 15px;
            justify-content: center;
            margin-top: 30px;
        }}
        .btn {{
            padding: 14px 30px;
            border-radius: 6px;
            text-decoration: none;
            font-weight: 600;
            font-size: 15px;
            transition: transform 0.2s, box-shadow 0.2s;
        }}
        .btn-primary {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }}
        .btn-secondary {{
            background: #f5f5f5;
            color: #555;
            border: 2px solid #ddd;
        }}
        .btn:hover {{
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        }}
        .details {{
            margin-top: 40px;
            padding-top: 30px;
            border-top: 1px solid #e0e0e0;
        }}
        .details-grid {{
            display: grid;
            grid-template-columns: 150px 1fr;
            gap: 12px;
            text-align: left;
            max-width: 500px;
            margin: 0 auto;
        }}
        .details-label {{
            font-weight: 600;
            color: #666;
            font-size: 13px;
        }}
        .details-value {{
            color: #333;
            font-size: 13px;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>📡 Station Network</h1>
        <div class="subtitle">Subscriber Management Portal</div>
    </div>

    <div class="nav">
        <a href="/dashboard">Dashboard</a>
        <a href="/subscribers">Subscribers</a>
        <a href="/reports">Reports</a>
        <a href="/settings">Settings</a>
        <a href="/logout">Logout</a>
    </div>

    <div class="container">
        <div class="access-denied-card">
            <div class="icon">🚫</div>
            <div class="title">Access Denied</div>
            <div class="message">You don't have permission to view this page.</div>
            <div class="submessage">
                The "{page_name}" section requires elevated privileges that your account doesn't have.
            </div>

            <div class="info-box">
                <p><strong>⚠ Insufficient Permissions</strong><br>
                Your current role does not grant access to this resource. If you believe this is an error,
                please contact your system administrator to request the necessary permissions.</p>
            </div>

            <div class="button-group">
                <a href="/dashboard" class="btn btn-primary">← Back to Dashboard</a>
                <a href="/support" class="btn btn-secondary">Contact Support</a>
            </div>

            <div class="details">
                <div class="details-grid">
                    <div class="details-label">Resource:</div>
                    <div class="details-value">{page_path}</div>
                    <div class="details-label">Required Role:</div>
                    <div class="details-value">Administrator</div>
                    <div class="details-label">Your Role:</div>
                    <div class="details-value">Read-Only User</div>
                    <div class="details-label">Error Code:</div>
                    <div class="details-value">403 - Forbidden</div>
                </div>
            </div>
        </div>
    </div>
</body>
</html>"""

        response = "HTTP/1.1 403 Forbidden\r\n"
        response += "Content-Type: text/html; charset=utf-8\r\n"
        response += f"Content-Length: {len(html)}\r\n"
        response += "Connection: close\r\n"
        response += "\r\n"
        response += html

        return response

    def _generate_fake_dashboard(self, request: Dict[str, Any]) -> str:
        """Generate fake dashboard with subscriber lookup"""
        html = """<!DOCTYPE html>
<html>
<head>
    <title>Subscriber Management - Station Network</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #f5f7fa;
            min-height: 100vh;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px 40px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .header h1 {
            font-size: 24px;
            font-weight: 600;
        }
        .header .subtitle {
            font-size: 14px;
            opacity: 0.9;
            margin-top: 5px;
        }
        .nav {
            background: white;
            padding: 15px 40px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            display: flex;
            gap: 30px;
        }
        .nav a {
            color: #667eea;
            text-decoration: none;
            font-weight: 500;
            font-size: 14px;
            padding: 5px 0;
            border-bottom: 2px solid transparent;
            transition: border-color 0.3s;
        }
        .nav a:hover, .nav a.active {
            border-bottom-color: #667eea;
        }
        .container {
            max-width: 1200px;
            margin: 40px auto;
            padding: 0 40px;
        }
        .welcome-banner {
            background: linear-gradient(135deg, #e8f5e9 0%, #c8e6c9 100%);
            border-left: 4px solid #4caf50;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 30px;
        }
        .welcome-banner h2 {
            color: #2e7d32;
            font-size: 18px;
            margin-bottom: 5px;
        }
        .welcome-banner p {
            color: #558b2f;
            font-size: 14px;
        }
        .search-section {
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            margin-bottom: 30px;
        }
        .search-section h2 {
            color: #333;
            font-size: 20px;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .search-form {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
        }
        .form-group {
            display: flex;
            flex-direction: column;
        }
        .form-group label {
            font-size: 13px;
            font-weight: 600;
            color: #555;
            margin-bottom: 8px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .form-group input {
            padding: 12px 15px;
            border: 2px solid #e0e0e0;
            border-radius: 6px;
            font-size: 15px;
            transition: border-color 0.3s;
        }
        .form-group input:focus {
            outline: none;
            border-color: #667eea;
        }
        .form-group input::placeholder {
            color: #aaa;
        }
        .search-button {
            grid-column: 1 / -1;
            padding: 14px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 6px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s, box-shadow 0.2s;
            margin-top: 10px;
        }
        .search-button:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(102, 126, 234, 0.4);
        }
        .search-button:active {
            transform: translateY(0);
        }
        .info-box {
            background: #f8f9fa;
            border-left: 4px solid #667eea;
            padding: 15px;
            border-radius: 4px;
            margin-top: 20px;
        }
        .info-box p {
            color: #666;
            font-size: 13px;
            line-height: 1.6;
        }
        .quick-stats {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 20px;
            margin-bottom: 30px;
        }
        .stat-card {
            background: white;
            padding: 25px;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            text-align: center;
        }
        .stat-card .number {
            font-size: 32px;
            font-weight: 700;
            color: #667eea;
            margin-bottom: 10px;
        }
        .stat-card .label {
            color: #666;
            font-size: 14px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .result-container {
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            margin-top: 20px;
            display: none;
        }
        .result-container.show {
            display: block;
        }
        .result-error {
            background: #fff3cd;
            border: 1px solid #ffc107;
            color: #856404;
            padding: 15px;
            border-radius: 6px;
            text-align: center;
        }
        .logout-link {
            text-align: center;
            margin-top: 40px;
            padding-bottom: 40px;
        }
        .logout-link a {
            color: #999;
            text-decoration: none;
            font-size: 14px;
        }
        .logout-link a:hover {
            color: #667eea;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>📡 Station Network</h1>
        <div class="subtitle">Subscriber Management Portal</div>
    </div>

    <div class="nav">
        <a href="/dashboard" class="active">Dashboard</a>
        <a href="/subscribers">Subscribers</a>
        <a href="/reports">Reports</a>
        <a href="/settings">Settings</a>
        <a href="/logout">Logout</a>
    </div>

    <div class="container">
        <div class="welcome-banner">
            <h2>✓ Welcome Back, Administrator</h2>
            <p>You have successfully logged into the subscriber management system.</p>
        </div>

        <div class="quick-stats">
            <div class="stat-card">
                <div class="number">1,134,438</div>
                <div class="label">Active Subscribers</div>
            </div>
            <div class="stat-card">
                <div class="number">8,247</div>
                <div class="label">New This Month</div>
            </div>
            <div class="stat-card">
                <div class="number">99.7%</div>
                <div class="label">Network Uptime</div>
            </div>
        </div>

        <div class="search-section">
            <h2>🔍 Subscriber Lookup</h2>
            <form id="searchForm" class="search-form" action="/dashboard/search" method="POST">
                <div class="form-group">
                    <label for="imsi">IMSI (International Mobile Subscriber Identity)</label>
                    <input type="text" id="imsi" name="imsi" placeholder="e.g., 310150123456789">
                </div>
                <div class="form-group">
                    <label for="msisdn">MSISDN (Mobile Number)</label>
                    <input type="text" id="msisdn" name="msisdn" placeholder="e.g., +27821234567">
                </div>
                <div class="form-group">
                    <label for="iccid">ICCID (SIM Card Number)</label>
                    <input type="text" id="iccid" name="iccid" placeholder="e.g., 8927011234567890123">
                </div>
                <div class="form-group">
                    <label for="email">Email Address</label>
                    <input type="email" id="email" name="email" placeholder="e.g., user@example.com">
                </div>
                <button type="submit" class="search-button">Search Subscriber Database</button>
            </form>

            <div class="info-box">
                <p><strong>Note:</strong> Enter at least one search parameter. The system will search across all subscriber records in the database.</p>
            </div>
        </div>

        <div class="result-container" id="resultContainer">
            <div class="result-error">
                <strong>⚠ No Results Found</strong><br>
                <p style="margin-top: 10px;">No subscriber matching the provided criteria was found in the database.</p>
            </div>
        </div>

        <div class="logout-link">
            <a href="/">← Return to Login</a>
        </div>
    </div>

    <script>
        document.getElementById('searchForm').addEventListener('submit', function(e) {
            e.preventDefault();

            const formData = new FormData(this);

            // Convert FormData to URL-encoded string
            const urlEncodedData = new URLSearchParams(formData).toString();

            fetch('/dashboard/search', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded'
                },
                body: urlEncodedData
            })
            .then(response => response.text())
            .then(html => {
                // Show result container
                const resultContainer = document.getElementById('resultContainer');
                resultContainer.classList.add('show');
                resultContainer.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
            })
            .catch(error => {
                console.error('Search error:', error);
            });
        });
    </script>
</body>
</html>"""

        response = "HTTP/1.1 200 OK\r\n"
        response += "Content-Type: text/html; charset=utf-8\r\n"
        response += f"Content-Length: {len(html)}\r\n"
        response += "Connection: close\r\n"
        response += "\r\n"
        response += html

        return response

    def _generate_404(self, path: str) -> str:
        """Generate 404 response"""
        html = f"""<!DOCTYPE html>
<html>
<head><title>404 Not Found</title></head>
<body>
<h1>Not Found</h1>
<p>The requested URL {path} was not found on this server.</p>
<hr><p>Apache/2.4.41 (Ubuntu) Server at portal.stationnetwork.com Port 8888</p>
</body>
</html>"""

        response = "HTTP/1.1 404 Not Found\r\n"
        response += "Content-Type: text/html\r\n"
        response += f"Content-Length: {len(html)}\r\n"
        response += "Server: Apache/2.4.41\r\n"
        response += "Connection: close\r\n"
        response += "\r\n"
        response += html

        return response

    def _handle_dashboard_search(self, request: Dict[str, Any], client_ip: str) -> str:
        """Handle dashboard subscriber search and log search queries"""
        body = request['body']

        # Parse form data
        imsi = ''
        msisdn = ''
        iccid = ''
        email = ''

        try:
            # Handle both URL-encoded and multipart form data
            if body:
                params = parse_qs(body)
                imsi = params.get('imsi', [''])[0] if params.get('imsi') else ''
                msisdn = params.get('msisdn', [''])[0] if params.get('msisdn') else ''
                iccid = params.get('iccid', [''])[0] if params.get('iccid') else ''
                email = params.get('email', [''])[0] if params.get('email') else ''

                # URL decode if needed
                imsi = unquote(imsi) if imsi else ''
                msisdn = unquote(msisdn) if msisdn else ''
                iccid = unquote(iccid) if iccid else ''
                email = unquote(email) if email else ''
        except Exception as e:
            self.logger.error(f"Error parsing search params: {e}, body: {body[:200]}")

        # Log the search attempt with all parameters
        search_data = {}
        if imsi:
            search_data['imsi'] = imsi
        if msisdn:
            search_data['msisdn'] = msisdn
        if iccid:
            search_data['iccid'] = iccid
        if email:
            search_data['email'] = email

        metadata = {
            'user_agent': request['user_agent'],
            'path': request['path'],
            'method': request['method'],
            'referer': request['headers'].get('referer', ''),
            'search_type': 'subscriber_lookup',
            'search_params': search_data,
            'timestamp': datetime.now().isoformat()
        }

        # Log the search attempt
        self.log_auth_attempt(
            client_ip,
            username='',
            password='',
            success=False,
            metadata=metadata
        )

        # Also log to console for visibility
        self.logger.warning(
            f"SUBSCRIBER SEARCH from {client_ip}: IMSI={imsi or 'N/A'}, "
            f"MSISDN={msisdn or 'N/A'}, ICCID={iccid or 'N/A'}, EMAIL={email or 'N/A'}"
        )

        # Return "not found" response
        html = """<!DOCTYPE html>
<html>
<head>
    <title>Search Result</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #f5f7fa;
            padding: 40px;
        }
        .result-card {
            max-width: 600px;
            margin: 0 auto;
            background: white;
            padding: 40px;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            text-align: center;
        }
        .result-icon {
            font-size: 64px;
            margin-bottom: 20px;
        }
        .result-title {
            font-size: 24px;
            color: #333;
            margin-bottom: 15px;
        }
        .result-message {
            color: #666;
            font-size: 16px;
            line-height: 1.6;
            margin-bottom: 30px;
        }
        .back-button {
            display: inline-block;
            padding: 12px 30px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            text-decoration: none;
            border-radius: 6px;
            font-weight: 600;
            transition: transform 0.2s;
        }
        .back-button:hover {
            transform: translateY(-2px);
        }
    </style>
</head>
<body>
    <div class="result-card">
        <div class="result-icon">🔍</div>
        <div class="result-title">No Subscriber Found</div>
        <div class="result-message">
            The subscriber information you searched for could not be found in our database.<br>
            Please verify the details and try again.
        </div>
        <a href="/dashboard" class="back-button">← Back to Dashboard</a>
    </div>
</body>
</html>"""

        response = "HTTP/1.1 200 OK\r\n"
        response += "Content-Type: text/html; charset=utf-8\r\n"
        response += f"Content-Length: {len(html)}\r\n"
        response += "Connection: close\r\n"
        response += "\r\n"
        response += html

        return response

    def _handle_login_attempt(self, request: Dict[str, Any], client_ip: str) -> bool:
        """Handle login attempt and log credentials

        Returns:
            bool: True if fake success should be granted, False otherwise
        """
        body = request['body']

        # Parse form data
        username = ''
        password = ''

        if 'application/json' in request['headers'].get('content-type', ''):
            # JSON payload
            try:
                data = json.loads(body)
                username = data.get('username', data.get('user', data.get('email', '')))
                password = data.get('password', data.get('pass', ''))
            except:
                pass
        else:
            # Form-encoded data
            try:
                params = parse_qs(body)
                username = params.get('username', params.get('user', params.get('email', [''])))
                password = params.get('password', params.get('pass', ['']))
                username = username[0] if username else ''
                password = password[0] if password else ''
                username = unquote(username)
                password = unquote(password)
            except:
                pass

        # Determine if this should be a fake success
        http_config = self.config.get('protocols', {}).get('http', {})
        fake_success_probability = http_config.get('fake_success_probability', 0.0)
        fake_success_usernames = http_config.get('fake_success_usernames', [])

        grant_fake_success = False

        # Check for 100% guaranteed success credential
        if username == '_rootadmin' and password == '_Corporate_Portal_':
            grant_fake_success = True
            self.logger.warning(f"FAKE SUCCESS (guaranteed) granted to {username} from {client_ip}")
        # Check if username is in the list AND probability check passes
        elif username.lower() in [u.lower() for u in fake_success_usernames]:
            if random.random() < fake_success_probability:
                grant_fake_success = True
                self.logger.warning(f"FAKE SUCCESS (probabilistic) granted to {username} from {client_ip}")

        # Log additional metadata
        metadata = {
            'user_agent': request['user_agent'],
            'path': request['path'],
            'method': request['method'],
            'referer': request['headers'].get('referer', ''),
            'timestamp': datetime.now().isoformat()
        }

        # Log the authentication attempt
        self.log_auth_attempt(
            client_ip,
            username,
            password,
            success=grant_fake_success,
            metadata=metadata
        )

        return grant_fake_success

    def _generate_login_page(self, request: Dict[str, Any]) -> str:
        """Generate login page HTML"""
        template_name = self.config.get('protocols', {}).get('http', {}).get('template', 'corporate')

        if template_name == 'wordpress':
            html = self.templates.wordpress_login()
        elif template_name == 'admin':
            html = self.templates.admin_panel_login()
        elif template_name == 'office365':
            html = self.templates.office365_login()
        else:
            html = self.templates.corporate_login()

        # Build HTTP response
        response = "HTTP/1.1 200 OK\r\n"
        response += "Content-Type: text/html; charset=utf-8\r\n"
        response += f"Content-Length: {len(html)}\r\n"
        response += "Server: Apache/2.4.41\r\n"
        response += "Connection: close\r\n"
        response += "\r\n"
        response += html

        return response

    def _generate_success_page(self, request: Dict[str, Any]) -> str:
        """Generate fake success page after login"""
        html = self.templates.loading_page()

        response = "HTTP/1.1 200 OK\r\n"
        response += "Content-Type: text/html; charset=utf-8\r\n"
        response += f"Content-Length: {len(html)}\r\n"
        response += "Server: Apache/2.4.41\r\n"
        response += "Connection: close\r\n"
        response += "\r\n"
        response += html

        return response

    def _generate_fake_success_redirect(self, request: Dict[str, Any]) -> str:
        """Generate redirect to dashboard for fake successful login"""
        # Return 302 redirect to dashboard
        response = "HTTP/1.1 302 Found\r\n"
        response += "Location: /dashboard\r\n"
        response += "Content-Length: 0\r\n"
        response += "Server: Apache/2.4.41\r\n"
        response += "Connection: close\r\n"
        response += "\r\n"

        return response

    def _handle_static_resource(self, request: Dict[str, Any]) -> str:
        """Handle static resource requests (return minimal responses)"""
        # Return minimal CSS or JS
        if request['path'].endswith('.css'):
            content = "/* Honeypot CSS */"
            response = "HTTP/1.1 200 OK\r\n"
            response += "Content-Type: text/css\r\n"
        elif request['path'].endswith('.js'):
            content = "// Honeypot JS"
            response = "HTTP/1.1 200 OK\r\n"
            response += "Content-Type: application/javascript\r\n"
        else:
            content = ""
            response = "HTTP/1.1 404 Not Found\r\n"
            response += "Content-Type: text/plain\r\n"

        response += f"Content-Length: {len(content)}\r\n"
        response += "Connection: close\r\n"
        response += "\r\n"
        response += content

        return response


class LoginTemplates:
    """Login page templates"""

    def corporate_login(self) -> str:
        """Modern corporate login page"""
        return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Corporate Portal - Sign In</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            padding: 20px;
        }
        .login-container {
            background: white;
            border-radius: 10px;
            box-shadow: 0 14px 28px rgba(0,0,0,0.25), 0 10px 10px rgba(0,0,0,0.22);
            width: 100%;
            max-width: 400px;
            padding: 40px;
        }
        .logo {
            text-align: center;
            margin-bottom: 30px;
        }
        .logo h1 {
            color: #667eea;
            font-size: 32px;
            font-weight: 700;
        }
        .form-group {
            margin-bottom: 20px;
        }
        .form-group label {
            display: block;
            margin-bottom: 8px;
            color: #333;
            font-weight: 500;
        }
        .form-group input {
            width: 100%;
            padding: 12px 15px;
            border: 2px solid #e0e0e0;
            border-radius: 5px;
            font-size: 14px;
            transition: border-color 0.3s;
        }
        .form-group input:focus {
            outline: none;
            border-color: #667eea;
        }
        .btn-login {
            width: 100%;
            padding: 14px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 5px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s;
        }
        .btn-login:hover {
            transform: translateY(-2px);
        }
        .options {
            margin-top: 20px;
            text-align: center;
        }
        .options a {
            color: #667eea;
            text-decoration: none;
            font-size: 14px;
        }
        .footer {
            margin-top: 30px;
            text-align: center;
            color: #999;
            font-size: 12px;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="logo">
            <h1>📡 Station Network</h1>
            <p style="color: #666; margin-top: 5px;">Subscriber Portal</p>
        </div>
        <form action="/auth" method="POST">
            <div class="form-group">
                <label for="username">Account Number or Email</label>
                <input type="text" id="username" name="username" placeholder="Enter your account number" required autofocus>
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" placeholder="Enter your password" required>
            </div>
            <button type="submit" class="btn-login">Sign In to My Account</button>
        </form>
        <div class="options">
            <a href="/forgot-password">Forgot password?</a> •
            <a href="/register">Register New Account</a>
        </div>
        <div class="footer">
            © 2025 Station Network Services. All rights reserved.
        </div>
    </div>
</body>
</html>"""

    def wordpress_login(self) -> str:
        """WordPress-style login page"""
        return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Log In ‹ My Blog — WordPress</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen-Sans, Ubuntu, Cantarell, "Helvetica Neue", sans-serif;
            background: #f0f0f1;
            margin: 0;
            padding: 50px 0;
        }
        #login {
            width: 320px;
            margin: 0 auto;
        }
        #login h1 a {
            background-image: url(data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iODQiIGhlaWdodD0iODQiIHZpZXdCb3g9IjAgMCA4NCA4NCIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj48ZyBmaWxsPSJub25lIiBmaWxsLXJ1bGU9ImV2ZW5vZGQiPjxjaXJjbGUgZmlsbD0iIzI3MUEzMCIgY3g9IjQyIiBjeT0iNDIiIHI9IjQyIi8+PHBhdGggZD0iTTU4IDIzdjM4SDI2VjIzaDMyeiIgZmlsbD0iI0ZGRiIvPjwvZz48L3N2Zz4=);
            background-size: 84px;
            background-position: center top;
            background-repeat: no-repeat;
            color: #3c434a;
            height: 84px;
            font-size: 20px;
            font-weight: 400;
            line-height: 1.3em;
            margin: 0 auto 25px;
            padding: 0;
            text-decoration: none;
            width: 84px;
            text-indent: -9999px;
            outline: 0;
            overflow: hidden;
            display: block;
        }
        #loginform {
            background: #fff;
            border: 1px solid #c3c4c7;
            box-shadow: 0 1px 3px rgba(0,0,0,.04);
            padding: 26px 24px 46px;
            font-size: 14px;
        }
        .login label {
            color: #3c434a;
            font-size: 14px;
            line-height: 1.5;
            display: block;
            margin-bottom: 5px;
        }
        .login input[type="text"],
        .login input[type="password"] {
            background: #fff;
            border: 1px solid #8c8f94;
            box-shadow: 0 0 0 transparent;
            color: #2c3338;
            font-size: 24px;
            width: 100%;
            padding: 3px 5px;
            margin: 0 6px 16px 0;
            line-height: 1.33333333;
        }
        .login input[type="text"]:focus,
        .login input[type="password"]:focus {
            border-color: #2271b1;
            box-shadow: 0 0 0 1px #2271b1;
            outline: 2px solid transparent;
        }
        .submit {
            margin-top: 20px;
        }
        .button-primary {
            background: #2271b1;
            border-color: #2271b1;
            color: #fff;
            text-decoration: none;
            font-size: 14px;
            height: 32px;
            line-height: 2.30769231;
            padding: 0 12px;
            border-width: 1px;
            border-style: solid;
            border-radius: 3px;
            white-space: nowrap;
            box-sizing: border-box;
            cursor: pointer;
            width: 100%;
        }
        .button-primary:hover {
            background: #135e96;
            border-color: #135e96;
        }
        #nav {
            text-align: center;
            padding: 0 24px;
            font-size: 13px;
            margin: 24px 0;
        }
        #nav a {
            color: #50575e;
            text-decoration: none;
        }
    </style>
</head>
<body class="login">
    <div id="login">
        <h1><a href="/">My Blog</a></h1>
        <form name="loginform" id="loginform" action="/auth" method="post">
            <p>
                <label for="user_login">Username or Email Address</label>
                <input type="text" name="username" id="user_login" class="input" size="20" autocapitalize="off" required />
            </p>
            <p>
                <label for="user_pass">Password</label>
                <input type="password" name="password" id="user_pass" class="input" size="20" required />
            </p>
            <p class="submit">
                <input type="submit" name="wp-submit" id="wp-submit" class="button button-primary button-large" value="Log In" />
            </p>
        </form>
        <p id="nav">
            <a href="/lost-password">Lost your password?</a>
        </p>
    </div>
</body>
</html>"""

    def admin_panel_login(self) -> str:
        """Admin panel style login"""
        return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Panel - Login</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #1a1a2e;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
        }
        .login-box {
            background: #16213e;
            width: 400px;
            padding: 40px;
            border-radius: 10px;
            box-shadow: 0 15px 25px rgba(0,0,0,.6);
        }
        .login-box h2 {
            margin: 0 0 30px;
            padding: 0;
            color: #fff;
            text-align: center;
            font-size: 28px;
        }
        .user-box {
            position: relative;
            margin-bottom: 30px;
        }
        .user-box input {
            width: 100%;
            padding: 10px 0;
            font-size: 16px;
            color: #fff;
            border: none;
            border-bottom: 1px solid #fff;
            outline: none;
            background: transparent;
        }
        .user-box label {
            position: absolute;
            top: 0;
            left: 0;
            padding: 10px 0;
            font-size: 16px;
            color: #fff;
            pointer-events: none;
            transition: .5s;
        }
        .user-box input:focus ~ label,
        .user-box input:valid ~ label {
            top: -20px;
            left: 0;
            color: #03e9f4;
            font-size: 12px;
        }
        .submit-btn {
            position: relative;
            display: inline-block;
            padding: 10px 20px;
            color: #03e9f4;
            font-size: 16px;
            text-decoration: none;
            text-transform: uppercase;
            overflow: hidden;
            transition: .5s;
            margin-top: 20px;
            letter-spacing: 4px;
            background: transparent;
            border: 1px solid #03e9f4;
            border-radius: 5px;
            width: 100%;
            cursor: pointer;
        }
        .submit-btn:hover {
            background: #03e9f4;
            color: #fff;
            box-shadow: 0 0 5px #03e9f4,
                        0 0 25px #03e9f4,
                        0 0 50px #03e9f4,
                        0 0 100px #03e9f4;
        }
        .icon {
            text-align: center;
            margin-bottom: 20px;
            font-size: 48px;
        }
    </style>
</head>
<body>
    <div class="login-box">
        <div class="icon">🔐</div>
        <h2>Administrator</h2>
        <form action="/auth" method="POST">
            <div class="user-box">
                <input type="text" name="username" required="">
                <label>Username</label>
            </div>
            <div class="user-box">
                <input type="password" name="password" required="">
                <label>Password</label>
            </div>
            <button type="submit" class="submit-btn">Sign In</button>
        </form>
    </div>
</body>
</html>"""

    def office365_login(self) -> str:
        """Microsoft Office 365 style login"""
        return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sign in to your account</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: "Segoe UI", "Helvetica Neue", Helvetica, Arial, sans-serif;
            background: #f5f5f5;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
        }
        .ms-login {
            background: #fff;
            width: 440px;
            padding: 44px;
            box-shadow: 0 2px 6px rgba(0,0,0,.2);
        }
        .ms-logo {
            margin-bottom: 16px;
        }
        .ms-logo img {
            width: 108px;
        }
        .ms-title {
            font-size: 24px;
            font-weight: 600;
            color: #1b1b1b;
            margin-bottom: 16px;
        }
        .ms-input-group {
            margin-bottom: 16px;
        }
        .ms-input-group input {
            width: 100%;
            padding: 8px 10px;
            font-size: 15px;
            border: 1px solid #666;
            border-radius: 0;
            outline: none;
        }
        .ms-input-group input:focus {
            border-color: #0078d4;
        }
        .ms-btn {
            background: #0067b8;
            border: 1px solid #0067b8;
            color: #fff;
            padding: 5px 12px;
            min-width: 108px;
            font-size: 15px;
            cursor: pointer;
            text-align: center;
            margin-top: 24px;
        }
        .ms-btn:hover {
            background: #005ba1;
        }
        .ms-footer {
            margin-top: 16px;
            font-size: 13px;
        }
        .ms-footer a {
            color: #0067b8;
            text-decoration: none;
        }
    </style>
</head>
<body>
    <div class="ms-login">
        <div class="ms-logo">
            <svg xmlns="http://www.w3.org/2000/svg" width="108" height="24" viewBox="0 0 108 24">
                <rect fill="#f25022" width="11" height="11"/>
                <rect fill="#7fba00" x="13" width="11" height="11"/>
                <rect fill="#00a4ef" y="13" width="11" height="11"/>
                <rect fill="#ffb900" x="13" y="13" width="11" height="11"/>
                <text x="30" y="16" font-family="Segoe UI,sans-serif" font-size="13" font-weight="600" fill="#5e5e5e">Microsoft</text>
            </svg>
        </div>
        <div class="ms-title">Sign in</div>
        <form action="/auth" method="POST">
            <div class="ms-input-group">
                <input type="text" name="username" placeholder="Email, phone, or Skype" required autofocus>
            </div>
            <div class="ms-input-group">
                <input type="password" name="password" placeholder="Password" required>
            </div>
            <button type="submit" class="ms-btn">Sign in</button>
        </form>
        <div class="ms-footer">
            <a href="#">Can't access your account?</a>
        </div>
    </div>
</body>
</html>"""

    def loading_page(self) -> str:
        """Fake loading/success page"""
        return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Signing in...</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            color: white;
        }
        .loading-container {
            text-align: center;
        }
        .spinner {
            border: 4px solid rgba(255,255,255,0.3);
            border-radius: 50%;
            border-top: 4px solid white;
            width: 60px;
            height: 60px;
            animation: spin 1s linear infinite;
            margin: 0 auto 20px;
        }
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        h2 {
            font-size: 24px;
            font-weight: 400;
            margin-bottom: 10px;
        }
        p {
            font-size: 14px;
            opacity: 0.9;
        }
    </style>
</head>
<body>
    <div class="loading-container">
        <div class="spinner"></div>
        <h2>Signing you in...</h2>
        <p>Please wait while we verify your credentials</p>
    </div>
    <script>
        setTimeout(function() {
            document.querySelector('h2').textContent = 'Session expired';
            document.querySelector('p').textContent = 'Please try again later';
            document.querySelector('.spinner').style.display = 'none';
        }, 3000);
    </script>
</body>
</html>"""

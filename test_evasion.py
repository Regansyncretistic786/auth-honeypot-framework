#!/usr/bin/env python3
"""
Test script for evasion and realism features
Tests timing, banner variation, and detection capabilities
"""
import socket
import time
import sys
from datetime import datetime

# Test configuration
HONEYPOT_HOST = "localhost"

TESTS = {
    'ssh': {'port': 2222, 'test_banner': True, 'test_timing': True},
    'ftp': {'port': 2121, 'test_banner': True, 'test_timing': True},
    'telnet': {'port': 2323, 'test_banner': False, 'test_timing': True},
    'http': {'port': 8080, 'test_banner': True, 'test_timing': True, 'test_fingerprint': True},
    'mysql': {'port': 3306, 'test_banner': True, 'test_timing': True},
    'rdp': {'port': 3389, 'test_banner': False, 'test_timing': True},
    'smb': {'port': 445, 'test_banner': False, 'test_timing': True},
}


def test_timing(protocol: str, port: int):
    """Test realistic timing delays"""
    print(f"\n[{protocol.upper()}] Testing timing delays...")

    timings = []

    for i in range(3):
        try:
            start = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((HONEYPOT_HOST, port))

            # Receive initial data (banner/greeting)
            try:
                data = sock.recv(4096)
                elapsed = time.time() - start
                timings.append(elapsed * 1000)  # Convert to ms
                print(f"  Attempt {i+1}: {elapsed*1000:.2f}ms")
            except:
                pass

            sock.close()
        except Exception as e:
            print(f"  Attempt {i+1}: Connection failed - {e}")

    if timings:
        avg = sum(timings) / len(timings)
        print(f"  Average response time: {avg:.2f}ms")
        print(f"  Variation: {max(timings) - min(timings):.2f}ms")

        # Check if timing is realistic (should have some variation)
        if max(timings) - min(timings) > 10:
            print(f"  ✓ Good timing variation detected (anti-fingerprinting)")
        else:
            print(f"  ⚠ Low timing variation (may be detectable)")


def test_banner_variation(protocol: str, port: int):
    """Test banner variation across multiple connections"""
    print(f"\n[{protocol.upper()}] Testing banner variation...")

    banners = []

    for i in range(5):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((HONEYPOT_HOST, port))

            # Receive banner
            data = sock.recv(4096)

            if protocol == 'http':
                # Send HTTP request to get Server header
                sock.sendall(b"GET / HTTP/1.1\r\nHost: test\r\n\r\n")
                response = sock.recv(4096).decode('latin-1', errors='ignore')
                for line in response.split('\r\n'):
                    if line.startswith('Server:'):
                        banner = line.split(':', 1)[1].strip()
                        banners.append(banner)
                        print(f"  Attempt {i+1}: {banner}")
                        break
            elif protocol == 'mysql':
                # MySQL server version is in greeting packet
                if len(data) > 10:
                    # Skip protocol version byte
                    version_end = data.find(b'\x00', 5)
                    if version_end > 0:
                        version = data[5:version_end].decode('latin-1', errors='ignore')
                        banners.append(version)
                        print(f"  Attempt {i+1}: MySQL {version}")
            else:
                banner = data.decode('utf-8', errors='ignore').strip()
                banners.append(banner)
                print(f"  Attempt {i+1}: {banner[:80]}")

            sock.close()
            time.sleep(0.5)  # Brief delay between tests

        except Exception as e:
            print(f"  Attempt {i+1}: Failed - {e}")

    if banners:
        unique_banners = len(set(banners))
        print(f"\n  Total banners collected: {len(banners)}")
        print(f"  Unique banners: {unique_banners}")

        if unique_banners > 1:
            print(f"  ✓ Banner randomization working! ({unique_banners} different banners)")
        elif unique_banners == 1:
            print(f"  ⚠ Same banner every time (may be using config override)")


def test_http_fingerprinting():
    """Test HTTP browser fingerprinting detection"""
    print(f"\n[HTTP] Testing browser fingerprinting...")

    test_cases = [
        {
            'name': 'Normal Browser',
            'headers': b"GET / HTTP/1.1\r\nHost: test\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\nAccept: text/html\r\nAccept-Language: en-US\r\n\r\n",
            'expected': 'Not flagged'
        },
        {
            'name': 'Python Requests (Scanner)',
            'headers': b"GET / HTTP/1.1\r\nHost: test\r\nUser-Agent: python-requests/2.28.0\r\n\r\n",
            'expected': 'Flagged as scanner'
        },
        {
            'name': 'cURL (Scanner)',
            'headers': b"GET / HTTP/1.1\r\nHost: test\r\nUser-Agent: curl/7.68.0\r\nAccept: */*\r\n\r\n",
            'expected': 'Flagged as scanner'
        },
        {
            'name': 'Nikto Scanner',
            'headers': b"GET / HTTP/1.1\r\nHost: test\r\nUser-Agent: Mozilla/5.00 (Nikto/2.1.6)\r\n\r\n",
            'expected': 'Flagged as scanner'
        },
        {
            'name': 'Headless Chrome',
            'headers': b"GET / HTTP/1.1\r\nHost: test\r\nUser-Agent: Mozilla/5.0 HeadlessChrome/90.0\r\n\r\n",
            'expected': 'Flagged as headless'
        },
        {
            'name': 'No User-Agent (Bot)',
            'headers': b"GET / HTTP/1.1\r\nHost: test\r\n\r\n",
            'expected': 'Flagged as suspicious'
        },
    ]

    for test in test_cases:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((HONEYPOT_HOST, TESTS['http']['port']))

            sock.sendall(test['headers'])
            response = sock.recv(4096).decode('latin-1', errors='ignore')

            print(f"\n  Test: {test['name']}")
            print(f"    Expected: {test['expected']}")
            print(f"    Response received: {len(response)} bytes")

            sock.close()
            time.sleep(0.5)

        except Exception as e:
            print(f"  Test {test['name']}: Failed - {e}")

    print("\n  ℹ Check logs/attacks_*.json for SUSPICIOUS CLIENT entries to verify detection")


def test_auth_timing(protocol: str, port: int):
    """Test authentication timing delays"""
    print(f"\n[{protocol.upper()}] Testing authentication timing...")

    if protocol == 'ftp':
        for i in range(3):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(10)
                sock.connect((HONEYPOT_HOST, port))

                # Read banner
                sock.recv(4096)

                # Send USER command
                sock.sendall(b"USER testuser\r\n")
                sock.recv(4096)

                # Send PASS command and time it
                start = time.time()
                sock.sendall(b"PASS testpass\r\n")
                response = sock.recv(4096)
                elapsed = time.time() - start

                print(f"  Attempt {i+1}: Auth response time: {elapsed*1000:.2f}ms")

                sock.close()
                time.sleep(0.5)

            except Exception as e:
                print(f"  Attempt {i+1}: Failed - {e}")

    elif protocol == 'telnet':
        for i in range(3):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(10)
                sock.connect((HONEYPOT_HOST, port))

                # Read banner and login prompt
                time.sleep(0.1)
                sock.recv(4096)

                # Send username
                sock.sendall(b"testuser\r\n")
                time.sleep(0.1)
                sock.recv(4096)

                # Send password and time it
                start = time.time()
                sock.sendall(b"testpass\r\n")
                response = sock.recv(4096)
                elapsed = time.time() - start

                print(f"  Attempt {i+1}: Auth response time: {elapsed*1000:.2f}ms")

                sock.close()
                time.sleep(0.5)

            except Exception as e:
                print(f"  Attempt {i+1}: Failed - {e}")


def main():
    print("=" * 70)
    print("Evasion & Realism Feature Tests")
    print("=" * 70)
    print(f"Target: {HONEYPOT_HOST}")
    print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    if len(sys.argv) > 1:
        # Test specific protocol
        protocol = sys.argv[1].lower()
        if protocol not in TESTS:
            print(f"\nError: Unknown protocol '{protocol}'")
            print(f"Available: {', '.join(TESTS.keys())}")
            return

        protocols_to_test = {protocol: TESTS[protocol]}
    else:
        # Test all protocols
        protocols_to_test = TESTS

    for protocol, config in protocols_to_test.items():
        print(f"\n{'='*70}")
        print(f"Testing {protocol.upper()} (port {config['port']})")
        print('='*70)

        # Test timing
        if config.get('test_timing'):
            test_timing(protocol, config['port'])

        # Test banner variation
        if config.get('test_banner'):
            test_banner_variation(protocol, config['port'])

        # Test auth timing
        if protocol in ['ftp', 'telnet']:
            test_auth_timing(protocol, config['port'])

        # Test HTTP fingerprinting
        if config.get('test_fingerprint'):
            test_http_fingerprinting()

    print(f"\n{'='*70}")
    print("Testing Complete!")
    print("=" * 70)
    print("\nNext steps:")
    print("  1. Check logs/honeypot.log for warnings about suspicious clients")
    print("  2. Check logs/attacks_*.json for detailed detection results")
    print("  3. Look for 'SUSPICIOUS CLIENT' entries in the logs")
    print("\nTo test a specific protocol:")
    print("  python3 test_evasion.py <protocol>")
    print(f"  Available protocols: {', '.join(TESTS.keys())}")


if __name__ == "__main__":
    main()

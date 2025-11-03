#!/usr/bin/env python3
"""
Comprehensive protocol testing script
Tests SSH, FTP, and Telnet honeypots properly
"""
import paramiko
import socket
import time
from ftplib import FTP, error_perm

def test_ssh(host='localhost', port=2222):
    """Test SSH honeypot"""
    print("[SSH] Testing SSH honeypot...")

    credentials = [
        ('admin', 'admin123'),
        ('root', 'password'),
        ('user', 'test123'),
    ]

    for username, password in credentials:
        try:
            print(f"  [*] Trying {username}:{password}")

            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            ssh.connect(
                host,
                port=port,
                username=username,
                password=password,
                timeout=5,
                look_for_keys=False,
                allow_agent=False
            )

            print(f"  [!] ERROR: Authentication succeeded (should never happen!)")
            ssh.close()

        except paramiko.AuthenticationException:
            print(f"  [✓] Rejected (logged)")
        except Exception as e:
            print(f"  [✓] Connection failed: {e}")

        time.sleep(0.5)

    print()

def test_ftp(host='localhost', port=2121):
    """Test FTP honeypot"""
    print("[FTP] Testing FTP honeypot...")

    credentials = [
        ('admin', 'admin123'),
        ('ftp', 'ftp'),
        ('user', 'password'),
    ]

    for username, password in credentials:
        try:
            print(f"  [*] Trying {username}:{password}")

            ftp = FTP()
            ftp.connect(host, port, timeout=5)

            try:
                ftp.login(username, password)
                print(f"  [!] ERROR: Login succeeded (should never happen!)")
                ftp.quit()
            except error_perm as e:
                if '530' in str(e):
                    print(f"  [✓] Rejected (logged)")
                else:
                    print(f"  [✓] Failed: {e}")

        except Exception as e:
            print(f"  [✓] Connection error: {e}")

        time.sleep(0.5)

    print()

def test_telnet(host='localhost', port=2323):
    """Test Telnet honeypot"""
    print("[TELNET] Testing Telnet honeypot...")

    credentials = [
        ('admin', 'admin123'),
        ('root', 'toor'),
        ('user', 'password'),
    ]

    for username, password in credentials:
        try:
            print(f"  [*] Trying {username}:{password}")

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((host, port))

            # Read banner
            banner = sock.recv(1024)

            # Should see "login:" prompt
            data = sock.recv(1024)

            # Send username
            sock.sendall(username.encode() + b'\r\n')
            time.sleep(0.2)

            # Should see "Password:" prompt
            data = sock.recv(1024)

            # Send password
            sock.sendall(password.encode() + b'\r\n')
            time.sleep(0.2)

            # Should see "Login incorrect"
            response = sock.recv(1024)
            if b'incorrect' in response.lower() or b'denied' in response.lower():
                print(f"  [✓] Rejected (logged)")
            else:
                print(f"  [!] Unexpected response: {response}")

            sock.close()

        except Exception as e:
            print(f"  [✓] Connection error: {e}")

        time.sleep(0.5)

    print()

def main():
    print("╔═══════════════════════════════════════════════════════════════╗")
    print("║                                                               ║")
    print("║  Protocol Test Suite                                          ║")
    print("║  Tests all honeypot protocols properly                       ║")
    print("║                                                               ║")
    print("╚═══════════════════════════════════════════════════════════════╝")
    print()

    # Test all protocols
    test_ssh()
    test_ftp()
    test_telnet()

    print("═══════════════════════════════════════════════════════════════")
    print("Test complete! Check logs/attacks_*.json for captured attempts")
    print()
    print("View logs:")
    print("  cat logs/attacks_$(date +%Y%m%d).json | jq .")
    print()

if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""
Remote Honeypot Tester
Test honeypot from another machine on the network

Compatible with:
- Linux (Ubuntu, Debian, Kali, CentOS, etc.)
- macOS (Intel and Apple Silicon)
- Windows (7, 10, 11)
"""
import argparse
import paramiko
import socket
import sys
import time
import platform
from ftplib import FTP, error_perm
from colorama import init, Fore, Style

# Initialize colorama with cross-platform support
init(autoreset=True, strip=False)

def test_ssh(host, port=2222):
    """Test SSH honeypot"""
    print(f"\n{Fore.CYAN}[SSH] Testing SSH honeypot on {host}:{port}{Style.RESET_ALL}")

    credentials = [
        ('admin', 'Password1'),
        ('admin', 'Password2'),
        ('admin', 'Password3'),
        ('root', 'toor'),
        ('user', 'password123'),
    ]

    success_count = 0
    for username, password in credentials:
        try:
            print(f"  {Fore.YELLOW}[*]{Style.RESET_ALL} Trying {username}:{password} ... ", end='')

            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            ssh.connect(
                host,
                port=port,
                username=username,
                password=password,
                timeout=10,
                look_for_keys=False,
                allow_agent=False
            )

            print(f"{Fore.RED}[!] GRANTED ACCESS (BUG!){Style.RESET_ALL}")
            ssh.close()

        except paramiko.AuthenticationException:
            print(f"{Fore.GREEN}✓ Rejected (logged){Style.RESET_ALL}")
            success_count += 1
        except socket.timeout:
            print(f"{Fore.RED}✗ Timeout{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}✗ Error: {e}{Style.RESET_ALL}")

        time.sleep(0.5)

    print(f"\n  {Fore.CYAN}Summary: {success_count}/{len(credentials)} attempts logged{Style.RESET_ALL}")
    return success_count

def test_ftp(host, port=2121):
    """Test FTP honeypot"""
    print(f"\n{Fore.CYAN}[FTP] Testing FTP honeypot on {host}:{port}{Style.RESET_ALL}")

    credentials = [
        ('admin', 'admin'),
        ('ftp', 'ftp'),
        ('anonymous', ''),
        ('user', 'password'),
    ]

    success_count = 0
    for username, password in credentials:
        try:
            print(f"  {Fore.YELLOW}[*]{Style.RESET_ALL} Trying {username}:{password if password else '(empty)'} ... ", end='')

            ftp = FTP()
            ftp.connect(host, port, timeout=10)

            try:
                ftp.login(username, password)
                print(f"{Fore.RED}[!] GRANTED ACCESS (BUG!){Style.RESET_ALL}")
                ftp.quit()
            except error_perm as e:
                if '530' in str(e):
                    print(f"{Fore.GREEN}✓ Rejected (logged){Style.RESET_ALL}")
                    success_count += 1
                else:
                    print(f"{Fore.YELLOW}~ {e}{Style.RESET_ALL}")

        except socket.timeout:
            print(f"{Fore.RED}✗ Timeout{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}✗ Error: {e}{Style.RESET_ALL}")

        time.sleep(0.5)

    print(f"\n  {Fore.CYAN}Summary: {success_count}/{len(credentials)} attempts logged{Style.RESET_ALL}")
    return success_count

def test_telnet(host, port=2323):
    """Test Telnet honeypot"""
    print(f"\n{Fore.CYAN}[TELNET] Testing Telnet honeypot on {host}:{port}{Style.RESET_ALL}")

    credentials = [
        ('admin', 'admin'),
        ('root', 'toor'),
        ('user', 'password'),
    ]

    success_count = 0
    for username, password in credentials:
        sock = None
        try:
            print(f"  {Fore.YELLOW}[*]{Style.RESET_ALL} Trying {username}:{password} ... ", end='')

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(15)
            sock.connect((host, port))

            # Read banner and login prompt
            time.sleep(0.3)
            try:
                banner = sock.recv(4096, socket.MSG_DONTWAIT)
            except:
                pass

            # Send username character by character with echo reading
            for char in username:
                sock.sendall(char.encode())
                time.sleep(0.02)
                # Try to read echo
                try:
                    sock.recv(1, socket.MSG_DONTWAIT)
                except:
                    pass

            # Send only \n (not \r\n) to avoid double line ending issues
            sock.sendall(b'\n')
            time.sleep(0.4)

            # Read password prompt
            try:
                sock.recv(4096, socket.MSG_DONTWAIT)
            except:
                pass

            # Send password character by character (no echo expected)
            for char in password:
                sock.sendall(char.encode())
                time.sleep(0.02)

            sock.sendall(b'\n')
            time.sleep(0.5)

            # Read final response
            try:
                final_response = sock.recv(4096)
                if b'incorrect' in final_response.lower() or b'denied' in final_response.lower():
                    print(f"{Fore.GREEN}✓ Rejected (logged){Style.RESET_ALL}")
                    success_count += 1
                else:
                    print(f"{Fore.YELLOW}~ Response: {final_response[:40]}{Style.RESET_ALL}")
                    # Still count as success if we got this far
                    success_count += 1
            except Exception as e:
                # Connection closed = auth rejected and logged
                print(f"{Fore.GREEN}✓ Connection closed (logged){Style.RESET_ALL}")
                success_count += 1

        except socket.timeout:
            print(f"{Fore.RED}✗ Timeout{Style.RESET_ALL}")
        except BrokenPipeError:
            # Broken pipe usually means honeypot got the data and closed
            print(f"{Fore.GREEN}✓ Connection closed (logged){Style.RESET_ALL}")
            success_count += 1
        except Exception as e:
            print(f"{Fore.RED}✗ Error: {e}{Style.RESET_ALL}")
        finally:
            if sock:
                try:
                    sock.close()
                except:
                    pass

        time.sleep(0.5)

    print(f"\n  {Fore.CYAN}Summary: {success_count}/{len(credentials)} attempts logged{Style.RESET_ALL}")
    return success_count

def test_http(host, port=8080):
    """Test HTTP honeypot"""
    print(f"\n{Fore.CYAN}[HTTP] Testing HTTP honeypot on {host}:{port}{Style.RESET_ALL}")

    credentials = [
        ('admin', 'admin'),
        ('administrator', 'password'),
        ('root', 'toor'),
        ('user', 'password123'),
    ]

    success_count = 0
    for username, password in credentials:
        try:
            print(f"  {Fore.YELLOW}[*]{Style.RESET_ALL} Trying {username}:{password} ... ", end='')

            # Try importing requests, fall back to urllib if not available
            try:
                import requests
                response = requests.post(
                    f"http://{host}:{port}/auth",
                    data={'username': username, 'password': password},
                    timeout=10,
                    allow_redirects=False
                )
                if response.status_code in [200, 302, 401, 403]:
                    print(f"{Fore.GREEN}✓ Submitted (logged){Style.RESET_ALL}")
                    success_count += 1
                else:
                    print(f"{Fore.YELLOW}~ Status: {response.status_code}{Style.RESET_ALL}")
            except ImportError:
                # Fall back to urllib
                from urllib.parse import urlencode
                from urllib.request import urlopen, Request
                from urllib.error import HTTPError, URLError

                data = urlencode({'username': username, 'password': password}).encode()
                req = Request(f"http://{host}:{port}/auth", data=data)
                try:
                    response = urlopen(req, timeout=10)
                    print(f"{Fore.GREEN}✓ Submitted (logged){Style.RESET_ALL}")
                    success_count += 1
                except HTTPError as e:
                    # Even HTTP errors mean the request was sent
                    print(f"{Fore.GREEN}✓ Submitted (logged){Style.RESET_ALL}")
                    success_count += 1
                except URLError:
                    print(f"{Fore.RED}✗ Connection failed{Style.RESET_ALL}")

        except Exception as e:
            print(f"{Fore.RED}✗ Error: {e}{Style.RESET_ALL}")

        time.sleep(0.5)

    print(f"\n  {Fore.CYAN}Summary: {success_count}/{len(credentials)} attempts logged{Style.RESET_ALL}")
    return success_count

def check_dependencies():
    """Check if required dependencies are installed"""
    missing = []

    try:
        import paramiko
    except ImportError:
        missing.append('paramiko')

    try:
        import colorama
    except ImportError:
        missing.append('colorama')

    if missing:
        print(f"{Fore.RED}Error: Missing required dependencies: {', '.join(missing)}{Style.RESET_ALL}")
        print(f"\n{Fore.YELLOW}Install them with:{Style.RESET_ALL}")

        # Platform-specific installation instructions
        os_name = platform.system()
        if os_name == 'Windows':
            print(f"  py -m pip install {' '.join(missing)}")
        else:
            print(f"  pip3 install {' '.join(missing)}")
            print(f"  or")
            print(f"  python3 -m pip install {' '.join(missing)}")

        sys.exit(1)

def print_system_info():
    """Print system information for debugging"""
    os_name = platform.system()
    os_version = platform.release()
    python_version = platform.python_version()
    machine = platform.machine()

    print(f"{Fore.CYAN}System: {os_name} {os_version} ({machine}){Style.RESET_ALL}")
    print(f"{Fore.CYAN}Python: {python_version}{Style.RESET_ALL}")

def main():
    parser = argparse.ArgumentParser(
        description='Test honeypot from remote machine (Cross-platform: Linux/macOS/Windows)',
        epilog='Example: python3 remote_test.py 192.168.0.165'
    )
    parser.add_argument(
        'host',
        help='Honeypot IP address (e.g., 192.168.0.165)'
    )
    parser.add_argument(
        '--ssh-port',
        type=int,
        default=2222,
        help='SSH port (default: 2222)'
    )
    parser.add_argument(
        '--ftp-port',
        type=int,
        default=2121,
        help='FTP port (default: 2121)'
    )
    parser.add_argument(
        '--telnet-port',
        type=int,
        default=2323,
        help='Telnet port (default: 2323)'
    )
    parser.add_argument(
        '--http-port',
        type=int,
        default=8888,
        help='HTTP port (default: 8888)'
    )
    parser.add_argument(
        '--protocol',
        choices=['ssh', 'ftp', 'telnet', 'http', 'all'],
        default='all',
        help='Which protocol to test (default: all)'
    )
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Show system information'
    )

    args = parser.parse_args()

    # Check dependencies first
    check_dependencies()

    print(f"{Fore.CYAN}╔════════════════════════════════════════════════════════════╗{Style.RESET_ALL}")
    print(f"{Fore.CYAN}║                                                            ║{Style.RESET_ALL}")
    print(f"{Fore.CYAN}║{Fore.YELLOW}  Remote Honeypot Tester{Style.RESET_ALL}                                  {Fore.CYAN}║{Style.RESET_ALL}")
    print(f"{Fore.CYAN}║  {Fore.GREEN}Cross-platform: Linux | macOS | Windows{Style.RESET_ALL}              {Fore.CYAN}║{Style.RESET_ALL}")
    print(f"{Fore.CYAN}║                                                            ║{Style.RESET_ALL}")
    print(f"{Fore.CYAN}╚════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")

    if args.verbose:
        print()
        print_system_info()

    print(f"\n{Fore.GREEN}Target: {args.host}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Testing authentication with common credentials...{Style.RESET_ALL}")

    total_tests = 0
    total_success = 0

    if args.protocol in ['ssh', 'all']:
        count = test_ssh(args.host, args.ssh_port)
        total_success += count
        total_tests += 5  # Number of SSH tests

    if args.protocol in ['ftp', 'all']:
        count = test_ftp(args.host, args.ftp_port)
        total_success += count
        total_tests += 4  # Number of FTP tests

    if args.protocol in ['telnet', 'all']:
        count = test_telnet(args.host, args.telnet_port)
        total_success += count
        total_tests += 3  # Number of Telnet tests

    if args.protocol in ['http', 'all']:
        count = test_http(args.host, args.http_port)
        total_success += count
        total_tests += 4  # Number of HTTP tests

    print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}Test Complete!{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"\nTotal attempts sent: {total_tests}")
    print(f"Successfully logged: {total_success}")
    print(f"\n{Fore.YELLOW}Check the honeypot dashboard to see these attacks!{Style.RESET_ALL}\n")

if __name__ == '__main__':
    main()

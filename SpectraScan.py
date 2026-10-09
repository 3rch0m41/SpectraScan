"""
network_scanner - Simple TCP port, banner and vulnerability scanner.

DESCRIPTION
    Performs a basic reconnaissance of a single host in three phases:

      1. TCP connect scan over a user-supplied port range (inclusive).
      2. Banner grabbing on every open port found.
      3. Nmap scan with OS detection, service/version detection and the
         NSE "vuln" script category.

    Total elapsed time is printed at the end.

USAGE
    Command line:
        $ python network_scanner.py 192.168.1.10 -s 1 -e 1024
        $ python network_scanner.py --help

    Interactive (no arguments; you will be prompted):
        $ python network_scanner.py

    As a module:
        >>> from network_scanner import network_scan
        >>> network_scan("192.168.1.10", 1, 1024)

    Show this help:
        $ python -m pydoc network_scanner

REQUIREMENTS
    - Python 3.6+
    - Nmap installed and available in PATH
    - python-nmap        (pip install python-nmap)
    - Root/Administrator privileges for OS detection (-O)

NOTES
    - The port range is inclusive: both start and end ports are scanned.
    - The connect scan is sequential with a 1-second timeout per port,
      so closed or filtered ports can make large ranges slow
      (up to ~1 s per port).
    - The Nmap vuln scan runs against the target's default ports,
      not the range you entered, and can take several minutes.

LEGAL
    Scan only systems you own or are explicitly authorised to test.
    Unauthorised scanning may be illegal in your jurisdiction.
"""

import argparse
import socket
from datetime import datetime

import nmap


def port_scan(target, start_port, end_port):
    """
    Perform a TCP connect scan on a range of ports.

    Attempts a full TCP handshake on each port from start_port to end_port
    (both inclusive). A port is considered open if connect_ex() returns 0.

    Args:
        target (str): IP address or hostname to scan.
        start_port (int): First port to scan (inclusive).
        end_port (int): Last port to scan (inclusive).

    Returns:
        list[int]: Open port numbers, in ascending order.
                   Empty list if none are open.

    Example:
        >>> port_scan("127.0.0.1", 20, 80)
        [22, 80]
    """
    print(f"Scanning target: {target} for open ports from {start_port} to {end_port}...")
    open_ports = []
    for port in range(start_port, end_port + 1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target, port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    return open_ports


def banner_grab(target, port):
    """
    Read the service banner from an open TCP port.

    Connects to the port (2-second timeout for both connect and read) and
    reads up to 1024 bytes sent by the service. Works for services that
    greet the client first (e.g. SSH, FTP, SMTP); services that wait for
    client input (e.g. HTTP) usually return nothing.

    Args:
        target (str): IP address or hostname.
        port (int): TCP port to connect to.

    Returns:
        str | None: The banner decoded as UTF-8 (invalid bytes ignored) and
                    stripped of surrounding whitespace, or None if the
                    connection or read fails.

    Example:
        >>> banner_grab("127.0.0.1", 22)
        'SSH-2.0-OpenSSH_9.6'
    """
    print(f"Grabbing banner for {target}:{port}...")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(2)
            sock.connect((target, port))
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
        return banner.strip()
    except (OSError, socket.timeout):
        return None


def vulnerability_scan(target):
    """
    Run an Nmap OS, version and vulnerability scan on the target.

    Equivalent to:  nmap -O -sV --script=vuln <target>

    Args:
        target (str): IP address or hostname.

    Returns:
        nmap.PortScannerHostDict | None: The Nmap result for the host
            (keys such as 'hostnames', 'osmatch', 'tcp', ...), or None if
            the scan fails or the host is not in the results
            (e.g. host down, Nmap missing, insufficient privileges).

    Notes:
        -O requires root/Administrator privileges.
        NSE vuln script output is stored per port under
        result[protocol][port]['script'].
    """
    print(f"Performing vulnerability scan on {target}...")
    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=target, arguments='-O -sV --script=vuln')
        hosts = nm.all_hosts()
        if not hosts:
            print("Host did not respond to the Nmap scan.")
            return None
        # Nmap keys results by IP, so use the resolved host, not the hostname typed in.
        return nm[hosts[0]]
    except Exception as e:
        print(f"Error during vulnerability scan: {e}")
        return None


def print_vuln_results(vuln_info):
    """
    Print hostnames, OS matches and per-port NSE script output.

    Args:
        vuln_info (nmap.PortScannerHostDict): Result from vulnerability_scan().

    Returns:
        None. All output is printed.
    """
    hostnames = [h['name'] for h in vuln_info.get('hostnames', []) if h.get('name')]
    if hostnames:
        print(f"Hostnames: {', '.join(hostnames)}")

    os_matches = vuln_info.get('osmatch', [])
    if os_matches:
        print("Operating system guesses:")
        for match in os_matches[:3]:
            print(f"  - {match['name']} ({match['accuracy']}% accuracy)")
    else:
        print("Operating system: not detected (OS detection requires root).")

    found_any = False
    for proto in ('tcp', 'udp'):
        for port, info in sorted(vuln_info.get(proto, {}).items()):
            scripts = info.get('script')
            if not scripts:
                continue
            found_any = True
            service = f"{info.get('product', '')} {info.get('version', '')}".strip()
            print(f"\n[{proto}/{port}] {info.get('name', '')} {service}".rstrip())
            for script_name, output in scripts.items():
                print(f"  {script_name}:")
                for line in output.strip().splitlines():
                    print(f"    {line}")

    if not found_any:
        print("No vulnerability script output reported.")


def network_scan(target, start_port, end_port):
    """
    Run the full scan workflow and print results to stdout.

    Steps:
        1. port_scan() from start_port to end_port (inclusive)
        2. banner_grab() on every open port
        3. vulnerability_scan() on the host
        4. print_vuln_results() for hostnames, OS and NSE output
        5. Print total elapsed time

    Args:
        target (str): IP address or hostname.
        start_port (int): First port to scan (inclusive).
        end_port (int): Last port to scan (inclusive).

    Returns:
        None. All output is printed.
    """
    print(f"Starting network scan on {target}:")
    start_time = datetime.now()
    open_ports = port_scan(target, start_port, end_port)

    if open_ports:
        print(f"Open ports found: {open_ports}")
    else:
        print("No open ports found.")

    for port in open_ports:
        banner = banner_grab(target, port)
        if banner:
            print(f"Banner for {target}:{port} - {banner}")
        else:
            print(f"No banner found for port {port}.")

    vuln_info = vulnerability_scan(target)
    if vuln_info:
        print_vuln_results(vuln_info)
    else:
        print("Unable to retrieve vulnerability information.")

    end_time = datetime.now()
    print(f"Scan completed in {end_time - start_time}")


def valid_port(value):
    """argparse type: accept an integer between 1 and 65535."""
    port = int(value)
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError(f"{value} is not a valid port (1-65535)")
    return port


def parse_args():
    """
    Parse command-line arguments, prompting for any that are missing.

    Returns:
        argparse.Namespace: with attributes target, start, end.
    """
    parser = argparse.ArgumentParser(
        description="TCP port scan, banner grabbing and Nmap vulnerability scan "
                    "of a single host. Scan only systems you are authorised to test.",
        epilog="Example: python network_scanner.py 192.168.1.10 -s 1 -e 1024",
    )
    parser.add_argument("target", nargs="?",
                        help="IP address or hostname to scan (prompted if omitted)")
    parser.add_argument("-s", "--start", type=valid_port,
                        help="first port to scan, inclusive (prompted if omitted)")
    parser.add_argument("-e", "--end", type=valid_port,
                        help="last port to scan, inclusive (prompted if omitted)")
    args = parser.parse_args()

    try:
        if args.target is None:
            args.target = input("Enter the target IP address or hostname: ").strip()
        if args.start is None:
            args.start = valid_port(input("Enter the starting port number: "))
        if args.end is None:
            args.end = valid_port(input("Enter the ending port number: "))
    except (ValueError, argparse.ArgumentTypeError) as e:
        parser.error(f"invalid port: {e}")

    if args.start > args.end:
        parser.error("starting port must be less than or equal to ending port")
    return args


if __name__ == "__main__":
    try:
        args = parse_args()
        network_scan(args.target, args.start, args.end)
    except KeyboardInterrupt:
        print("\nScan interrupted by user.")
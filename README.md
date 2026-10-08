# Network Scanner

🇬🇧 **English** | 🇮🇹 [Italiano](README.it.md)

A Python network scanner that performs basic host reconnaissance in a single run: TCP port scanning, banner grabbing and vulnerability analysis with Nmap.

> ⚠️ **Disclaimer:** use this tool **only on systems you own or are explicitly authorised to test**. Unauthorised scanning of networks and hosts may be illegal. The author is not responsible for any misuse.

---

## Table of contents

- [How it works](#how-it-works)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Sample output](#sample-output)
- [Code structure](#code-structure)
- [Known limitations](#known-limitations)
- [Roadmap](#roadmap)
- [Author](#author)

---

## How it works

The scan runs in three consecutive phases.

**1. Port scan (TCP connect)**
For each port in the given range, the script attempts a full TCP handshake. If the connection succeeds, the port is marked as open. The range is inclusive: `-s 1 -e 1024` checks ports 1 through 1024.

**2. Banner grabbing**
On every open port, the script connects and reads the first bytes sent by the service. This works with services that greet the client first, such as SSH, FTP and SMTP, and helps identify the software and its version.

**3. Vulnerability scan (Nmap)**
Runs Nmap with OS detection (`-O`), service and version detection (`-sV`) and the NSE scripts in the `vuln` category. For each port it reports the detected service and the script output, along with OS guesses and their accuracy.

The total elapsed time is shown at the end.

## Requirements

- Python 3.6 or later
- [Nmap](https://nmap.org/download.html) installed and available in your `PATH`
- The [`python-nmap`](https://pypi.org/project/python-nmap/) library
- Root or Administrator privileges for OS detection (`-O`)

## Installation

```bash
git clone https://github.com/<your-username>/<repo-name>.git
cd <repo-name>
pip install python-nmap
```

Check that Nmap is installed:

```bash
nmap --version
```

## Usage

**Command line**

```bash
sudo python network_scanner.py 192.168.1.10 -s 1 -e 1024
```

| Argument | Description |
|---|---|
| `target` | IP address or hostname to scan |
| `-s`, `--start` | First port of the range (inclusive, 1–65535) |
| `-e`, `--end` | Last port of the range (inclusive, 1–65535) |
| `-h`, `--help` | Show the help message |

**Interactive mode**

If you run the script without arguments, it prompts for any missing parameters:

```bash
sudo python network_scanner.py
```

**As a module**

```python
from network_scanner import network_scan

network_scan("192.168.1.10", 1, 1024)
```

Full function documentation is available with:

```bash
python -m pydoc network_scanner
```

## Sample output

```text
Starting network scan on 192.168.1.10:
Scanning target: 192.168.1.10 for open ports from 1 to 1024...
Open ports found: [22, 80]
Grabbing banner for 192.168.1.10:22...
Banner for 192.168.1.10:22 - SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6
Grabbing banner for 192.168.1.10:80...
No banner found for port 80.
Performing vulnerability scan on 192.168.1.10...
Operating system guesses:
  - Linux 5.0 - 5.14 (98% accuracy)

[tcp/80] http Apache httpd 2.4.52
  http-csrf:
    Couldn't find any CSRF vulnerabilities.
  ...
Scan completed in 0:03:12.481920
```

*Output is illustrative and depends on the target.*

## Code structure

| Function | Purpose |
|---|---|
| `port_scan()` | TCP connect scan over the port range |
| `banner_grab()` | Reads a service's banner |
| `vulnerability_scan()` | Nmap scan with OS detection, `-sV` and `vuln` scripts |
| `print_vuln_results()` | Prints hostnames, operating system and NSE output |
| `network_scan()` | Orchestrates the three phases and measures elapsed time |
| `parse_args()` | Handles command-line arguments and interactive prompts |

## Known limitations

- **Slow port scan:** scanning is sequential with a 1-second timeout per port, so large ranges on filtered hosts can take a long time.
- **Ports scanned by Nmap:** the Nmap phase uses Nmap's default ports, not the range you specify, and can take several minutes.
- **Services without banners:** services that wait for a client request, such as HTTP, usually return no banner.
- **Supported protocols:** only IPv4 and TCP are supported.

---

## Roadmap

### ✅ v1.1 — Completed
- [x] Inclusive port range
- [x] Timeout applied to the banner-grabbing connection too
- [x] Correct per-port output of NSE `vuln` scripts
- [x] Hostname support in Nmap results
- [x] Command-line interface with `argparse`, with interactive fallback
- [x] Port validation and clean Ctrl+C interruption
- [x] Full code documentation through docstrings

### 🚧 v1.2 — Performance
- [ ] Concurrent port scan with `ThreadPoolExecutor` or `asyncio`
- [ ] Configurable timeout from the command line
- [ ] Nmap scan limited to the open ports found
- [ ] `--no-vuln` flag for fast reconnaissance without Nmap
- [ ] Startup check for Nmap and root privileges

### 🔜 v1.3 — Result quality
- [ ] Active probes for "silent" services, such as an HTTP `HEAD` request and the TLS banner on port 443
- [ ] Export results to JSON and CSV (`-o report.json`)
- [ ] Logging with verbosity levels (`-v`, `-vv`)

### 🔭 v2.0 — Wider scope
- [ ] Multiple targets: CIDR ranges and host files
- [ ] Host discovery phase
- [ ] IPv6 support
- [ ] Optional UDP scanning (`-sU`)
- [ ] Automated tests with `pytest`

Suggestions and bug reports are welcome through [Issues](../../issues).

---

## Author

**Giulio Malini** (*Erchomai*)

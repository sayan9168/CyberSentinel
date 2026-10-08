# CyberSentinel

### Advanced Multi-threaded Network Security Scanner

Port scanning · Service detection · Known vulnerability checks · Detailed reporting

[![Python](https://img.shields.io/badge/Python-3.6%2B-blue?logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![No Dependencies](https://img.shields.io/badge/Dependencies-None-brightgreen)](#)

> Pure standard-library Python tool for **authorized** network security assessments.

---

## ⚠️ Legal Disclaimer

This tool is intended **only** for:

- Systems you own
- Systems you have **explicit written authorization** to test
- Educational and defensive security research

Unauthorized scanning is illegal. The author assumes no liability for misuse.

---

## Features

| Feature | Description |
|---------|-------------|
| **Port Scanning** | TCP connect scan (1–65535) |
| **Service Detection** | Identify common services on open ports |
| **Vulnerability Checks** | Known CVEs (EternalBlue, BlueKeep, Log4j, etc.) |
| **Network Discovery** | Hostname / IP resolution |
| **Multi-threading** | Fast concurrent scanning |
| **Reporting** | JSON + text reports |
| **Color Output** | Easy-to-read terminal results |
| **Zero external deps** | Pure Python standard library |

---

## Requirements

- Python 3.6+
- No external packages required

---

## Quick Start

```bash
git clone https://github.com/sayan9168/CyberSentinel.git
cd CyberSentinel

python3 security_scanner.py --help
```

### Examples

```bash
# Basic scan
python3 security_scanner.py -t 192.168.1.1

# Specific port range
python3 security_scanner.py -t 192.168.1.1 -p 1-1000

# Specific ports
python3 security_scanner.py -t example.com -p 22,80,443

# Full port range
python3 security_scanner.py -t 192.168.1.1 --full

# Save report
python3 security_scanner.py -t 192.168.1.1 -o report.json

# Custom threads & timeout
python3 security_scanner.py -t 192.168.1.1 -T 200 --timeout 3
```

---

## Command Line Options

| Option | Description |
|--------|-------------|
| `-t, --target` | Target IP or hostname (**required**) |
| `-p, --ports` | Port range (default: `1-1024`) |
| `--full` | Scan all ports `1-65535` |
| `-T, --threads` | Number of threads (default: `100`) |
| `--timeout` | Socket timeout in seconds (default: `2`) |
| `-o, --output` | Save JSON report to file |
| `-v, --verbose` | Verbose output |

---

## Detected Vulnerabilities (examples)

- **CVE-2017-0144** — EternalBlue (SMB)
- **CVE-2020-0796** — SMBv3 Compression
- **CVE-2019-0708** — BlueKeep (RDP)
- **CVE-2021-44228** — Log4j
- **CVE-2015-3306** — ProFTPD mod_copy
- **CVE-2022-0543** — Redis Lua Sandbox Escape

---

## Author

[Sayan Mahata](https://github.com/sayan9168) (Sayan the researcher)

---

## License

MIT License — free for educational and authorized use.

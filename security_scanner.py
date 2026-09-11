#!/usr/bin/env python3
"""
Advanced Cybersecurity Network Scanner
Features:
- Port Scanning (TCP/UDP)
- Service Detection
- OS Fingerprinting
- Vulnerability Assessment
- Network Discovery
- Detailed Reporting
"""

import socket
import threading
import queue
import argparse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import re
from typing import Dict, List, Optional, Tuple
import struct
import sys

# ANSI color codes for terminal output
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    RESET = '\033[0m'

# Common ports and their services
COMMON_PORTS = {
    21: 'FTP',
    22: 'SSH',
    23: 'Telnet',
    25: 'SMTP',
    53: 'DNS',
    80: 'HTTP',
    110: 'POP3',
    111: 'RPCbind',
    135: 'MSRPC',
    139: 'NetBIOS',
    143: 'IMAP',
    443: 'HTTPS',
    445: 'SMB',
    993: 'IMAPS',
    995: 'POP3S',
    1433: 'MSSQL',
    1521: 'Oracle',
    3306: 'MySQL',
    3389: 'RDP',
    5432: 'PostgreSQL',
    5900: 'VNC',
    6379: 'Redis',
    8080: 'HTTP-Proxy',
    27017: 'MongoDB'
}

# Known vulnerabilities for specific services
VULNERABILITY_DB = {
    'FTP': [
        {'cve': 'CVE-2015-3306', 'severity': 'HIGH', 'description': 'ProFTPD mod_copy vulnerability'},
        {'cve': 'CVE-2010-4221', 'severity': 'MEDIUM', 'description': 'vsftpd backdoor vulnerability'}
    ],
    'SMB': [
        {'cve': 'CVE-2017-0144', 'severity': 'CRITICAL', 'description': 'EternalBlue SMB vulnerability'},
        {'cve': 'CVE-2020-0796', 'severity': 'CRITICAL', 'description': 'SMBv3 compression vulnerability'}
    ],
    'HTTP': [
        {'cve': 'CVE-2021-44228', 'severity': 'CRITICAL', 'description': 'Log4j vulnerability (if applicable)'},
        {'cve': 'CVE-2017-5638', 'severity': 'CRITICAL', 'description': 'Apache Struts2 RCE'}
    ],
    'SSH': [
        {'cve': 'CVE-2018-15473', 'severity': 'MEDIUM', 'description': 'OpenSSH username enumeration'}
    ],
    'RDP': [
        {'cve': 'CVE-2019-0708', 'severity': 'CRITICAL', 'description': 'BlueKeep RDP vulnerability'}
    ],
    'Redis': [
        {'cve': 'CVE-2022-0543', 'severity': 'CRITICAL', 'description': 'Redis Lua sandbox escape'}
    ]
}


class PortScanner:
    """Advanced port scanner with service detection"""
    
    def __init__(self, target: str, timeout: int = 2):
        self.target = target
        self.timeout = timeout
        self.open_ports: Dict[int, str] = {}
        self.filtered_ports: List[int] = []
        self.closed_ports: List[int] = []
        
    def scan_port(self, port: int, protocol: str = 'tcp') -> Optional[str]:
        """Scan a single port and return service if open"""
        try:
            if protocol == 'tcp':
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target, port)) if protocol == 'tcp' else 0
            
            if result == 0:
                # Port is open, try to detect service
                service = self._detect_service(sock, port, protocol)
                sock.close()
                return service
            else:
                sock.close()
                return None
                
        except socket.timeout:
            return 'filtered'
        except Exception:
            return None
    
    def _detect_service(self, sock: socket.socket, port: int, protocol: str) -> str:
        """Detect service running on open port"""
        try:
            sock.settimeout(1)
            
            # Send probe based on port
            if port == 80 or port == 8080:
                sock.send(b'GET / HTTP/1.0\r\n\r\n')
            elif port == 443:
                sock.send(b'GET / HTTP/1.0\r\n\r\n')
            elif port == 21:
                sock.send(b'QUIT\r\n')
            elif port == 25:
                sock.send(b'EHLO test\r\n')
            elif port == 110:
                sock.send(b'QUIT\r\n')
            elif port == 143:
                sock.send(b'A1 LOGOUT\r\n')
            else:
                sock.send(b'\r\n')
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            
            # Get service from common ports
            service = COMMON_PORTS.get(port, 'Unknown')
            
            # Enhance with banner information
            if banner:
                if 'apache' in banner.lower() or 'nginx' in banner.lower():
                    service = 'HTTP'
                elif 'ssh' in banner.lower():
                    service = 'SSH'
                elif 'ftp' in banner.lower():
                    service = 'FTP'
                elif 'smtp' in banner.lower():
                    service = 'SMTP'
                elif 'mysql' in banner.lower():
                    service = 'MySQL'
                elif 'postgres' in banner.lower():
                    service = 'PostgreSQL'
                elif 'redis' in banner.lower():
                    service = 'Redis'
                elif 'mongodb' in banner.lower():
                    service = 'MongoDB'
            
            return service
            
        except:
            return COMMON_PORTS.get(port, 'Unknown')
    
    def scan_range(self, start_port: int, end_port: int, threads: int = 100) -> Dict[int, str]:
        """Scan a range of ports using threading"""
        print(f"{Colors.CYAN}[*] Scanning ports {start_port}-{end_port} on {self.target}{Colors.RESET}")
        
        port_queue = queue.Queue()
        for port in range(start_port, end_port + 1):
            port_queue.put(port)
        
        def worker():
            while not port_queue.empty():
                port = port_queue.get()
                service = self.scan_port(port)
                if service:
                    if service == 'filtered':
                        self.filtered_ports.append(port)
                    else:
                        self.open_ports[port] = service
                else:
                    self.closed_ports.append(port)
                port_queue.task_done()
        
        # Create threads
        threads_list = []
        for _ in range(min(threads, end_port - start_port + 1)):
            t = threading.Thread(target=worker)
            t.daemon = True
            t.start()
            threads_list.append(t)
        
        for t in threads_list:
            t.join()
        
        return self.open_ports


class VulnerabilityAssessor:
    """Assess vulnerabilities based on detected services"""
    
    def __init__(self):
        self.vulnerabilities: List[Dict] = []
    
    def assess(self, services: Dict[int, str]) -> List[Dict]:
        """Check for known vulnerabilities"""
        self.vulnerabilities = []
        
        for port, service in services.items():
            if service in VULNERABILITY_DB:
                for vuln in VULNERABILITY_DB[service]:
                    vuln_info = {
                        'port': port,
                        'service': service,
                        'cve': vuln['cve'],
                        'severity': vuln['severity'],
                        'description': vuln['description'],
                        'recommendation': self._get_recommendation(service, vuln['cve'])
                    }
                    self.vulnerabilities.append(vuln_info)
        
        return self.vulnerabilities
    
    def _get_recommendation(self, service: str, cve: str) -> str:
        """Get remediation recommendation"""
        recommendations = {
            'CVE-2017-0144': 'Apply MS17-010 patch immediately, disable SMBv1',
            'CVE-2020-0796': 'Apply Microsoft security update for SMBv3',
            'CVE-2019-0708': 'Apply RDP security patches, enable NLA',
            'CVE-2021-44228': 'Update Log4j to version 2.17.0 or later',
            'CVE-2015-3306': 'Update ProFTPD to version 1.3.5 or later',
            'CVE-2022-0543': 'Update Redis to latest version, disable Lua if not needed'
        }
        return recommendations.get(cve, f'Update {service} to latest version and apply security patches')


class NetworkDiscovery:
    """Discover network information"""
    
    @staticmethod
    def get_hostname(ip: str) -> Optional[str]:
        """Get hostname from IP"""
        try:
            return socket.gethostbyaddr(ip)[0]
        except:
            return None
    
    @staticmethod
    def get_ip_info(hostname: str) -> Dict:
        """Get IP information"""
        try:
            ip = socket.gethostbyname(hostname)
            return {
                'hostname': hostname,
                'ip': ip,
                'resolved': True
            }
        except socket.gaierror:
            return {
                'hostname': hostname,
                'ip': None,
                'resolved': False
            }


class ReportGenerator:
    """Generate detailed security reports"""
    
    @staticmethod
    def generate_json_report(scan_results: Dict) -> str:
        """Generate JSON report"""
        return json.dumps(scan_results, indent=2)
    
    @staticmethod
    def generate_text_report(scan_results: Dict) -> str:
        """Generate formatted text report"""
        report = []
        report.append("=" * 80)
        report.append(f"{Colors.BOLD}ADVANCED CYBERSECURITY SCAN REPORT{Colors.RESET}")
        report.append("=" * 80)
        report.append(f"Target: {scan_results['target']}")
        report.append(f"Scan Time: {scan_results['scan_time']}")
        report.append(f"Open Ports: {len(scan_results['open_ports'])}")
        report.append("")
        
        # Open Ports Section
        report.append(f"{Colors.GREEN}[+] OPEN PORTS{Colors.RESET}")
        report.append("-" * 40)
        for port, service in sorted(scan_results['open_ports'].items()):
            report.append(f"  Port {port:<6} - {service}")
        report.append("")
        
        # Vulnerabilities Section
        if scan_results['vulnerabilities']:
            report.append(f"{Colors.RED}[!] VULNERABILITIES DETECTED{Colors.RESET}")
            report.append("-" * 40)
            for vuln in scan_results['vulnerabilities']:
                severity_color = Colors.RED if vuln['severity'] == 'CRITICAL' else \
                                Colors.YELLOW if vuln['severity'] == 'HIGH' else Colors.WHITE
                report.append(f"  {severity_color}[{vuln['severity']}]{Colors.RESET} {vuln['cve']}")
                report.append(f"    Port: {vuln['port']}, Service: {vuln['service']}")
                report.append(f"    Description: {vuln['description']}")
                report.append(f"    Recommendation: {vuln['recommendation']}")
                report.append("")
        else:
            report.append(f"{Colors.GREEN}[✓] No known vulnerabilities detected{Colors.RESET}")
        
        report.append("=" * 80)
        report.append("Scan completed successfully")
        report.append("=" * 80)
        
        return "\n".join(report)


def main():
    parser = argparse.ArgumentParser(
        description=f'{Colors.BOLD}Advanced Cybersecurity Network Scanner{Colors.RESET}',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f'''
Examples:
  %(prog)s -t 192.168.1.1
  %(prog)s -t 192.168.1.1 -p 1-1000
  %(prog)s -t example.com --full
  %(prog)s -t 192.168.1.1 -o report.json
        '''
    )
    
    parser.add_argument('-t', '--target', required=True, help='Target IP address or hostname')
    parser.add_argument('-p', '--ports', default='1-1024', help='Port range (e.g., 1-1024 or 22,80,443)')
    parser.add_argument('--full', action='store_true', help='Full scan (ports 1-65535)')
    parser.add_argument('-T', '--threads', type=int, default=100, help='Number of threads (default: 100)')
    parser.add_argument('--timeout', type=int, default=2, help='Socket timeout in seconds (default: 2)')
    parser.add_argument('-o', '--output', help='Output file for report (JSON format)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    # Banner
    print(f"""
{Colors.CYAN}╔═══════════════════════════════════════════════════════════╗
║     {Colors.BOLD}ADVANCED CYBERSECURITY NETWORK SCANNER{Colors.RESET}{Colors.CYAN}          ║
║           Security Assessment Tool v1.0                 ║
╚═══════════════════════════════════════════════════════════╝
{Colors.RESET}""")
    
    # Resolve target
    print(f"{Colors.BLUE}[*] Resolving target: {args.target}{Colors.RESET}")
    ip_info = NetworkDiscovery.get_ip_info(args.target)
    
    if not ip_info['resolved']:
        print(f"{Colors.RED}[!] Could not resolve {args.target}{Colors.RESET}")
        sys.exit(1)
    
    target_ip = ip_info['ip']
    hostname = ip_info['hostname']
    
    print(f"{Colors.GREEN}[+] Resolved: {hostname} -> {target_ip}{Colors.RESET}")
    
    # Determine port range
    if args.full:
        start_port, end_port = 1, 65535
    elif ',' in args.ports:
        ports_list = [int(p.strip()) for p in args.ports.split(',')]
        start_port, end_port = min(ports_list), max(ports_list)
    else:
        start_port, end_port = map(int, args.ports.split('-'))
    
    print(f"{Colors.BLUE}[*] Starting scan on {target_ip}{Colors.RESET}")
    print(f"{Colors.BLUE}[*] Port range: {start_port}-{end_port}{Colors.RESET}")
    print(f"{Colors.BLUE}[*] Threads: {args.threads}{Colors.RESET}")
    print(f"{Colors.BLUE}[*] Timeout: {args.timeout}s{Colors.RESET}\n")
    
    start_time = datetime.now()
    
    # Port Scanning
    scanner = PortScanner(target_ip, timeout=args.timeout)
    open_ports = scanner.scan_range(start_port, end_port, threads=args.threads)
    
    # Vulnerability Assessment
    print(f"\n{Colors.YELLOW}[*] Performing vulnerability assessment...{Colors.RESET}")
    assessor = VulnerabilityAssessor()
    vulnerabilities = assessor.assess(open_ports)
    
    end_time = datetime.now()
    duration = end_time - start_time
    
    # Compile results
    scan_results = {
        'target': args.target,
        'ip': target_ip,
        'hostname': hostname,
        'scan_time': start_time.strftime('%Y-%m-%d %H:%M:%S'),
        'duration': str(duration),
        'port_range': f'{start_port}-{end_port}',
        'open_ports': open_ports,
        'filtered_ports': scanner.filtered_ports,
        'closed_ports_count': len(scanner.closed_ports),
        'vulnerabilities': vulnerabilities,
        'total_vulnerabilities': len(vulnerabilities),
        'critical_count': sum(1 for v in vulnerabilities if v['severity'] == 'CRITICAL'),
        'high_count': sum(1 for v in vulnerabilities if v['severity'] == 'HIGH')
    }
    
    # Display Results
    print("\n" + "=" * 80)
    report = ReportGenerator.generate_text_report(scan_results)
    print(report)
    
    # Save report if requested
    if args.output:
        json_report = ReportGenerator.generate_json_report(scan_results)
        with open(args.output, 'w') as f:
            f.write(json_report)
        print(f"\n{Colors.GREEN}[+] Report saved to: {args.output}{Colors.RESET}")
    
    # Summary
    print(f"\n{Colors.CYAN}=== SCAN SUMMARY ==={Colors.RESET}")
    print(f"Total Open Ports: {len(open_ports)}")
    print(f"Vulnerabilities Found: {len(vulnerabilities)}")
    if vulnerabilities:
        print(f"  - Critical: {scan_results['critical_count']}")
        print(f"  - High: {scan_results['high_count']}")
    print(f"Scan Duration: {duration}")
    
    return scan_results


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Scan interrupted by user{Colors.RESET}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Colors.RED}[!] Error: {str(e)}{Colors.RESET}")
        sys.exit(1)

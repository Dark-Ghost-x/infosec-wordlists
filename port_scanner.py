#!/usr/bin/env python3
import socket
import requests
import threading
import time
import sys
import json
from datetime import datetime
import urllib3
import ssl
import re

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class AdvancedPortScanner:
    def __init__(self):
        self.port_list_url = "https://raw.githubusercontent.com/Dark-Ghost-x/infosec-wordlists/main/Port-list"
        self.common_ports = []
        self.open_ports = []
        self.vulnerability_results = []
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36'
        ]
        
    def print_logo(self):
        logo = """
\033[92m
╔═══╗────╔╗──╔═══╗
║╔═╗║───╔╝╚╗─║╔═╗║
║╚═╝╠══╦╩╗╔╝─║╚══╦══╦══╦═╗
║╔══╣╔╗║╔╣╠══╬══╗║╔═╣╔╗║╔╗╗
║║──║╚╝║║║╚╦═╣╚═╝║╚═╣╔╗║║║║
╚╝──╚══╩╝╚═╝─╚═══╩══╩╝╚╩╝╚╝
\033[0m
        """
        print(logo)
        print("\033[92mCreator>> t.me/Red_Rooted_Ghost\033[0m")
        print("═══════════════════════════════════════\n")
    
    def load_port_list(self):
        try:
            response = requests.get(self.port_list_url, timeout=10)
            ports = []
            for line in response.text.splitlines():
                line = line.strip()
                if line and ',' in line:
                    port_numbers = line.split(',')
                    for port_str in port_numbers:
                        port_str = port_str.strip()
                        if port_str.isdigit():
                            ports.append(int(port_str))
                elif line and line.isdigit():
                    ports.append(int(line))
            
            self.common_ports = sorted(set(ports))
            if not self.common_ports:
                self.common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 136, 137, 138, 139, 143, 161, 162, 389, 443, 445, 465, 513, 514, 515, 548, 587, 631, 636, 873, 993, 995, 1025, 1026, 1027, 1028, 1029, 1433, 1434, 1521, 1723, 2049, 2100, 3000, 3128, 3306, 3389, 5000, 5001]
            
            print(f"[+] Loaded {len(self.common_ports)} ports from wordlist")
            return True
        except Exception as e:
            print(f"[-] Failed to load port list: {e}")
            self.common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 136, 137, 138, 139, 143, 161, 162, 389, 443, 445, 465, 513, 514, 515, 548, 587, 631, 636, 873, 993, 995, 1025, 1026, 1027, 1028, 1029, 1433, 1434, 1521, 1723, 2049, 2100, 3000, 3128, 3306, 3389, 5000, 5001]
            print(f"[+] Using default {len(self.common_ports)} ports")
            return True
    
    def extract_domain_from_url(self, url):
        if url.startswith(('http://', 'https://')):
            domain = url.split('//')[1].split('/')[0]
            return domain
        return url
    
    def get_real_ip(self, target):
        try:
            if target.startswith(('http://', 'https://')):
                domain = self.extract_domain_from_url(target)
            else:
                domain = target
            
            print(f"[*] Resolving real IP for: {domain}")
            
            ip = socket.gethostbyname(domain)
            
            print(f"[+] Real IP address: {ip}")
            
            try:
                hostname = socket.gethostbyaddr(ip)[0]
                print(f"[+] Hostname: {hostname}")
            except:
                print(f"[+] Hostname: Not available")
            
            return ip
        except Exception as e:
            print(f"[-] Failed to resolve IP: {e}")
            return None
    
    def scan_port(self, target, port, timeout=2):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((target, port))
            sock.close()
            return result == 0
        except:
            return False
    
    def get_service_info(self, port):
        service_info = {
            21: "FTP",
            22: "SSH", 
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            81: "HTTP",
            82: "HTTP", 
            83: "HTTP",
            84: "HTTP",
            85: "HTTP",
            110: "POP3",
            135: "MSRPC",
            136: "NETBIOS",
            137: "NETBIOS",
            138: "NETBIOS", 
            139: "NETBIOS",
            143: "IMAP",
            161: "SNMP",
            162: "SNMP",
            389: "LDAP",
            443: "HTTPS",
            445: "SMB",
            465: "SMTPS",
            513: "rlogin",
            514: "syslog",
            515: "printer",
            548: "AFP",
            587: "SMTP",
            631: "IPP",
            636: "LDAPS",
            873: "rsync",
            993: "IMAPS",
            995: "POP3S",
            1025: "NFS",
            1026: "NFS",
            1027: "NFS",
            1028: "NFS",
            1029: "NFS",
            1433: "MSSQL",
            1434: "MSSQL",
            1521: "Oracle",
            1723: "PPTP",
            2049: "NFS",
            2100: "Oracle",
            3000: "Node.js",
            3128: "Proxy",
            3306: "MySQL",
            3389: "RDP",
            5000: "UPnP",
            5001: "Synology"
        }
        return service_info.get(port, "Unknown")
    
    def test_http_service(self, target, port):
        try:
            protocols = ['http', 'https']
            for protocol in protocols:
                try:
                    url = f"{protocol}://{target}:{port}"
                    headers = {'User-Agent': self.user_agents[0]}
                    response = requests.get(url, headers=headers, timeout=5, verify=False)
                    
                    vuln_indicators = []
                    risk_level = "Low"
                    
                    if response.status_code == 200:
                        server_header = response.headers.get('Server', '').lower()
                        powered_by = response.headers.get('X-Powered-By', '').lower()
                        
                        outdated_servers = ['apache/2.2', 'nginx/1.4', 'iis/7.0', 'iis/6.0']
                        for old_server in outdated_servers:
                            if old_server in server_header:
                                vuln_indicators.append(f"Outdated server: {old_server}")
                                risk_level = "Medium"
                                break
                        
                        outdated_php = ['php/5.2', 'php/5.3', 'php/5.4']
                        for php_ver in outdated_php:
                            if php_ver in powered_by:
                                vuln_indicators.append(f"Outdated PHP: {php_ver}")
                                risk_level = "High"
                                break
                        
                        if not vuln_indicators:
                            vuln_indicators.append("No obvious vulnerabilities detected")
                        
                        return {
                            'service': 'HTTP/HTTPS',
                            'protocol': protocol.upper(),
                            'banner': response.headers.get('Server', 'Unknown'),
                            'status_code': response.status_code,
                            'vulnerabilities': vuln_indicators,
                            'risk_level': risk_level
                        }
                        
                except:
                    continue
            return None
        except:
            return None
    
    def test_ftp_service(self, target, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((target, port))
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.close()
            
            vuln_indicators = []
            risk_level = "Low"
            
            banner_lower = banner.lower()
            if 'vsftpd' in banner_lower and '2.3.4' in banner:
                vuln_indicators.append("vsftpd 2.3.4 backdoor vulnerability")
                risk_level = "High"
            elif 'anonymous' in banner_lower:
                vuln_indicators.append("Anonymous FTP login allowed")
                risk_level = "Medium"
            else:
                vuln_indicators.append("No obvious vulnerabilities detected")
            
            return {
                'service': 'FTP',
                'banner': banner.strip(),
                'vulnerabilities': vuln_indicators,
                'risk_level': risk_level
            }
        except:
            return None
    
    def test_ssh_service(self, target, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((target, port))
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.close()
            
            vuln_indicators = []
            risk_level = "Low"
            
            if 'openssh' in banner.lower():
                outdated_versions = ['7.2', '7.1', '6.9', '6.8', '6.7', '6.6']
                for ver in outdated_versions:
                    if ver in banner:
                        vuln_indicators.append(f"Outdated OpenSSH version: {ver}")
                        risk_level = "Medium"
                        break
                if not vuln_indicators:
                    vuln_indicators.append("No obvious vulnerabilities detected")
            else:
                vuln_indicators.append("Unknown SSH implementation")
            
            return {
                'service': 'SSH',
                'banner': banner.strip(),
                'vulnerabilities': vuln_indicators,
                'risk_level': risk_level
            }
        except:
            return None
    
    def test_mysql_service(self, target, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((target, port))
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.close()
            
            vuln_indicators = []
            risk_level = "Low"
            
            if 'mysql' in banner.lower():
                outdated_versions = ['5.1', '5.0', '4.']
                for ver in outdated_versions:
                    if ver in banner:
                        vuln_indicators.append(f"Outdated MySQL version: {ver}")
                        risk_level = "High"
                        break
                if not vuln_indicators:
                    vuln_indicators.append("No obvious vulnerabilities detected")
            
            return {
                'service': 'MySQL',
                'banner': banner.strip(),
                'vulnerabilities': vuln_indicators,
                'risk_level': risk_level
            }
        except:
            return None
    
    def perform_vulnerability_scan(self, target, port):
        service_name = self.get_service_info(port)
        
        if service_name in ["HTTP", "HTTPS"]:
            return self.test_http_service(target, port)
        elif service_name == "FTP":
            return self.test_ftp_service(target, port)
        elif service_name == "SSH":
            return self.test_ssh_service(target, port)
        elif service_name == "MySQL":
            return self.test_mysql_service(target, port)
        else:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                sock.connect((target, port))
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
                sock.close()
                
                return {
                    'service': service_name,
                    'banner': banner.strip()[:100],
                    'vulnerabilities': ["Service detected - manual analysis required"],
                    'risk_level': "Unknown"
                }
            except:
                return {
                    'service': service_name,
                    'banner': 'Unable to retrieve',
                    'vulnerabilities': ["Service detected - no banner retrieved"],
                    'risk_level': "Unknown"
                }
    
    def scan_target(self, target, max_threads=50):
        print(f"[+] Starting port scan for: {target}")
        print(f"[*] Scanning {len(self.common_ports)} ports...")
        
        open_ports = []
        lock = threading.Lock()
        
        def worker(port):
            if self.scan_port(target, port):
                with lock:
                    open_ports.append(port)
                    service = self.get_service_info(port)
                    print(f"[!] Port {port}/tcp open - {service}")
        
        threads = []
        for port in self.common_ports:
            while threading.active_count() > max_threads:
                time.sleep(0.1)
            thread = threading.Thread(target=worker, args=(port,))
            thread.daemon = True
            thread.start()
            threads.append(thread)
        
        for thread in threads:
            thread.join()
        
        self.open_ports = sorted(open_ports)
        return self.open_ports
    
    def vulnerability_assessment(self, target):
        if not self.open_ports:
            return
            
        print(f"\n[*] Starting vulnerability assessment on {len(self.open_ports)} open ports...")
        
        for port in self.open_ports:
            print(f"[*] Testing port {port}...")
            result = self.perform_vulnerability_scan(target, port)
            if result:
                result['port'] = port
                self.vulnerability_results.append(result)
    
    def generate_report(self, target):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"port_scan_{target.replace('.', '_')}_{timestamp}.json"
        
        report = {
            'target': target,
            'scan_date': datetime.now().isoformat(),
            'open_ports': self.open_ports,
            'vulnerability_assessment': self.vulnerability_results,
            'summary': {
                'total_open_ports': len(self.open_ports),
                'high_risk_ports': len([r for r in self.vulnerability_results if r['risk_level'] == 'High']),
                'medium_risk_ports': len([r for r in self.vulnerability_results if r['risk_level'] == 'Medium']),
                'low_risk_ports': len([r for r in self.vulnerability_results if r['risk_level'] == 'Low'])
            }
        }
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        return filename
    
    def display_results(self):
        print("\n" + "="*80)
        print("SCAN RESULTS")
        print("="*80)
        
        if not self.open_ports:
            print("No open ports found")
            return
        
        print(f"\nOpen ports: {len(self.open_ports)}")
        for port in self.open_ports:
            service = self.get_service_info(port)
            print(f"  {port}/tcp - {service}")
        
        if self.vulnerability_results:
            print(f"\nVulnerability Assessment:")
            for result in self.vulnerability_results:
                color = "\033[92m" if result['risk_level'] == 'Low' else "\033[93m" if result['risk_level'] == 'Medium' else "\033[91m"
                print(f"\n{color}Port {result['port']} ({result['service']}) - Risk: {result['risk_level']}\033[0m")
                print(f"  Banner: {result.get('banner', 'N/A')}")
                print(f"  Vulnerabilities: {', '.join(result['vulnerabilities'])}")

def show_menu():
    print("\n" + "="*50)
    print("ADVANCED PORT SCANNER")
    print("="*50)
    print("1. Port Scan")
    print("2. Target IP Info")
    print("3. Exit")
    print("="*50)

def main():
    scanner = AdvancedPortScanner()
    scanner.print_logo()
    
    if not scanner.load_port_list():
        print("[-] Failed to load port list. Exiting...")
        sys.exit(1)
    
    while True:
        show_menu()
        choice = input("\nSelect option (1-3): ").strip()
        
        if choice == '1':
            target = input("Enter target (IP/URL): ").strip()
            if not target:
                print("[-] Please enter a valid target")
                continue
                
            start_time = time.time()
            
            if target.startswith(('http://', 'https://')):
                real_ip = scanner.get_real_ip(target)
                if real_ip:
                    target = real_ip
            
            open_ports = scanner.scan_target(target)
            
            if open_ports:
                scanner.vulnerability_assessment(target)
                filename = scanner.generate_report(target)
                scanner.display_results()
                print(f"\n[+] Results saved to: {filename}")
            else:
                print("[-] No open ports found")
            
            end_time = time.time()
            print(f"\n[*] Scan completed in {end_time - start_time:.2f} seconds")
            
        elif choice == '2':
            target = input("Enter website URL or domain: ").strip()
            if not target:
                print("[-] Please enter a valid target")
                continue
                
            scanner.get_real_ip(target)
            
        elif choice == '3':
            print("\n[+] Goodbye!")
            break
            
        else:
            print("[-] Invalid choice. Please select 1-3")

if __name__ == "__main__":
    main()

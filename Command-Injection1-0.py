#!/usr/bin/env python3
import requests
import urllib3
import time
import sys
import json
import random
from urllib.parse import urljoin, urlparse
from datetime import datetime
import os
import re
from bs4 import BeautifulSoup

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class AdvancedCmdInjectionTester:
    def __init__(self):
        self.payloads_url = "https://raw.githubusercontent.com/Dark-Ghost-x/infosec-wordlists/main/command-injection-payload.txt"
        self.params_url = "https://raw.githubusercontent.com/Dark-Ghost-x/infosec-wordlists/main/injectable-parameters.txt"
        self.payloads = []
        self.parameters = []
        self.vulnerable_urls = []
        self.results = []
        self.session = requests.Session()
        
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1'
        ]
        
    def print_logo(self):
        logo = """
╔═══╗────────────────╔╗╔══╗─────────╔╗
║╔═╗║────────────────║║╚╣╠╝──╔╗────╔╝╚╗
║║─╚╬══╦╗╔╦╗╔╦══╦═╗╔═╝║─║║╔═╗╚╬══╦═╩╗╔╬╦══╦═╗
║║─╔╣╔╗║╚╝║╚╝║╔╗║╔╗╣╔╗║─║║║╔╗╦╣║═╣╔═╣║╠╣╔╗║╔╗╗
║╚═╝║╚╝║║║║║║║╔╗║║║║╚╝║╔╣╠╣║║║║║═╣╚═╣╚╣║╚╝║║║║
╚═══╩══╩╩╩╩╩╩╩╝╚╩╝╚╩══╝╚══╩╝╚╣╠══╩══╩═╩╩══╩╝╚╝
────────────────────────────╔╝║
────────────────────────────╚═╝
        """
        print(logo)
        print("═══════════════════════════════════════")
        print("Created By Red telegram: t.me/Red_Rooted_Ghost")
        print("═══════════════════════════════════════\n")
    
    def animate_loading(self, text, duration=2):
        print(f"[*] {text}", end='', flush=True)
        for i in range(10):
            print('.', end='', flush=True)
            time.sleep(duration / 10)
        print()
    
    def load_wordlists(self):
        self.animate_loading("Loading payloads from GitHub", 3)
        try:
            response = requests.get(self.payloads_url, timeout=15)
            self.payloads = [line.strip() for line in response.text.splitlines() if line.strip() and not line.startswith('#')]
            print(f"[+] Loaded {len(self.payloads)} payloads")
        except Exception as e:
            print(f"[-] Failed to load payloads: {e}")
            return False
        
        self.animate_loading("Loading parameters from GitHub", 2)
        try:
            response = requests.get(self.params_url, timeout=15)
            self.parameters = [line.strip() for line in response.text.splitlines() if line.strip() and not line.startswith('#')]
            print(f"[+] Loaded {len(self.parameters)} parameters")
        except Exception as e:
            print(f"[-] Failed to load parameters: {e}")
            return False
        
        return True

    def extract_parameters_from_html(self, html_content):
        parameters = set()
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            
            for form in soup.find_all('form'):
                for input_tag in form.find_all('input'):
                    name = input_tag.get('name')
                    if name:
                        parameters.add(name)
                
                for select_tag in form.find_all('select'):
                    name = select_tag.get('name')
                    if name:
                        parameters.add(name)
                
                for textarea_tag in form.find_all('textarea'):
                    name = textarea_tag.get('name')
                    if name:
                        parameters.add(name)
            
            for a_tag in soup.find_all('a'):
                href = a_tag.get('href', '')
                if '?' in href:
                    query_string = href.split('?', 1)[1]
                    params = query_string.split('&')
                    for param in params:
                        if '=' in param:
                            parameters.add(param.split('=')[0])
            
            scripts = soup.find_all('script')
            for script in scripts:
                if script.string:
                    script_content = script.string
                    param_patterns = [
                        r'[\?&]([a-zA-Z0-9_\-]+)=',
                        r'\.get\(\s*["\']([^"\']+)["\']',
                        r'\.post\(\s*["\']([^"\']+)["\']',
                        r'param(?:eter)?s?\[["\']([^"\']+)["\']\]',
                        r'[\?&]([a-zA-Z0-9_\-]+)\s*:\s*'
                    ]
                    for pattern in param_patterns:
                        matches = re.findall(pattern, script_content)
                        parameters.update(matches)
            
        except Exception as e:
            pass
        
        return list(parameters)

    def set_random_headers(self):
        headers = {
            'User-Agent': random.choice(self.user_agents),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        }
        self.session.headers.update(headers)
    
    def is_firewall_blocked(self, response):
        firewall_indicators = [
            'cloudflare', 'incapsula', 'akamai', 'sucuri', 'barracuda',
            'fortinet', 'palo alto', 'check point', 'waf', 'web application firewall',
            'access denied', 'security violation', 'forbidden', 'blocked',
            '403', '406', '418', '429', '503'
        ]
        
        response_text = response.text.lower()
        headers_text = str(response.headers).lower()
        
        for indicator in firewall_indicators:
            if indicator in response_text or indicator in headers_text:
                return True
        
        if response.status_code in [403, 406, 418, 429, 503]:
            return True
            
        return False

    def analyze_response(self, response, payload, original_response=None):
        analysis = {
            'suspicious': False,
            'indicators': [],
            'confidence': 0,
            'os_detected': 'unknown',
            'injection_type': 'unknown',
            'is_firewall': False
        }
        
        if self.is_firewall_blocked(response):
            analysis['is_firewall'] = True
            analysis['confidence'] = 10
            return analysis
        
        text = response.text.lower()
        content_length = len(response.text)
        
        success_indicators = {
            'linux': ['root:', 'uid=', 'gid=', '/bin/', '/etc/passwd', 'linux', 'bash'],
            'windows': ['administrator', 'c:\\', 'program files', 'windows', 'cmd.exe'],
            'general': ['command not found', 'syntax error', 'permission denied', 'cannot', 'error']
        }
        
        for os_type, indicators in success_indicators.items():
            for indicator in indicators:
                if indicator in text:
                    analysis['suspicious'] = True
                    analysis['indicators'].append(indicator)
                    if os_type != 'general':
                        analysis['os_detected'] = os_type
                    analysis['confidence'] += 15
        
        if original_response:
            length_diff = abs(content_length - len(original_response.text))
            if length_diff > 500:
                analysis['suspicious'] = True
                analysis['indicators'].append('content_length_change')
                analysis['confidence'] += 25
            elif length_diff > 100:
                analysis['confidence'] += 10
        
        if content_length > 10000:
            analysis['suspicious'] = True
            analysis['indicators'].append('large_response')
            analysis['confidence'] += 20
        elif content_length > 5000:
            analysis['confidence'] += 10
        
        if response.status_code not in [200, 301, 302, 404]:
            analysis['suspicious'] = True
            analysis['indicators'].append(f'status_{response.status_code}')
            analysis['confidence'] += 5
        
        injection_patterns = {
            'pipe': '|',
            'semicolon': ';', 
            'ampersand': '&',
            'backtick': '`',
            'dollar': '$',
            'subshell': '$('
        }
        
        for inj_type, pattern in injection_patterns.items():
            if pattern in payload:
                analysis['injection_type'] = inj_type
                break
        
        return analysis
    
    def retest_suspicious_payload(self, url, param, payload, method, original_response, max_retests=3):
        results = []
        for i in range(max_retests):
            time.sleep(0.5)
            result = self.test_payload(url, param, payload, method, original_response)
            if result:
                results.append(result)
        
        if len(results) >= 2:
            confidence_sum = sum(r['analysis']['confidence'] for r in results)
            avg_confidence = confidence_sum / len(results)
            
            best_result = max(results, key=lambda x: x['analysis']['confidence'])
            best_result['analysis']['confidence'] = min(avg_confidence + 10, 95)
            best_result['retests'] = len(results)
            
            return best_result
        
        return None

    def test_payload(self, url, param, payload, method='GET', original_response=None):
        try:
            self.set_random_headers()
            
            test_data = {param: payload}
            timeout = 10
            
            if method.upper() == 'GET':
                response = self.session.get(url, params=test_data, timeout=timeout, verify=False, allow_redirects=True)
            else:
                response = self.session.post(url, data=test_data, timeout=timeout, verify=False, allow_redirects=True)
            
            analysis = self.analyze_response(response, payload, original_response)
            
            if analysis['suspicious'] and analysis['confidence'] > 30 and not analysis['is_firewall']:
                return {
                    'url': response.url if method == 'GET' else url,
                    'parameter': param,
                    'payload': payload,
                    'method': method,
                    'analysis': analysis,
                    'status_code': response.status_code,
                    'response_length': len(response.text),
                    'timestamp': datetime.now().isoformat()
                }
            
        except Exception as e:
            pass
        
        return None
    
    def smart_scan(self, target_url):
        print(f"\n[+] Target: {target_url}")
        
        try:
            response = self.session.get(target_url, timeout=10, verify=False)
            html_params = self.extract_parameters_from_html(response.text)
            all_params = list(set(self.parameters + html_params))
            original_response = response
        except:
            all_params = self.parameters
            original_response = None
        
        print(f"[+] Found {len(all_params)} parameters to test")
        
        vulnerabilities = []
        tested_payloads = min(50, len(self.payloads))
        total_tests = len(all_params) * tested_payloads * 2
        current_test = 0
        
        print(f"[*] Testing {total_tests} combinations...")
        
        for param in all_params:
            for payload in self.payloads[:tested_payloads]:
                current_test += 2
                
                progress = (current_test / total_tests) * 100
                print(f"[*] Progress: {progress:.1f}% ({current_test}/{total_tests})", end='\r')
                
                result_get = self.test_payload(target_url, param, payload, 'GET', original_response)
                if result_get and result_get['analysis']['confidence'] > 60:
                    retest_result = self.retest_suspicious_payload(target_url, param, payload, 'GET', original_response)
                    if retest_result:
                        vulnerabilities.append(retest_result)
                        print(f"\n[!] VULNERABLE - GET {param}")
                        print(f"    Confidence: {retest_result['analysis']['confidence']}%")
                        print(f"    OS: {retest_result['analysis']['os_detected']}")
                
                result_post = self.test_payload(target_url, param, payload, 'POST', original_response)
                if result_post and result_post['analysis']['confidence'] > 60:
                    retest_result = self.retest_suspicious_payload(target_url, param, payload, 'POST', original_response)
                    if retest_result:
                        vulnerabilities.append(retest_result)
                        print(f"\n[!] VULNERABLE - POST {param}")
                        print(f"    Confidence: {retest_result['analysis']['confidence']}%")
                        print(f"    OS: {retest_result['analysis']['os_detected']}")
        
        return vulnerabilities
    
    def save_results(self, vulnerabilities, target_url):
        domain = urlparse(target_url).netloc.replace(':', '_')
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"cmd_injection_{domain}_{timestamp}.json"
        
        results = {
            'target': target_url,
            'scan_date': datetime.now().isoformat(),
            'total_vulnerabilities': len(vulnerabilities),
            'vulnerabilities': vulnerabilities
        }
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        
        return filename
    
    def generate_report(self, vulnerabilities):
        if not vulnerabilities:
            print("\n[-] No vulnerabilities found")
            return
        
        print("\n" + "=" * 80)
        print("COMMAND INJECTION SCAN REPORT")
        print("=" * 80)
        
        for i, vuln in enumerate(vulnerabilities, 1):
            print(f"\n[{i}] VULNERABILITY FOUND:")
            print(f"   URL: {vuln['url']}")
            print(f"   Parameter: {vuln['parameter']}")
            print(f"   Payload: {vuln['payload']}")
            print(f"   Method: {vuln['method']}")
            print(f"   Confidence: {vuln['analysis']['confidence']}%")
            print(f"   OS: {vuln['analysis']['os_detected']}")
            print(f"   Type: {vuln['analysis']['injection_type']}")
            print(f"   Indicators: {', '.join(vuln['analysis']['indicators'])}")
            print(f"   Status Code: {vuln['status_code']}")
            print(f"   Response Length: {vuln['response_length']}")
            print("-" * 50)

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 cmd_injection.py <target_url>")
        print("Example: python3 cmd_injection.py http://example.com/search")
        sys.exit(1)
    
    target_url = sys.argv[1]
    
    tester = AdvancedCmdInjectionTester()
    tester.print_logo()
    
    if not tester.load_wordlists():
        print("[-] Failed to load wordlists. Exiting...")
        sys.exit(1)
    
    start_time = time.time()
    vulnerabilities = tester.smart_scan(target_url)
    end_time = time.time()
    
    if vulnerabilities:
        filename = tester.save_results(vulnerabilities, target_url)
        print(f"\n[+] Results saved to: {filename}")
    
    tester.generate_report(vulnerabilities)
    
    print(f"\n[*] Scan completed in {end_time - start_time:.2f} seconds")
    print(f"[+] Total vulnerabilities found: {len(vulnerabilities)}")

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Comprehensive Web Security Scanner

Features:
- Domain-based output folders
- Complete port scanning with Nmap
- Security header analysis
- Technology fingerprinting
- Common file exposure checks (robots.txt, .env, etc.)
- Detailed HTML reporting
- Error handling and fallback mechanisms
"""
import sys
import warnings
import os
import time
import socket
import argparse
import subprocess
import requests
import re
import json
from urllib.parse import urlparse, urljoin
from datetime import datetime, timezone
import html
import logging
import ssl
from http.cookies import SimpleCookie
import shutil

# Python version check for f-string compatibility
if sys.version_info < (3, 6):
    print("This script requires Python 3.6 or higher.")
    sys.exit(1)

warnings.filterwarnings("ignore", message="urllib3 v2 only supports OpenSSL 1.1.1+")

# Configuration
DEFAULT_TIMEOUT = 15
MAX_RETRIES = 3
RETRY_DELAY = 2
COMMON_PORTS = [
    21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 111, 123, 135, 137, 138, 139, 143, 161, 162, 179, 389, 443, 445, 465, 514,
    515, 587, 631, 636, 993, 995, 1025, 1433, 1521, 1723, 2049, 2082, 2083, 2086, 2087, 2095, 2096, 2181, 2222, 2375,
    2376, 2483, 2484, 3306, 3389, 3690, 4000, 4040, 4443, 4567, 5000, 5432, 5500, 5631, 5900, 5984, 6379, 6660, 6667,
    7001, 7002, 7071, 7443, 7777, 8000, 8008, 8080, 8081, 8083, 8086, 8088, 8090, 8443, 8888, 9000, 9043, 9080, 9090,
    9200, 9300, 9418, 9999, 11211, 27017, 27018, 27019, 28017
]
COMMON_FILES = ["robots.txt", ".env", ".git/config", "wp-config.php", "phpinfo.php"]
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"

# Suppress warnings
requests.packages.urllib3.disable_warnings()

logging.basicConfig(
    level=logging.INFO,
    format="[{levelname}] {message}",
    style="{",
    handlers=[logging.StreamHandler()]
)
class ScannerUtils:
    """Utility functions for the scanner"""

    @staticmethod
    def sanitize_filename(name: str) -> str:
        return "".join(c if c.isalnum() or c in ('-', '_') else '_' for c in name)

    @staticmethod
    def get_domain_from_url(url: str) -> str:
        parsed = urlparse(url)
        domain = parsed.netloc.split(':')[0]
        return domain

    @staticmethod
    def create_output_dir(target_url: str) -> str:
        domain = ScannerUtils.get_domain_from_url(target_url)
        dir_name = os.path.join("Results", domain)
        try:
            os.makedirs(dir_name, exist_ok=True)
            return dir_name
        except Exception as e:
            logging.error(f"Error creating output directory: {e}")
            return None

class TargetChecker:
    """Handles target validation and initial checks"""

    def __init__(self, target_url: str):
        self.target_url = target_url
        self.parsed_url = urlparse(target_url)
        if not self.parsed_url.scheme:
            self.target_url = f"https://{target_url}"
            self.parsed_url = urlparse(self.target_url)

    def check_site_availability(self) -> dict:
        """Check if target is reachable with retries"""
        results = {
            'url': self.target_url,
            'status': None,
            'error': None,
            'final_url': None,
            'response_time': None,
            'headers': {}
        }
        session = requests.Session()
        session.headers.update({'User-Agent': USER_AGENT})
        for attempt in range(MAX_RETRIES):
            try:
                start_time = time.time()
                response = session.get(
                    self.target_url,
                    timeout=DEFAULT_TIMEOUT,
                    allow_redirects=True,
                    verify=False
                )
                elapsed = time.time() - start_time
                results.update({
                    'status': response.status_code,
                    'final_url': response.url,
                    'response_time': f"{elapsed:.2f}s",
                    'headers': dict(response.headers)
                })
                break
            except requests.RequestException as e:
                results['error'] = str(e)
                if attempt < MAX_RETRIES - 1:
                    time.sleep(RETRY_DELAY)
        return results

    def get_host_info(self) -> dict:
        """Get IP address and hostname info"""
        hostname = self.parsed_url.hostname
        try:
            ip_addr = socket.gethostbyname(hostname)
            return {
                'hostname': hostname,
                'ip_address': ip_addr,
                'resolved': True
            }
        except socket.gaierror as e:
            return {
                'hostname': hostname,
                'ip_address': None,
                'resolved': False,
                'error': str(e)
            }

class PortScanner:
    """Handles port scanning operations"""

    def __init__(self, host: str, scan_all_ports: bool = False):
        self.host = host
        self.nmap_installed = self.is_tool_installed('nmap')
        self.scan_all_ports = scan_all_ports

    @staticmethod
    def is_tool_installed(name: str) -> bool:
        """Check if command-line tool is available"""
        # Use shutil.which for cross-platform compatibility
        return shutil.which(name) is not None

    def scan_with_nmap(self, output_file: str = None) -> dict:
        """Scan ports using nmap if available"""
        if not self.nmap_installed:
            return {"error": "nmap not installed", "method": "none"}
        cmd = [
            'nmap', '-sV', '-Pn', '-T4',
            '-oN', output_file if output_file else '-'
        ]
        if self.scan_all_ports:
            cmd.append('-p-')
        else:
            cmd.extend(['-p', ','.join(str(p) for p in COMMON_PORTS)])
        cmd.append(self.host)
        try:
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=300
            )
            output = {
                'success': result.returncode == 0,
                'output': result.stdout,
                'error': result.stderr,
                'method': 'nmap'
            }
            if output_file:
                with open(output_file, 'w') as f:
                    f.write(result.stdout)
            return output
        except subprocess.TimeoutExpired:
            return {"error": "nmap scan timed out", "method": "nmap"}
        except Exception as e:
            return {"error": str(e), "method": "nmap"}

    def quick_port_check(self) -> dict:
        """Quick port check using socket when nmap isn't available"""
        results = {}
        for port in COMMON_PORTS:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(5)
                result = sock.connect_ex((self.host, port))
                results[str(port)] = result == 0
        return {
            'success': True,
            'results': results,
            'method': 'socket'
        }

class FileChecker:
    """Checks for common exposed files"""

    def __init__(self, target_url: str):
        self.target_url = target_url
        self.base_url = self._normalize_url(target_url)

    def _normalize_url(self, url: str) -> str:
        """Ensure URL ends with / for proper path joining"""
        if not url.endswith('/'):
            url += '/'
        return url

    def check_common_files(self) -> dict:
        """Check for common exposed files"""
        results = {}
        for filename in COMMON_FILES:
            file_url = urljoin(self.base_url, filename)
            try:
                response = requests.get(
                    file_url,
                    timeout=DEFAULT_TIMEOUT,
                    allow_redirects=False,
                    verify=False,
                    headers={'User-Agent': USER_AGENT}
                )
                results[filename] = {
                    'exists': response.status_code == 200,
                    'status_code': response.status_code,
                    'url': file_url,
                    'content': response.text[:2000] if response.status_code == 200 else None
                }
            except requests.RequestException as e:
                results[filename] = {
                    'exists': False,
                    'error': str(e),
                    'url': file_url
                }
        return results

class SecurityHeaderAnalyzer:
    """Analyzes HTTP security headers"""

    @staticmethod
    def analyze(headers: dict) -> dict:
        """Check for important security headers (case-insensitive)"""
        important_headers = [
            "Content-Security-Policy",
            "Strict-Transport-Security",
            "X-Content-Type-Options",
            "X-Frame-Options",
            "X-XSS-Protection",
            "Referrer-Policy",
            "Permissions-Policy"
        ]
        lower_headers = {k.lower(): v for k, v in headers.items()}
        results = {}
        for header in important_headers:
            val = lower_headers.get(header.lower())
            results[header] = val if val is not None else "Missing"
        return results

class VulnerabilityDetector:
    """Detects technologies, CMS, and checks for known vulnerabilities"""

    NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    NVD_API_KEY = None  # Optional: Set your NVD API key here for higher rate limits

    @staticmethod
    def detect_technologies(headers: dict, html_content: str) -> dict:
        """Basic technology and CMS detection from headers and HTML"""
        tech = set()
        cms = None
        # Server header
        server = headers.get('Server') or headers.get('server')
        if server:
            tech.add(server)
        # X-Powered-By header
        powered = headers.get('X-Powered-By') or headers.get('x-powered-by')
        if powered:
            tech.add(powered)
        # HTML meta generator
        match = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', html_content, re.I)
        if match:
            gen = match.group(1)
            tech.add(gen)
            # Try to extract CMS name
            if "wordpress" in gen.lower():
                cms = "WordPress"
            elif "joomla" in gen.lower():
                cms = "Joomla"
            elif "drupal" in gen.lower():
                cms = "Drupal"
        # WordPress/Joomla/Drupal path hints
        if re.search(r'/wp-content/', html_content, re.I):
            cms = "WordPress"
        if re.search(r'/administrator/', html_content, re.I):
            cms = "Joomla"
        if re.search(r'/sites/default/', html_content, re.I):
            cms = "Drupal"
        return {"technologies": list(tech), "cms": cms}

    @staticmethod
    def check_cve(technologies: list) -> list:
        """Query NVD for CVEs related to detected technologies (top 1 per tech for demo)"""
        cve_results = []
        headers = {}
        if VulnerabilityDetector.NVD_API_KEY:
            headers['apiKey'] = VulnerabilityDetector.NVD_API_KEY
        for tech in technologies:
            params = {"keywordSearch": tech, "resultsPerPage": 1}
            try:
                resp = requests.get(VulnerabilityDetector.NVD_API_URL, params=params, headers=headers, timeout=10)
                if resp.status_code == 200:
                    data = resp.json()
                    for item in data.get("vulnerabilities", []):
                        cve = item.get("cve", {})
                        cve_id = cve.get("id")
                        desc = cve.get("descriptions", [{}])[0].get("value", "")
                        cve_results.append({"technology": tech, "cve_id": cve_id, "description": desc})
            except Exception as e:
                cve_results.append({"technology": tech, "error": str(e)})
        return cve_results

    @staticmethod
    def cms_checks(cms: str, html_content: str) -> dict:
        """Basic CMS checks for common misconfigurations or version leaks"""
        results = {}
        if cms == "WordPress":
            # Version detection
            match = re.search(r'content="WordPress\s*([0-9\.]+)"', html_content, re.I)
            if match:
                results["version"] = match.group(1)
            # Readme exposure
            if "readme.html" in html_content:
                results["readme_exposed"] = True
        elif cms == "Joomla":
            match = re.search(r'content="Joomla!\s*-\s*Open Source Content Management\s*([0-9\.]+)?"', html_content, re.I)
            if match:
                results["version"] = match.group(1)
            if "administrator/" in html_content:
                results["admin_panel_exposed"] = True
        elif cms == "Drupal":
            match = re.search(r'content="Drupal\s*([0-9\.]+)"', html_content, re.I)
            if match:
                results["version"] = match.group(1)
        return results

class VulnerabilityFuzzer:
    """Basic vulnerability fuzzing for XSS, SQLi, LFI on forms and parameters"""

    XSS_PAYLOAD = "<script>alert(1337)</script>"
    SQLI_PAYLOAD = "' OR '1'='1"
    LFI_PAYLOAD = "../../etc/passwd"

    @staticmethod
    def find_forms(html_content):
        """Extract forms and their inputs from HTML"""
        forms = []
        for form in re.findall(r'(<form.*?</form>)', html_content, re.I | re.S):
            action = re.search(r'action=["\']?([^"\'> ]+)', form, re.I)
            method = re.search(r'method=["\']?([^"\'> ]+)', form, re.I)
            inputs = re.findall(r'<input[^>]+name=["\']?([^"\'> ]+)', form, re.I)
            forms.append({
                'action': action.group(1) if action else '',
                'method': (method.group(1) if method else 'get').lower(),
                'inputs': inputs
            })
        return forms

    @staticmethod
    def fuzz_forms(base_url, forms):
        """Fuzz forms with payloads"""
        results = []
        session = requests.Session()
        session.headers.update({'User-Agent': USER_AGENT})
        for form in forms:
            url = urljoin(base_url, form['action'])
            for payload, label in [
                (VulnerabilityFuzzer.XSS_PAYLOAD, 'XSS'),
                (VulnerabilityFuzzer.SQLI_PAYLOAD, 'SQLi'),
                (VulnerabilityFuzzer.LFI_PAYLOAD, 'LFI')
            ]:
                data = {name: payload for name in form['inputs']}
                try:
                    if form['method'] == 'post':
                        resp = session.post(url, data=data, timeout=DEFAULT_TIMEOUT, verify=False)
                    else:
                        resp = session.get(url, params=data, timeout=DEFAULT_TIMEOUT, verify=False)
                    reflected = payload in resp.text
                    error = None
                    if label == 'SQLi' and re.search(r'sql|syntax|mysql|error|database', resp.text, re.I):
                        error = 'SQL error detected'
                    if label == 'LFI' and 'root:x:' in resp.text:
                        error = 'Possible LFI (passwd contents found)'
                    results.append({
                        'form_action': url,
                        'payload_type': label,
                        'reflected': reflected,
                        'error': error
                    })
                except Exception as e:
                    results.append({
                        'form_action': url,
                        'payload_type': label,
                        'reflected': False,
                        'error': str(e)
                    })
        return results

    @staticmethod
    def fuzz_url_params(base_url):
        """Fuzz GET parameters in the URL"""
        parsed = urlparse(base_url)
        if not parsed.query:
            return []
        params = dict([kv.split('=', 1) if '=' in kv else (kv, '') for kv in parsed.query.split('&')])
        results = []
        session = requests.Session()
        session.headers.update({'User-Agent': USER_AGENT})
        for payload, label in [
            (VulnerabilityFuzzer.XSS_PAYLOAD, 'XSS'),
            (VulnerabilityFuzzer.SQLI_PAYLOAD, 'SQLi'),
            (VulnerabilityFuzzer.LFI_PAYLOAD, 'LFI')
        ]:
            fuzzed_params = {k: payload for k in params}
            url = parsed._replace(query="&".join(f"{k}={payload}" for k in params)).geturl()
            try:
                resp = session.get(url, timeout=DEFAULT_TIMEOUT, verify=False)
                reflected = payload in resp.text
                error = None
                if label == 'SQLi' and re.search(r'sql|syntax|mysql|error|database', resp.text, re.I):
                    error = 'SQL error detected'
                if label == 'LFI' and 'root:x:' in resp.text:
                    error = 'Possible LFI (passwd contents found)'
                results.append({
                    'param_url': url,
                    'payload_type': label,
                    'reflected': reflected,
                    'error': error
                })
            except Exception as e:
                results.append({
                    'param_url': url,
                    'payload_type': label,
                    'reflected': False,
                    'error': str(e)
                })
        return results

    @staticmethod
    def run(base_url, html_content):
        """Run fuzzing on forms and URL params"""
        forms = VulnerabilityFuzzer.find_forms(html_content)
        form_results = VulnerabilityFuzzer.fuzz_forms(base_url, forms) if forms else []
        param_results = VulnerabilityFuzzer.fuzz_url_params(base_url)
        return {
            'forms': form_results,
            'params': param_results
        }

class SSLChecker:
    """Performs SSL/TLS security checks"""

    @staticmethod
    def check_ssl(hostname, port=443):
        """Check SSL certificate validity, expiration, and weak ciphers"""
        result = {
            'valid': False,
            'expired': None,
            'issuer': None,
            'subject': None,
            'notAfter': None,
            'weak_ciphers': [],
            'error': None
        }
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    result['issuer'] = dict(x[0] for x in cert.get('issuer', []))
                    result['subject'] = dict(x[0] for x in cert.get('subject', []))
                    result['notAfter'] = cert.get('notAfter')
                    # Expiry check
                    if cert.get('notAfter'):
                        exp = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
                        # Fix: Use timezone-aware UTC now to avoid DeprecationWarning
                        now_utc = datetime.now(timezone.utc)
                        exp_utc = exp.replace(tzinfo=timezone.utc)
                        result['expired'] = exp_utc < now_utc
                        result['valid'] = not result['expired']
                    else:
                        result['expired'] = None
                        result['valid'] = False
                    # Weak cipher check (basic)
                    cipher = ssock.cipher()
                    if cipher and (re.search(r'RC4|DES|3DES|NULL|EXPORT', cipher[0], re.I) or cipher[1] < 128):
                        result['weak_ciphers'].append(cipher[0])
        except Exception as e:
            result['error'] = str(e)
        return result

class CookieSecurityChecker:
    """Checks for Secure, HttpOnly, SameSite flags on cookies"""

    @staticmethod
    def analyze_cookies(headers):
        """Analyze Set-Cookie headers"""
        cookies = []
        set_cookie_headers = []
        for k, v in headers.items():
            if k.lower() == 'set-cookie':
                set_cookie_headers.append(v)
        # Handle multiple Set-Cookie headers (requests may combine them)
        if set_cookie_headers:
            for cookie_str in set_cookie_headers:
                for morsel in cookie_str.split(','):
                    try:
                        cookie = SimpleCookie()
                        cookie.load(morsel)
                        for key in cookie:
                            c = cookie[key]
                            cookies.append({
                                'name': key,
                                'secure': bool(c['secure']),
                                'httponly': bool(c['httponly']),
                                'samesite': c['samesite'] if 'samesite' in c else None,
                                'raw': morsel.strip()
                            })
                    except Exception:
                        continue
        return cookies

class ReportGenerator:
    """Generates comprehensive HTML reports"""

    @staticmethod
    def generate_html_report(scan_results: dict, output_dir: str) -> str:
        """Generate an HTML report from scan results"""
        domain = ScannerUtils.get_domain_from_url(scan_results['target_info']['url'])
        report_file = os.path.join(output_dir, f"security_report_{domain}.html")
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        target_info = scan_results['target_info']
        port_scan = scan_results['port_scan']
        security_headers = scan_results['security_headers']
        common_files = scan_results['common_files']
        vuln = scan_results.get("vulnerability_detection", {})
        fuzzing = scan_results.get("fuzzing", {})
        ssl_info = scan_results.get("ssl_info", {})
        cookie_info = scan_results.get("cookie_info", [])

        # Format common files results
        files_content = ""
        for filename, data in common_files.items():
            status = "FOUND" if data.get('exists') else "Not found"
            status_class = "found" if data.get('exists') else "not-found"
            content = f"<pre>{html.escape(data['content'])}</pre>" if data.get('content') else ""
            files_content += f"""
            <div class='file-result'>
                <h4>{html.escape(filename)} - <span class='{status_class}'>{status}</span></h4>
                {content}
            </div>
            """

        # Format security headers
        headers_content = ""
        for header, value in security_headers.items():
            status_class = "ok" if value != "Missing" else "warn"
            safe_value = html.escape(str(value)) if value != "Missing" else "Missing"
            headers_content += f"""
            <tr>
                <td>{html.escape(header)}</td>
                <td>{safe_value}</td>
                <td class='{status_class}'>{'Present' if value != 'Missing' else 'Missing'}</td>
            </tr>
            """

        # Vulnerability section HTML
        vuln_html = ""
        if vuln:
            techs = ", ".join(vuln.get("technologies", [])) or "None detected"
            cms = vuln.get("cms") or "None detected"
            cms_info = vuln.get("cms_info", {})
            cve_info = vuln.get("cve_info", [])
            vuln_html += f"""
            <div class='section'>
                <h2>Vulnerability Detection</h2>
                <h4>Detected Technologies</h4>
                <p>{html.escape(techs)}</p>
                <h4>Detected CMS</h4>
                <p>{html.escape(str(cms))}</p>
            """
            if cms_info:
                vuln_html += "<h4>CMS Info/Checks</h4><ul>"
                for k, v in cms_info.items():
                    vuln_html += f"<li>{html.escape(str(k))}: {html.escape(str(v))}</li>"
                vuln_html += "</ul>"
            if cve_info:
                vuln_html += "<h4>Known CVEs (from NVD)</h4><ul>"
                for cve in cve_info:
                    if "cve_id" in cve:
                        vuln_html += f"<li><b>{html.escape(cve['cve_id'])}</b>: {html.escape(cve['description'])}</li>"
                    elif "error" in cve:
                        vuln_html += f"<li>Error for {html.escape(cve['technology'])}: {html.escape(cve['error'])}</li>"
                vuln_html += '</ul>'
            vuln_html += '</div>'

        # Fuzzing section
        fuzz_html = ""
        if fuzzing:
            fuzz_html += "<div class='section'><h2>Basic Vulnerability Fuzzing</h2>"
            if fuzzing.get('forms'):
                fuzz_html += "<h4>Form Fuzzing Results</h4><ul>"
                for res in fuzzing['forms']:
                    fuzz_html += f"<li>Form: {html.escape(res.get('form_action',''))} | Type: {res['payload_type']} | Reflected: {res['reflected']} | Error: {html.escape(str(res['error'])) if res.get('error') else ''}</li>"
                fuzz_html += "</ul>"
            if fuzzing.get('params'):
                fuzz_html += "<h4>URL Parameter Fuzzing Results</h4><ul>"
                for res in fuzzing['params']:
                    fuzz_html += f"<li>URL: {html.escape(res.get('param_url',''))} | Type: {res['payload_type']} | Reflected: {res['reflected']} | Error: {html.escape(str(res['error'])) if res.get('error') else ''}</li>"
                fuzz_html += "</ul>"
            fuzz_html += "</div>"

        # SSL section
        ssl_html = ""
        if ssl_info:
            ssl_html += "<div class='section'><h2>SSL/TLS Security</h2><table>"
            for k in ['issuer', 'subject', 'notAfter', 'valid', 'expired', 'weak_ciphers', 'error']:
                v = ssl_info.get(k)
                if isinstance(v, dict):
                    v = json.dumps(v)
                elif isinstance(v, list):
                    v = ", ".join(v)
                ssl_html += f"<tr><th>{html.escape(str(k))}</th><td>{html.escape(str(v))}</td></tr>"
            ssl_html += "</table></div>"

        # Cookie section
        cookie_html = ""
        if cookie_info:
            cookie_html += "<div class='section'><h2>Cookie and Session Security</h2><table><tr><th>Name</th><th>Secure</th><th>HttpOnly</th><th>SameSite</th><th>Raw</th></tr>"
            for c in cookie_info:
                cookie_html += f"<tr><td>{html.escape(c['name'])}</td><td>{c['secure']}</td><td>{c['httponly']}</td><td>{html.escape(str(c['samesite']))}</td><td>{html.escape(c['raw'])}</td></tr>"
            cookie_html += "</table></div>"
        html_report = f"""<!DOCTYPE html>
<html>
<head>
    <title>Security Scan Report - {domain}</title>
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; padding: 20px; max-width: 1200px; margin: 0 auto; }}
        h1 {{ color: #2c3e50; }}
        h2 {{ color: #34495e; border-bottom: 1px solid #eee; padding-bottom: 10px; }}
        pre {{ background: #f5f5f5; padding: 10px; overflow-x: auto; max-height: 300px; }}
        .found {{ color: #27ae60; font-weight: bold; }}
        .not-found {{ color: #7f8c8d; }}
        .error {{ color: #e74c3c; }}
        .ok {{ color: #27ae60; }}
        .warn {{ color: #f39c12; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background-color: #f8f9fa; }}
        .section {{ margin-bottom: 40px; }}
        .file-result {{ margin-bottom: 20px; }}
        .summary {{ background: #f8f9fa; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
    </style>
</head>
<body>
    <h1>Security Scan Report for {html.escape(domain)}</h1>
    <p class='summary'>Done on: {timestamp}</p>
    <div class='section'>
        <h2>Target Information</h2>
        <table>
            <tr><th>URL</th><td>{html.escape(str(target_info.get('url', 'N/A')))}</td></tr>
            <tr><th>Final URL</th><td>{html.escape(str(target_info.get('final_url', 'N/A')))}</td></tr>
            <tr><th>Hostname</th><td>{html.escape(str(target_info.get('hostname', 'N/A')))}</td></tr>
            <tr><th>IP Address</th><td>{html.escape(str(target_info.get('ip_address', 'N/A')))}</td></tr>
            <tr><th>Resolved</th><td>{html.escape(str(target_info.get('resolved', 'N/A')))}</td></tr>
            <tr><th>Status Code</th><td>{html.escape(str(target_info.get('status', 'N/A')))}</td></tr>
            <tr><th>Response Time</th><td>{html.escape(str(target_info.get('response_time', 'N/A')))}</td></tr>
            <tr><th>Error</th><td>{html.escape(str(target_info.get('error', '')))}</td></tr>
        </table>
    </div>
    <div class='section'>
        <h2>Port Scan Results</h2>
        <p><em>Method: {html.escape(str(port_scan.get('method', 'N/A')))}</em></p>
        <pre>{html.escape(str(port_scan.get('output', 'No port scan results available')))}</pre>
        {f"<p class='error'>Error: {html.escape(str(port_scan['error']))}</p>" if port_scan.get('error') else ""}
    </div>
    <div class='section'>
        <h2>Security Headers</h2>
        <table>
            <tr><th>Header</th><th>Value</th><th>Status</th></tr>
            {headers_content}
        </table>
    </div>
    <div class='section'>
        <h2>Common Files Check</h2>
        {files_content}
    </div>
    {fuzz_html}
    {ssl_html}
    {cookie_html}
    {vuln_html}
</body>
</html>"""

        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(html_report)
        return report_file

class WebSecurityScanner:
    """Main scanner class that orchestrates all checks"""

    def __init__(self, target_url: str, scan_all_ports: bool = False):
        self.target_url = target_url
        self.target_checker = TargetChecker(target_url)
        self.output_dir = None
        self.scan_all_ports = scan_all_ports
        self.results = {
            'target_info': {},
            'port_scan': {},
            'security_headers': {},
            'common_files': {}
        }
        self.vuln_results = {}
        self.fuzzing_results = {}
        self.ssl_info = {}
        self.cookie_info = []

    def setup_output_directory(self) -> bool:
        """Prepare output directory for scan results"""
        self.output_dir = ScannerUtils.create_output_dir(self.target_url)
        if not self.output_dir:
            logging.error("Error: Could not create output directory")
            return False
        logging.info(f"Output directory: {os.path.abspath(self.output_dir)}")
        return True

    def run_all_checks(self) -> dict:
        """Execute all security checks"""
        logging.info("[1/5] Checking target availability...")
        target_info = self.target_checker.check_site_availability()
        host_info = self.target_checker.get_host_info()
        merged_info = {**target_info, **host_info}
        if 'error' in target_info and target_info['error']:
            merged_info['error'] = target_info['error']
        self.results['target_info'] = merged_info

        logging.info("[2/5] Running port scan...")
        port_scanner = PortScanner(self.target_checker.parsed_url.hostname, scan_all_ports=self.scan_all_ports)
        port_scan_file = os.path.join(self.output_dir, 'port_scan.txt')
        port_results = port_scanner.scan_with_nmap(output_file=port_scan_file)
        if port_results.get('error') and 'not installed' in port_results['error']:
            logging.warning("Nmap not available, falling back to basic port check")
            port_results = port_scanner.quick_port_check()
        self.results['port_scan'] = port_results

        logging.info("[3/5] Checking security headers...")
        self.results['security_headers'] = SecurityHeaderAnalyzer.analyze(
            self.results['target_info'].get('headers', {})
        )

        logging.info("[4/5] Checking for common files...")
        file_checker = FileChecker(self.target_url)
        self.results['common_files'] = file_checker.check_common_files()

        logging.info("[4.5/6] Basic Vulnerability Fuzzing...")
        homepage_path = os.path.join(self.output_dir, "homepage.html")
        html_content = ""
        if os.path.exists(homepage_path):
            with open(homepage_path, "r", encoding="utf-8") as f:
                html_content = f.read()
        else:
            # Try to fetch homepage if not saved
            try:
                resp = requests.get(self.target_url, timeout=DEFAULT_TIMEOUT, verify=False, headers={'User-Agent': USER_AGENT})
                html_content = resp.text
            except Exception:
                html_content = ""
        self.fuzzing_results = VulnerabilityFuzzer.run(self.target_url, html_content)
        self.results['fuzzing'] = self.fuzzing_results

        # === SSL/TLS Checks (Part 5) ===
        logging.info("[5/6] SSL/TLS Security Checks...")
        hostname = self.target_checker.parsed_url.hostname
        self.ssl_info = SSLChecker.check_ssl(hostname)
        self.results['ssl_info'] = self.ssl_info

        # === Cookie Security (Part 6) ===
        logging.info("[5.5/6] Cookie and Session Security Checks...")
        headers = self.results['target_info'].get('headers', {})
        self.cookie_info = CookieSecurityChecker.analyze_cookies(headers)
        self.results['cookie_info'] = self.cookie_info

        # === Vulnerability Detection (Part 6) ===
        logging.info("[6/6] Vulnerability Detection: Technology & CVE checks...")
        homepage_path = os.path.join(self.output_dir, "homepage.html")
        html_content = ""
        if os.path.exists(homepage_path):
            with open(homepage_path, "r", encoding="utf-8") as f:
                html_content = f.read()
        headers = self.results['target_info'].get('headers', {})
        tech_info = VulnerabilityDetector.detect_technologies(headers, html_content)
        cve_info = VulnerabilityDetector.check_cve(tech_info.get("technologies", []))
        cms_info = VulnerabilityDetector.cms_checks(tech_info.get("cms"), html_content) if tech_info.get("cms") else {}
        self.vuln_results = {
            "technologies": tech_info.get("technologies", []),
            "cms": tech_info.get("cms"),
            "cms_info": cms_info,
            "cve_info": cve_info
        }
        self.results["vulnerability_detection"] = self.vuln_results

        logging.info("Generating report...")
        report_path = ReportGenerator.generate_html_report(
            self.results,
            self.output_dir
        )
        if report_path:
            logging.info(f"Report generated: {report_path}")
        else:
            logging.error("Failed to generate report")
        return self.results

def main():
    """Main entry point for the scanner"""
    parser = argparse.ArgumentParser(
        description='Comprehensive Web Security Scanner',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument(
        '--target', '-t',
        required=True,
        help='Target URL to scan (e.g., https://example.com)'
    )
    args = parser.parse_args()

    # Print banner first with "by daradkeh" at the end of the last line
    print("\n" + "=" * 80)
    print(" WEB SECURITY SCANNER ".center(80, "="))
    print("=" * 69 + "by daradkeh")

    # Then prompt for scan_all_ports
    scan_all_ports = False
    try:
        user_input = input("Do you want to scan all ports with nmap (-p-)? (y/N): ").strip().lower()
        if user_input == 'y' or user_input == 'yes':
            scan_all_ports = True
    except Exception:
        pass

    scanner = WebSecurityScanner(args.target, scan_all_ports=scan_all_ports)
    if not scanner.setup_output_directory():
        return
    try:
        start_time = time.time()
        scanner.run_all_checks()
        elapsed = time.time() - start_time
        logging.info(f"Scan completed in {elapsed:.2f} seconds!")
    except KeyboardInterrupt:
        logging.warning("Scan interrupted by user")
    except Exception as e:
        logging.error(f"Error during scan: {str(e)}")

if __name__ == "__main__":
    main()
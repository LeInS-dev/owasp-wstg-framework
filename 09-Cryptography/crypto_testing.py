#!/usr/bin/env python3
"""
OWASP WSTG Cryptography Testing Framework
WSTG-CRYP-001 through WSTG-CRYP-011
"""

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'core'))

from base_tester import BaseTester
from utils import generate_report, save_findings, analyze_crypto
import requests
import json
import time
import hashlib
import base64
import re
from urllib.parse import urljoin, urlparse, parse_qs

class CryptographyTester(BaseTester):
    """Cryptography Security Testing"""

    def __init__(self, target_url):
        super().__init__()
        self.target_url = target_url
        self.session = requests.Session()
        self.findings = []
        self.crypto_results = {}

    def test_weak_transport_encryption(self):
        """WSTG-CRYP-001 - Test for Weak Transport Layer Security"""
        print("[*] Testing Transport Layer Security...")

        try:
            # Test HTTPS availability
            https_url = self.target_url.replace('http://', 'https://')
            transport_issues = []

            try:
                https_response = self.session.get(https_url, timeout=10, verify=False)
                if https_response.status_code == 200:
                    # Check certificate details
                    cert_info = self._analyze_certificate(https_response)
                    transport_issues.append({
                        'type': 'HTTPS Available',
                        'certificate': cert_info,
                        'https_working': True
                    })
                else:
                    transport_issues.append({
                        'type': 'HTTPS Unavailable',
                        'status_code': https_response.status_code,
                        'https_working': False
                    })
            except Exception as e:
                transport_issues.append({
                    'type': 'HTTPS Configuration Error',
                    'error': str(e),
                    'https_working': False
                })

            # Test HTTP to HTTPS redirection
            if self.target_url.startswith('http://'):
                try:
                    http_response = self.session.get(self.target_url, timeout=10, allow_redirects=False)
                    if http_response.status_code in [301, 302, 307, 308]:
                        redirect_url = http_response.headers.get('location', '')
                        if redirect_url.startswith('https://'):
                            transport_issues.append({
                                'type': 'HTTP to HTTPS Redirect',
                                'redirect_to': redirect_url,
                                'proper_redirect': True
                            })
                        else:
                            transport_issues.append({
                                'type': 'Insecure Redirect',
                                'redirect_to': redirect_url,
                                'proper_redirect': False
                            })
                    else:
                        transport_issues.append({
                            'type': 'No HTTPS Redirect',
                            'status_code': http_response.status_code,
                            'proper_redirect': False
                        })
                except Exception as e:
                    pass

            findings = {
                'test_id': 'WSTG-CRYP-001',
                'test_name': 'Transport Layer Security Testing',
                'description': 'Testing for weak transport layer security',
                'transport_issues': transport_issues,
                'https_available': any(issue.get('https_working', False) for issue in transport_issues),
                'risk_level': 'High' if not any(issue.get('https_working', False) for issue in transport_issues) else 'Low',
                'recommendations': [
                    'Implement HTTPS for all communications',
                    'Configure proper SSL/TLS certificates',
                    'Redirect all HTTP traffic to HTTPS',
                    'Use strong cipher suites (TLS 1.2+)',
                    'Implement HSTS headers'
                ]
            }

            self.findings.append(findings)
            return findings

        except Exception as e:
            print(f"[*] Error testing transport encryption: {e}")
            return None

    def test_weak_cryptography_implementation(self):
        """WSTG-CRYP-002 - Test for Weak Cryptographic Implementation"""
        print("[*] Testing Cryptographic Implementation...")

        try:
            crypto_vulnerabilities = []

            # Analyze response for cryptographic artifacts
            response = self.session.get(self.target_url, timeout=10)

            # Look for potential cryptographic algorithms
            crypto_patterns = {
                'md5': re.compile(r'[a-f0-9]{32}', re.IGNORECASE),
                'sha1': re.compile(r'[a-f0-9]{40}', re.IGNORECASE),
                'base64': re.compile(r'[A-Za-z0-9+/]{20,}={0,2}'),
                'hex_encoded': re.compile(r'[a-f0-9]{64,}'),
                'potential_jwt': re.compile(r'[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+')
            }

            matches = {}
            for algorithm, pattern in crypto_patterns.items():
                found = pattern.findall(response.text)
                if found:
                    matches[algorithm] = found[:5]  # Limit to first 5 matches

            if matches:
                crypto_vulnerabilities.append({
                    'type': 'Weak Hash Algorithm Detected',
                    'algorithms': list(matches.keys()),
                    'samples': matches,
                    'risk_level': 'Medium'
                })

            # Check for weak padding oracle patterns
            if 'base64' in matches:
                crypto_vulnerabilities.append({
                    'type': 'Potential Base64 Encoding',
                    'description': 'Base64 encoded data detected, verify if sensitive data is properly encrypted',
                    'samples': matches['base64'][:3],
                    'risk_level': 'Low'
                })

            # Check for session cookies
            cookies = response.cookies
            weak_cookies = []
            for cookie in cookies:
                if any(keyword in cookie.name.lower() for keyword in ['session', 'token', 'auth']):
                    # Check if cookie value appears to be weak
                    if len(cookie.value) < 20 or cookie.value.isdigit() or cookie.value.isalpha():
                        weak_cookies.append({
                            'name': cookie.name,
                            'value_length': len(cookie.value),
                            'predictable': cookie.value.isdigit() or cookie.value.isalpha()
                        })

            if weak_cookies:
                crypto_vulnerabilities.append({
                    'type': 'Weak Session Tokens',
                    'cookies': weak_cookies,
                    'risk_level': 'High'
                })

            findings = {
                'test_id': 'WSTG-CRYP-002',
                'test_name': 'Cryptographic Implementation Testing',
                'description': 'Testing for weak cryptographic implementations',
                'vulnerabilities': crypto_vulnerabilities,
                'vulnerability_count': len(crypto_vulnerabilities),
                'risk_level': 'High' if any(v['risk_level'] == 'High' for v in crypto_vulnerabilities) else 'Low',
                'recommendations': [
                    'Use strong cryptographic algorithms (SHA-256+, bcrypt)',
                    'Implement proper random number generation',
                    'Use cryptographically secure session tokens',
                    'Encrypt sensitive data at rest and in transit',
                    'Implement proper key management'
                ]
            }

            self.findings.append(findings)
            return findings

        except Exception as e:
            print(f"[*] Error testing cryptographic implementation: {e}")
            return None

    def test_insecure_random_values(self):
        """WSTG-CRYP-003 - Test for Insecure Random Values"""
        print("[*] Testing Random Value Generation...")

        try:
            # Analyze cookies for randomness
            response = self.session.get(self.target_url, timeout=10)
            session_cookies = []

            for cookie in response.cookies:
                if any(keyword in cookie.name.lower() for keyword in ['session', 'token', 'csrf', 'xsrf']):
                    # Collect multiple instances to test randomness
                    session_cookies.append({
                        'name': cookie.name,
                        'value': cookie.value,
                        'length': len(cookie.value)
                    })

            # Test cookie randomness by making multiple requests
            random_tests = []
            for cookie in response.cookies[:3]:  # Test first 3 cookies
                values = []
                try:
                    for i in range(5):
                        new_session = requests.Session()
                        new_response = new_session.get(self.target_url, timeout=10)
                        for c in new_response.cookies:
                            if c.name == cookie.name:
                                values.append(c.value)
                                break
                        time.sleep(0.5)

                    if len(values) > 1:
                        randomness_score = self._calculate_randomness_score(values)
                        random_tests.append({
                            'cookie_name': cookie.name,
                            'values_collected': len(values),
                            'randomness_score': randomness_score,
                            'sufficient_randomness': randomness_score > 0.7
                        })
                except Exception as e:
                    continue

            findings = {
                'test_id': 'WSTG-CRYP-003',
                'test_name': 'Random Value Generation Testing',
                'description': 'Testing for insecure random value generation',
                'session_cookies': session_cookies,
                'randomness_tests': random_tests,
                'weak_randomness_found': any(not test['sufficient_randomness'] for test in random_tests),
                'risk_level': 'High' if any(not test['sufficient_randomness'] for test in random_tests) else 'Low',
                'recommendations': [
                    'Use cryptographically secure random number generators',
                    'Implement proper session token entropy',
                    'Use platform-specific secure random functions',
                    'Test randomness with statistical analysis'
                ]
            }

            self.findings.append(findings)
            return findings

        except Exception as e:
            print(f"[*] Error testing random values: {e}")
            return None

    def test_weak_password_storage(self):
        """WSTG-CRYP-004 - Test for Weak Password Storage"""
        print("[*] Testing Password Storage Security...")

        try:
            password_storage_issues = []

            # Test for login forms and password handling
            response = self.session.get(self.target_url, timeout=10)
            forms = self._extract_forms(response)

            login_forms = []
            for form in forms:
                password_inputs = [inp for inp in form['inputs'] if inp.get('type') == 'password']
                if password_inputs:
                    login_forms.append({
                        'action': form['action'],
                        'method': form['method'],
                        'has_password_field': True
                    })

            if login_forms:
                # Test login form with various password hashes
                for form in login_forms:
                    try:
                        # Test password transmission
                        test_data = {'username': 'test', 'password': 'test123'}
                        if form['method'].upper() == 'POST':
                            login_response = self.session.post(form['action'], data=test_data, timeout=10)
                        else:
                            login_response = self.session.get(form['action'], params=test_data, timeout=10)

                        # Analyze response for password-related information
                        if any(keyword in login_response.text.lower() for keyword in ['password', 'pwd', 'hash', 'encrypt']):
                            password_storage_issues.append({
                                'type': 'Password Information Disclosure',
                                'form_action': form['action'],
                                'evidence': 'Password-related terms found in response',
                                'risk_level': 'High'
                            })

                    except Exception as e:
                        continue

            # Check for potential password files
            password_file_paths = [
                '/passwords.txt',
                '/users.txt',
                '/config.ini',
                '/settings.json',
                '/database.sql'
            ]

            for path in password_file_paths:
                try:
                    test_url = urljoin(self.target_url, path)
                    file_response = self.session.get(test_url, timeout=10)
                    if file_response.status_code == 200:
                        # Check if file contains password-like content
                        if self._contains_password_data(file_response.text):
                            password_storage_issues.append({
                                'type': 'Exposed Password File',
                                'file_path': path,
                                'accessible': True,
                                'risk_level': 'Critical'
                            })
                except Exception as e:
                    continue

            findings = {
                'test_id': 'WSTG-CRYP-004',
                'test_name': 'Password Storage Testing',
                'description': 'Testing for weak password storage practices',
                'login_forms_found': len(login_forms),
                'password_issues': password_storage_issues,
                'vulnerability_count': len(password_storage_issues),
                'risk_level': 'Critical' if any(issue['risk_level'] == 'Critical' for issue in password_storage_issues) else 'Low',
                'recommendations': [
                    'Use strong password hashing (bcrypt, Argon2, scrypt)',
                    'Implement proper salting',
                    'Never store plaintext passwords',
                    'Use secure password policies',
                    'Implement rate limiting and account lockout'
                ]
            }

            self.findings.append(findings)
            return findings

        except Exception as e:
            print(f"[*] Error testing password storage: {e}")
            return None

    def test_weak_crypto_algorithms(self):
        """WSTG-CRYP-005 - Test for Weak Cryptographic Algorithms"""
        print("[*] Testing Cryptographic Algorithms...")

        try:
            algorithm_vulnerabilities = []

            response = self.session.get(self.target_url, timeout=10)
            response_text = response.text.lower()

            # Check for deprecated cryptographic algorithms
            weak_algorithms = {
                'des': ['des', 'data encryption standard'],
                '3des': ['3des', 'triple des', 'tripledes'],
                'md5': ['md5', 'message-digest'],
                'sha1': ['sha1', 'sha-1'],
                'rc4': ['rc4', 'arcfour']
            }

            for algorithm, patterns in weak_algorithms.items():
                for pattern in patterns:
                    if pattern in response_text:
                        algorithm_vulnerabilities.append({
                            'algorithm': algorithm,
                            'pattern_found': pattern,
                            'risk_level': 'High' if algorithm in ['des', '3des', 'md5'] else 'Medium'
                        })

            # Check SSL/TLS version information
            if response.headers.get('server', '').lower():
                server_info = response.headers['server'].lower()
                if any(ssl_version in server_info for ssl_version in ['ssl/2', 'ssl/3']):
                    algorithm_vulnerabilities.append({
                        'algorithm': 'SSL/TLS',
                        'version': 'SSLv2/SSLv3 detected',
                        'risk_level': 'Critical'
                    })

            # Check for common cryptographic libraries that might be outdated
            crypto_library_patterns = [
                'openssl 1.0',
                'cryptolib',
                'mcrypt',
                'cryptopp'
            ]

            for pattern in crypto_library_patterns:
                if pattern in response_text:
                    algorithm_vulnerabilities.append({
                        'type': 'Cryptographic Library',
                        'library': pattern,
                        'potential_outdated': True,
                        'risk_level': 'Medium'
                    })

            findings = {
                'test_id': 'WSTG-CRYP-005',
                'test_name': 'Cryptographic Algorithms Testing',
                'description': 'Testing for weak cryptographic algorithms',
                'vulnerabilities': algorithm_vulnerabilities,
                'vulnerability_count': len(algorithm_vulnerabilities),
                'risk_level': 'Critical' if any(v.get('risk_level') == 'Critical' for v in algorithm_vulnerabilities) else 'Low',
                'recommendations': [
                    'Use strong cryptographic algorithms (AES-256, SHA-256+)',
                    'Avoid deprecated algorithms (DES, 3DES, MD5, SHA1)',
                    'Update cryptographic libraries regularly',
                    'Implement TLS 1.2 or higher',
                    'Use authenticated encryption modes'
                ]
            }

            self.findings.append(findings)
            return findings

        except Exception as e:
            print(f"[*] Error testing cryptographic algorithms: {e}")
            return None

    def run_comprehensive_test(self):
        """Run all cryptography tests"""
        print("=" * 60)
        print("OWASP WSTG CRYPTOGRAPHY TESTING")
        print("=" * 60)

        tests = [
            self.test_weak_transport_encryption,
            self.test_weak_cryptography_implementation,
            self.test_insecure_random_values,
            self.test_weak_password_storage,
            self.test_weak_crypto_algorithms
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

    def _analyze_certificate(self, response):
        """Analyze SSL certificate information"""
        cert_info = {
            'cert_available': True,
            'issuer': 'Certificate information not available in HTTP response',
            'validity': 'Not available',
            'protocol': 'Not available'
        }

        # Look for certificate-related headers
        if response.headers.get('strict-transport-security'):
            cert_info['hsts'] = True
        else:
            cert_info['hsts'] = False

        return cert_info

    def _calculate_randomness_score(self, values):
        """Calculate randomness score for a list of values"""
        if len(values) < 2:
            return 0.0

        # Simple randomness calculation based on character diversity
        all_chars = ''.join(values)
        unique_chars = set(all_chars)
        char_diversity = len(unique_chars) / len(all_chars) if all_chars else 0

        # Check for patterns
        has_patterns = False
        for i in range(len(values) - 1):
            if values[i] == values[i + 1]:
                has_patterns = True
                break

        # Calculate entropy-like score
        randomness_score = char_diversity * (0.8 if not has_patterns else 0.3)
        return min(randomness_score, 1.0)

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

    def _contains_password_data(self, content):
        """Check if content contains password-related data"""
        password_indicators = [
            'password',
            'passwd',
            'pwd:',
            'hash:',
            'bcrypt',
            'sha256',
            'md5:',
            'user:',
            'login:',
            'auth:'
        ]

        content_lower = content.lower()
        for indicator in password_indicators:
            if indicator in content_lower:
                return True

        return False

def main():
    if len(sys.argv) < 2:
        print("Usage: python crypto_testing.py <target_url>")
        sys.exit(1)

    target_url = sys.argv[1]

    try:
        tester = CryptographyTester(target_url)
        results = tester.run_comprehensive_test()

        if results:
            # Generate report
            report = generate_report(
                target_url=target_url,
                test_results=results,
                test_category='Cryptography',
                timestamp=time.strftime('%Y-%m-%d %H:%M:%S')
            )

            # Save results
            save_findings(report, 'cryptography_test_results.json')

            print(f"\n[*] Test completed. Results saved to cryptography_test_results.json")
        else:
            print("[*] No tests completed successfully")

    except KeyboardInterrupt:
        print("\n[*] Test interrupted by user")
    except Exception as e:
        print(f"[*] Error: {e}")

if __name__ == "__main__":
    main()
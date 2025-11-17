#!/usr/bin/env python3
"""
OWASP WSTG API Testing Framework
WSTG-APIT-001 through WSTG-APIT-012
"""

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'core'))

from base_tester import BaseTester
from utils import generate_report, save_findings, analyze_api
import requests
import json
import time
import random
from urllib.parse import urljoin, urlparse

class APITester(BaseTester):
    """API Security Testing"""

    def __init__(self, target_url):
        super().__init__()
        self.target_url = target_url
        self.session = requests.Session()
        self.findings = []
        self.api_results = {}
        self.api_endpoints = []

    def test_api_discovery(self):
        """WSTG-APIT-001 - Test API Discovery"""
        print("[*] Testing API Discovery...")

        try:
            discovered_endpoints = []

            # Common API endpoint patterns
            api_patterns = [
                '/api',
                '/api/v1',
                '/api/v2',
                '/rest',
                '/graphql',
                '/webhook',
                '/admin/api',
                '/api-docs',
                '/swagger.json',
                '/openapi.json'
            ]

            for pattern in api_patterns:
                try:
                    test_url = urljoin(self.target_url, pattern)
                    response = self.session.get(test_url, timeout=10)

                    if response.status_code != 404:
                        discovered_endpoints.append({
                            'endpoint': pattern,
                            'status_code': response.status_code,
                            'content_type': response.headers.get('content-type', ''),
                            'response_size': len(response.content)
                        })
                except Exception as e:
                    continue

            # Look for API documentation endpoints
            doc_endpoints = [
                '/docs',
                '/documentation',
                '/swagger',
                '/redoc',
                '/api-docs',
                '/api-documentation'
            ]

            for doc_endpoint in doc_endpoints:
                try:
                    test_url = urljoin(self.target_url, doc_endpoint)
                    response = self.session.get(test_url, timeout=10)

                    if response.status_code == 200:
                        discovered_endpoints.append({
                            'endpoint': doc_endpoint,
                            'status_code': response.status_code,
                            'type': 'documentation',
                            'accessible': True
                        })
                except Exception as e:
                    continue

            findings = {
                'test_id': 'WSTG-APIT-001',
                'test_name': 'API Discovery Testing',
                'description': 'Testing for API endpoint discovery',
                'discovered_endpoints': discovered_endpoints,
                'total_endpoints': len(discovered_endpoints),
                'api_documentation_found': any(e.get('type') == 'documentation' for e in discovered_endpoints),
                'risk_level': 'Medium' if len(discovered_endpoints) > 0 else 'Low',
                'recommendations': [
                    'Implement proper API access controls',
                    'Use authentication for all API endpoints',
                    'Avoid exposing internal API structure',
                    'Implement API rate limiting',
                    'Use API versioning properly'
                ]
            }

            self.findings.append(findings)
            self.api_endpoints = [e['endpoint'] for e in discovered_endpoints if e['status_code'] != 404]
            return findings

        except Exception as e:
            print(f"[*] Error testing API discovery: {e}")
            return None

    def test_api_authentication(self):
        """WSTG-APIT-002 - Test API Authentication"""
        print("[*] Testing API Authentication...")

        try:
            auth_vulnerabilities = []

            for endpoint in self.api_endpoints:
                try:
                    test_url = urljoin(self.target_url, endpoint)

                    # Test without authentication
                    response = self.session.get(test_url, timeout=10)

                    # Check for authentication bypass
                    if response.status_code == 200 and len(response.content) > 100:
                        auth_vulnerabilities.append({
                            'type': 'Authentication Bypass',
                            'endpoint': endpoint,
                            'status_code': response.status_code,
                            'response_size': len(response.content),
                            'risk_level': 'High'
                        })

                    # Test with common authentication headers
                    auth_headers = [
                        {'Authorization': 'Bearer invalid'},
                        {'Authorization': 'Basic invalid'},
                        {'X-API-Key': 'invalid'},
                        {'api-key': 'invalid'}
                    ]

                    for header in auth_headers:
                        try:
                            auth_response = self.session.get(test_url, headers=header, timeout=10)
                            # Check if different behavior occurs
                            if auth_response.status_code != response.status_code:
                                auth_vulnerabilities.append({
                                    'type': 'Authentication Mechanism Detected',
                                    'endpoint': endpoint,
                                    'header': list(header.keys())[0],
                                    'different_response': True,
                                    'risk_level': 'Medium'
                                })
                        except Exception as e:
                            continue

                except Exception as e:
                    continue

            findings = {
                'test_id': 'WSTG-APIT-002',
                'test_name': 'API Authentication Testing',
                'description': 'Testing for API authentication vulnerabilities',
                'vulnerabilities': auth_vulnerabilities,
                'vulnerability_count': len(auth_vulnerabilities),
                'risk_level': 'High' if auth_vulnerabilities else 'Low',
                'recommendations': [
                    'Implement proper API authentication',
                    'Use strong token-based authentication',
                    'Validate authentication on all requests',
                    'Implement API key rotation',
                    'Use OAuth 2.0 or similar standards'
                ]
            }

            self.findings.append(findings)
            return findings

        except Exception as e:
            print(f"[*] Error testing API authentication: {e}")
            return None

    def test_api_authorization(self):
        """WSTG-APIT-003 - Test API Authorization"""
        print("[*] Testing API Authorization...")

        try:
            authz_vulnerabilities = []

            # Test for privilege escalation
            admin_endpoints = [
                '/admin',
                '/users',
                '/settings',
                '/config',
                '/admin/users',
                '/api/admin'
            ]

            for endpoint in admin_endpoints:
                try:
                    test_url = urljoin(self.target_url, endpoint)
                    response = self.session.get(test_url, timeout=10)

                    if response.status_code == 200:
                        authz_vulnerabilities.append({
                            'type': 'Unauthorized Access to Admin Endpoint',
                            'endpoint': endpoint,
                            'accessible': True,
                            'risk_level': 'Critical'
                        })
                except Exception as e:
                    continue

            # Test for parameter-based access control bypass
            for endpoint in self.api_endpoints:
                try:
                    test_url = urljoin(self.target_url, endpoint)

                    # Test with different user IDs
                    test_ids = [1, 2, 999, 1000]
                    for test_id in test_ids:
                        test_url_with_id = f"{test_url}/{test_id}"
                        try:
                            response = self.session.get(test_url_with_id, timeout=10)

                            if response.status_code == 200:
                                authz_vulnerabilities.append({
                                    'type': 'ID-based Access Control Bypass',
                                    'endpoint': endpoint,
                                    'test_id': test_id,
                                    'access_granted': True,
                                    'risk_level': 'High'
                                })
                        except Exception as e:
                            continue

                except Exception as e:
                    continue

            findings = {
                'test_id': 'WSTG-APIT-003',
                'test_name': 'API Authorization Testing',
                'description': 'Testing for API authorization vulnerabilities',
                'vulnerabilities': authz_vulnerabilities,
                'vulnerability_count': len(authz_vulnerabilities),
                'risk_level': 'Critical' if authz_vulnerabilities else 'Low',
                'recommendations': [
                    'Implement proper role-based access control',
                    'Validate user permissions on every request',
                    'Use parameterized access control',
                    'Implement least privilege principle',
                    'Regularly audit API access controls'
                ]
            }

            self.findings.append(findings)
            return findings

        except Exception as e:
            print(f"[*] Error testing API authorization: {e}")
            return None

    def test_api_input_validation(self):
        """WSTG-APIT-004 - Test API Input Validation"""
        print("[*] Testing API Input Validation...")

        try:
            validation_vulnerabilities = []

            # Test with malicious payloads
            test_payloads = [
                '<script>alert("XSS")</script>',
                'SELECT * FROM users',
                '; DROP TABLE users',
                '../../etc/passwd',
                'null',
                'undefined',
                '{"malicious": true}',
                '12345678901234567890',
                '0x1234'
            ]

            for endpoint in self.api_endpoints:
                try:
                    test_url = urljoin(self.target_url, endpoint)

                    for payload in test_payloads:
                        # Test GET parameters
                        try:
                            params = {'test': payload}
                            response = self.session.get(test_url, params=params, timeout=10)

                            if payload in response.text or 'error' in response.text.lower():
                                validation_vulnerabilities.append({
                                    'type': 'Input Validation Issue',
                                    'endpoint': endpoint,
                                    'method': 'GET',
                                    'payload': payload,
                                    'reflected': payload in response.text,
                                    'risk_level': 'Medium'
                                })
                        except Exception as e:
                            continue

                        # Test POST body
                        try:
                            data = {'test': payload}
                            response = self.session.post(test_url, json=data, timeout=10)

                            if payload in response.text or 'error' in response.text.lower():
                                validation_vulnerabilities.append({
                                    'type': 'Input Validation Issue',
                                    'endpoint': endpoint,
                                    'method': 'POST',
                                    'payload': payload,
                                    'reflected': payload in response.text,
                                    'risk_level': 'Medium'
                                })
                        except Exception as e:
                            continue

                except Exception as e:
                    continue

            findings = {
                'test_id': 'WSTG-APIT-004',
                'test_name': 'API Input Validation Testing',
                'description': 'Testing for API input validation vulnerabilities',
                'vulnerabilities': validation_vulnerabilities,
                'vulnerability_count': len(validation_vulnerabilities),
                'risk_level': 'Medium' if validation_vulnerabilities else 'Low',
                'recommendations': [
                    'Implement strict input validation',
                    'Use parameterized queries',
                    'Sanitize all user input',
                    'Implement proper error handling',
                    'Use API validation frameworks'
                ]
            }

            self.findings.append(findings)
            return findings

        except Exception as e:
            print(f"[*] Error testing API input validation: {e}")
            return None

    def test_api_rate_limiting(self):
        """WSTG-APIT-005 - Test API Rate Limiting"""
        print("[*] Testing API Rate Limiting...")

        try:
            rate_limit_vulnerabilities = []

            for endpoint in self.api_endpoints:
                try:
                    test_url = urljoin(self.target_url, endpoint)

                    # Make multiple rapid requests
                    responses = []
                    for i in range(50):  # Make 50 requests quickly
                        try:
                            response = self.session.get(test_url, timeout=2)
                            responses.append(response.status_code)
                        except Exception as e:
                            continue

                    # Check if rate limiting is implemented
                    if all(status == 200 for status in responses):
                        rate_limit_vulnerabilities.append({
                            'type': 'Missing Rate Limiting',
                            'endpoint': endpoint,
                            'requests_made': len(responses),
                            'all_successful': True,
                            'risk_level': 'Medium'
                        })
                    elif any(status == 429 for status in responses):
                        # Rate limiting is implemented
                        pass

                except Exception as e:
                    continue

            findings = {
                'test_id': 'WSTG-APIT-005',
                'test_name': 'API Rate Limiting Testing',
                'description': 'Testing for API rate limiting vulnerabilities',
                'vulnerabilities': rate_limit_vulnerabilities,
                'vulnerability_count': len(rate_limit_vulnerabilities),
                'risk_level': 'Medium' if rate_limit_vulnerabilities else 'Low',
                'recommendations': [
                    'Implement API rate limiting',
                    'Use progressive rate limiting',
                    'Implement IP-based and user-based limits',
                    'Monitor for abuse patterns',
                    'Use API gateway for rate limiting'
                ]
            }

            self.findings.append(findings)
            return findings

        except Exception as e:
            print(f"[*] Error testing API rate limiting: {e}")
            return None

    def test_api_error_handling(self):
        """WSTG-APIT-006 - Test API Error Handling"""
        print("[*] Testing API Error Handling...")

        try:
            error_vulnerabilities = []

            for endpoint in self.api_endpoints:
                try:
                    test_url = urljoin(self.target_url, endpoint)

                    # Test with invalid methods
                    invalid_methods = ['PATCH', 'PUT', 'DELETE']
                    for method in invalid_methods:
                        try:
                            response = self.session.request(method, test_url, timeout=10)

                            # Check for verbose error messages
                            if response.status_code >= 400:
                                error_content = response.text.lower()
                                if any(keyword in error_content for keyword in ['error', 'exception', 'traceback', 'stack']):
                                    error_vulnerabilities.append({
                                        'type': 'Verbose Error Message',
                                        'endpoint': endpoint,
                                        'method': method,
                                        'status_code': response.status_code,
                                        'risk_level': 'Low'
                                    })
                        except Exception as e:
                            continue

                    # Test with malformed JSON
                    try:
                        malformed_json = '{"invalid": json}'
                        response = self.session.post(test_url, data=malformed_json, timeout=10)

                        if response.status_code >= 400:
                            error_content = response.text.lower()
                            if any(keyword in error_content for keyword in ['syntax', 'parse', 'json']):
                                error_vulnerabilities.append({
                                    'type': 'JSON Parse Error Disclosure',
                                    'endpoint': endpoint,
                                    'status_code': response.status_code,
                                    'risk_level': 'Low'
                                })
                    except Exception as e:
                        continue

                except Exception as e:
                    continue

            findings = {
                'test_id': 'WSTG-APIT-006',
                'test_name': 'API Error Handling Testing',
                'description': 'Testing for API error handling vulnerabilities',
                'vulnerabilities': error_vulnerabilities,
                'vulnerability_count': len(error_vulnerabilities),
                'risk_level': 'Low' if error_vulnerabilities else 'Low',
                'recommendations': [
                    'Implement consistent error responses',
                    'Avoid exposing internal error details',
                    'Use standard HTTP status codes',
                    'Implement proper logging for debugging',
                    'Use generic error messages for clients'
                ]
            }

            self.findings.append(findings)
            return findings

        except Exception as e:
            print(f"[*] Error testing API error handling: {e}")
            return None

    def test_api_cors_configuration(self):
        """WSTG-APIT-007 - Test API CORS Configuration"""
        print("[*] Testing API CORS Configuration...")

        try:
            cors_vulnerabilities = []

            for endpoint in self.api_endpoints:
                try:
                    test_url = urljoin(self.target_url, endpoint)

                    # Test with Origin header
                    origins = [
                        'https://evil.com',
                        'https://malicious-site.com',
                        'null',
                        'https://localhost:3000'
                    ]

                    for origin in origins:
                        try:
                            headers = {'Origin': origin}
                            response = self.session.options(test_url, headers=headers, timeout=10)

                            # Check CORS headers
                            cors_headers = {
                                'Access-Control-Allow-Origin': response.headers.get('Access-Control-Allow-Origin'),
                                'Access-Control-Allow-Methods': response.headers.get('Access-Control-Allow-Methods'),
                                'Access-Control-Allow-Headers': response.headers.get('Access-Control-Allow-Headers'),
                                'Access-Control-Allow-Credentials': response.headers.get('Access-Control-Allow-Credentials')
                            }

                            # Check if CORS is too permissive
                            if cors_headers['Access-Control-Allow-Origin'] == '*':
                                cors_vulnerabilities.append({
                                    'type': 'Permissive CORS Policy',
                                    'endpoint': endpoint,
                                    'test_origin': origin,
                                    'allowed_origin': cors_headers['Access-Control-Allow-Origin'],
                                    'risk_level': 'Medium'
                                })
                            elif cors_headers['Access-Control-Allow-Origin'] == origin and origin not in ['https://localhost:3000']:
                                cors_vulnerabilities.append({
                                    'type': 'Unsafe CORS Origin',
                                    'endpoint': endpoint,
                                    'test_origin': origin,
                                    'allowed_origin': cors_headers['Access-Control-Allow-Origin'],
                                    'risk_level': 'Medium'
                                })

                        except Exception as e:
                            continue

                except Exception as e:
                    continue

            findings = {
                'test_id': 'WSTG-APIT-007',
                'test_name': 'API CORS Configuration Testing',
                'description': 'Testing for API CORS configuration vulnerabilities',
                'vulnerabilities': cors_vulnerabilities,
                'vulnerability_count': len(cors_vulnerabilities),
                'risk_level': 'Medium' if cors_vulnerabilities else 'Low',
                'recommendations': [
                    'Configure CORS policies carefully',
                    'Avoid wildcard (*) origins in production',
                    'Validate origins against whitelist',
                    'Implement proper CORS headers',
                    'Test CORS configuration regularly'
                ]
            }

            self.findings.append(findings)
            return findings

        except Exception as e:
            print(f"[*] Error testing API CORS configuration: {e}")
            return None

    def test_api_versioning(self):
        """WSTG-APIT-008 - Test API Versioning"""
        print("[*] Testing API Versioning...")

        try:
            versioning_vulnerabilities = []

            # Test for version inconsistencies
            version_patterns = [
                '/api/v1',
                '/api/v2',
                '/api/v3',
                '/api/v0'
            ]

            for pattern in version_patterns:
                try:
                    test_url = urljoin(self.target_url, pattern)
                    response = self.session.get(test_url, timeout=10)

                    if response.status_code == 200:
                        versioning_vulnerabilities.append({
                            'type': 'API Version Exposed',
                            'version': pattern,
                            'accessible': True,
                            'risk_level': 'Low'
                        })
                except Exception as e:
                    continue

            # Test for version bypass
            if self.api_endpoints:
                for endpoint in self.api_endpoints:
                    # Try to access newer/older versions
                    if '/v1' in endpoint:
                        v2_endpoint = endpoint.replace('/v1', '/v2')
                        try:
                            response = self.session.get(urljoin(self.target_url, v2_endpoint), timeout=10)
                            if response.status_code == 200:
                                versioning_vulnerabilities.append({
                                    'type': 'API Version Bypass',
                                    'endpoint': v2_endpoint,
                                    'accessible': True,
                                    'risk_level': 'Low'
                                })
                        except Exception as e:
                            continue

            findings = {
                'test_id': 'WSTG-APIT-008',
                'test_name': 'API Versioning Testing',
                'description': 'Testing for API versioning vulnerabilities',
                'vulnerabilities': versioning_vulnerabilities,
                'vulnerability_count': len(versioning_vulnerabilities),
                'risk_level': 'Low' if versioning_vulnerabilities else 'Low',
                'recommendations': [
                    'Implement proper API versioning strategy',
                    'Use versioning in headers instead of URLs',
                    'Document API versioning clearly',
                    'Implement version deprecation policies',
                    'Test version compatibility regularly'
                ]
            }

            self.findings.append(findings)
            return findings

        except Exception as e:
            print(f"[*] Error testing API versioning: {e}")
            return None

    def run_comprehensive_test(self):
        """Run all API tests"""
        print("=" * 60)
        print("OWASP WSTG API TESTING")
        print("=" * 60)

        tests = [
            self.test_api_discovery,
            self.test_api_authentication,
            self.test_api_authorization,
            self.test_api_input_validation,
            self.test_api_rate_limiting,
            self.test_api_error_handling,
            self.test_api_cors_configuration,
            self.test_api_versioning
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

def main():
    if len(sys.argv) < 2:
        print("Usage: python api_tester.py <target_url>")
        sys.exit(1)

    target_url = sys.argv[1]

    try:
        tester = APITester(target_url)
        results = tester.run_comprehensive_test()

        if results:
            # Generate report
            report = generate_report(
                target_url=target_url,
                test_results=results,
                test_category='API Testing',
                timestamp=time.strftime('%Y-%m-%d %H:%M:%S')
            )

            # Save results
            save_findings(report, 'api_test_results.json')

            print(f"\n[*] Test completed. Results saved to api_test_results.json")
        else:
            print("[*] No tests completed successfully")

    except KeyboardInterrupt:
        print("\n[*] Test interrupted by user")
    except Exception as e:
        print(f"[*] Error: {e}")

if __name__ == "__main__":
    main()
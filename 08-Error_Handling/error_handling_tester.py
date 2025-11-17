#!/usr/bin/env python3
"""
OWASP WSTG Error Handling Testing Framework
WSTG-ERRH-001 through WSTG-ERRH-008
"""

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'core'))

from base_tester import BaseTester
from utils import generate_report, save_findings, analyze_error
import requests
import json
import time
from urllib.parse import urljoin, urlparse
import random

class ErrorHandlingTester(BaseTester):
    """Error Handling Security Testing"""

    def __init__(self, target_url):
        super().__init__()
        self.target_url = target_url
        self.session = requests.Session()
        self.findings = []
        self.error_results = {}

    def test_error_codes(self):
        """WSTG-ERRH-001 - Test for Improper Error Handling"""
        print("[*] Testing Error Codes and Messages...")

        try:
            error_endpoints = [
                '/nonexistent-page.html',
                '/404.php',
                '/error.php',
                '/undefined',
                '/admin/protected-area',
                '/api/v1/invalid-endpoint'
            ]

            errors_found = []

            for endpoint in error_endpoints:
                try:
                    test_url = urljoin(self.target_url, endpoint)
                    response = self.session.get(test_url, timeout=10)

                    error_info = {
                        'url': test_url,
                        'status_code': response.status_code,
                        'content_type': response.headers.get('content-type', ''),
                        'server': response.headers.get('server', ''),
                        'response_length': len(response.text),
                        'contains_stack_trace': self._contains_stack_trace(response.text),
                        'contains_sensitive_info': self._contains_sensitive_info(response.text),
                        'default_error_page': self._is_default_error_page(response.text)
                    }

                    errors_found.append(error_info)

                except requests.exceptions.RequestException as e:
                    continue

            findings = {
                'test_id': 'WSTG-ERRH-001',
                'test_name': 'Error Codes Testing',
                'description': 'Testing for improper error handling and information disclosure',
                'errors_found': errors_found,
                'total_errors_tested': len(error_endpoints),
                'stack_traces_found': sum(1 for e in errors_found if e['contains_stack_trace']),
                'sensitive_info_disclosed': sum(1 for e in errors_found if e['contains_sensitive_info']),
                'risk_level': 'High' if errors_found and any(e['contains_stack_trace'] for e in errors_found) else 'Low',
                'recommendations': [
                    'Implement custom error pages',
                    'Remove sensitive information from error messages',
                    'Log detailed errors server-side only',
                    'Return generic error messages to users'
                ]
            }

            self.findings.append(findings)
            return findings

        except Exception as e:
            print(f"[*] Error testing error codes: {e}")
            return None

    def test_database_error_messages(self):
        """WSTG-ERRH-002 - Test for Database Error Messages"""
        print("[*] Testing Database Error Messages...")

        try:
            # Test for SQL injection that triggers database errors
            sql_error_payloads = [
                "'",
                "' OR 1=1--",
                '"',
                '" OR 1=1--',
                "'; DROP TABLE users--",
                "' UNION SELECT NULL--",
                "' AND 1=CONVERT(int, (SELECT @@version))--",
                "' AND 1=(SELECT COUNT(*) FROM tabname)--"
            ]

            database_errors = []

            # Test URL parameters
            response = self.session.get(self.target_url)
            params = self._get_url_parameters(response)

            for param in params[:5]:  # Test first 5 parameters
                for payload in sql_error_payloads:
                    try:
                        test_url = self._inject_payload_in_url(self.target_url, param, payload)
                        test_response = self.session.get(test_url, timeout=10)

                        if self._contains_database_error(test_response.text):
                            error_info = {
                                'url': test_url,
                                'parameter': param,
                                'payload': payload,
                                'error_type': self._identify_database_type(test_response.text),
                                'error_message': self._extract_database_error(test_response.text)
                            }
                            database_errors.append(error_info)

                    except Exception as e:
                        continue

            # Test form inputs
            forms = self._extract_forms(response)
            for form in forms[:3]:  # Test first 3 forms
                for payload in sql_error_payloads:
                    try:
                        form_data = self._prepare_form_data_for_error_testing(form, payload)
                        test_response = self.session.post(form['action'], data=form_data, timeout=10)

                        if self._contains_database_error(test_response.text):
                            error_info = {
                                'url': form['action'],
                                'method': form['method'],
                                'payload': payload,
                                'error_type': self._identify_database_type(test_response.text),
                                'error_message': self._extract_database_error(test_response.text)
                            }
                            database_errors.append(error_info)

                    except Exception as e:
                        continue

            findings = {
                'test_id': 'WSTG-ERRH-002',
                'test_name': 'Database Error Messages Testing',
                'description': 'Testing for database error message disclosure',
                'database_errors': database_errors,
                'vulnerability_count': len(database_errors),
                'risk_level': 'Critical' if database_errors else 'Low',
                'recommendations': [
                    'Implement proper exception handling',
                    'Catch database exceptions before reaching user',
                    'Log database errors server-side only',
                    'Use parameterized queries to prevent database errors'
                ]
            }

            self.findings.append(findings)
            return findings

        except Exception as e:
            print(f"[*] Error testing database error messages: {e}")
            return None

    def test_web_server_error_messages(self):
        """WSTG-ERRH-003 - Test for Web Server Error Messages"""
        print("[*] Testing Web Server Error Messages...")

        try:
            server_errors = []

            # Test various invalid requests
            invalid_requests = [
                'GET',
                'POST / HTTP/1.1',
                'INVALID-REQUEST',
                '../../../etc/passwd',
                'http://invalid.url',
                '%00',
                'test\x00',
                'test%2e%2e%2f'
            ]

            for invalid_request in invalid_requests:
                try:
                    # Test in URL
                    test_url = f"{self.target_url}/{invalid_request}"
                    response = self.session.get(test_url, timeout=10)

                    if response.status_code >= 400:
                        error_info = {
                            'url': test_url,
                            'status_code': response.status_code,
                            'server_info': self._extract_server_info(response),
                            'detailed_error': self._is_detailed_error(response.text)
                        }
                        server_errors.append(error_info)

                except Exception as e:
                    continue

            # Test malformed headers
            try:
                headers = {
                    'Host': 'invalid.host',
                    'User-Agent': None,
                    'Accept': 'invalid/type',
                    'Connection': 'invalid-connection'
                }

                malformed_response = self.session.get(self.target_url, headers=headers, timeout=10)
                if malformed_response.status_code >= 400:
                    error_info = {
                        'url': self.target_url,
                        'test_type': 'malformed_headers',
                        'status_code': malformed_response.status_code,
                        'server_info': self._extract_server_info(malformed_response),
                        'detailed_error': self._is_detailed_error(malformed_response.text)
                    }
                    server_errors.append(error_info)

            except Exception as e:
                pass

            findings = {
                'test_id': 'WSTG-ERRH-003',
                'test_name': 'Web Server Error Messages Testing',
                'description': 'Testing for web server error message disclosure',
                'server_errors': server_errors,
                'vulnerability_count': len(server_errors),
                'risk_level': 'Medium' if server_errors else 'Low',
                'recommendations': [
                    'Configure server to hide detailed error messages',
                    'Use custom error pages',
                    'Disable server signature disclosure',
                    'Implement proper error handling'
                ]
            }

            self.findings.append(findings)
            return findings

        except Exception as e:
            print(f"[*] Error testing web server error messages: {e}")
            return None

    def test_api_error_handling(self):
        """WSTG-ERRH-004 - Test for API Error Handling"""
        print("[*] Testing API Error Handling...")

        try:
            api_errors = []

            # Test common API endpoints
            api_endpoints = [
                '/api',
                '/api/v1',
                '/api/v2',
                '/rest',
                '/graphql',
                '/api/users',
                '/api/auth'
            ]

            for endpoint in api_endpoints:
                try:
                    api_url = urljoin(self.target_url, endpoint)

                    # Test with invalid method
                    response = self.session.patch(api_url, timeout=10)
                    if response.status_code >= 400:
                        api_errors.append({
                            'endpoint': api_url,
                            'method': 'PATCH',
                            'status_code': response.status_code,
                            'error_format': self._analyze_api_error_format(response.text)
                        })

                    # Test with invalid JSON
                    invalid_json = '{"invalid": json,}'
                    response = self.session.post(api_url, json=invalid_json, timeout=10)
                    if response.status_code >= 400:
                        api_errors.append({
                            'endpoint': api_url,
                            'method': 'POST',
                            'test_type': 'invalid_json',
                            'status_code': response.status_code,
                            'error_format': self._analyze_api_error_format(response.text)
                        })

                    # Test with missing authentication
                    response = self.session.get(api_url + '/admin', timeout=10)
                    if response.status_code >= 400:
                        api_errors.append({
                            'endpoint': api_url + '/admin',
                            'method': 'GET',
                            'test_type': 'unauthorized_access',
                            'status_code': response.status_code,
                            'error_format': self._analyze_api_error_format(response.text)
                        })

                except Exception as e:
                    continue

            findings = {
                'test_id': 'WSTG-ERRH-004',
                'test_name': 'API Error Handling Testing',
                'description': 'Testing for proper API error handling and response formatting',
                'api_errors': api_errors,
                'vulnerability_count': len(api_errors),
                'risk_level': 'Medium' if api_errors else 'Low',
                'recommendations': [
                    'Implement consistent API error format',
                    'Use standard HTTP status codes',
                    'Include error details in response body',
                    'Avoid exposing internal error information'
                ]
            }

            self.findings.append(findings)
            return findings

        except Exception as e:
            print(f"[*] Error testing API error handling: {e}")
            return None

    def run_comprehensive_test(self):
        """Run all error handling tests"""
        print("=" * 60)
        print("OWASP WSTG ERROR HANDLING TESTING")
        print("=" * 60)

        tests = [
            self.test_error_codes,
            self.test_database_error_messages,
            self.test_web_server_error_messages,
            self.test_api_error_handling
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

    def _contains_stack_trace(self, content):
        """Check if response contains stack trace information"""
        stack_trace_indicators = [
            'stack trace',
            'traceback',
            'at line',
            'in file',
            'Fatal error',
            'Call Stack',
            'Exception in thread',
            'java.lang.',
            'System.NullReferenceException',
            'TypeError: ',
            'NameError: ',
            'AttributeError: ',
            'KeyError: '
        ]

        content_lower = content.lower()
        for indicator in stack_trace_indicators:
            if indicator in content_lower:
                return True
        return False

    def _contains_sensitive_info(self, content):
        """Check if response contains sensitive information"""
        sensitive_patterns = [
            'password',
            'secret',
            'api_key',
            'private_key',
            'database',
            'username:',
            'root:',
            'admin:',
            'config',
            'connection string',
            'server=',
            'user id='
        ]

        content_lower = content.lower()
        for pattern in sensitive_patterns:
            if pattern in content_lower:
                return True
        return False

    def _is_default_error_page(self, content):
        """Check if it's a default server error page"""
        default_error_indicators = [
            'apache/2.',
            'nginx/1.',
            'iis/',
            'server error',
            'not found',
            'the requested url',
            'http/1.1 404',
            'error 404',
            'page not found'
        ]

        content_lower = content.lower()
        for indicator in default_error_indicators:
            if indicator in content_lower:
                return True
        return False

    def _contains_database_error(self, content):
        """Check if response contains database error"""
        database_errors = [
            'sql syntax',
            'mysql_fetch',
            'ora-01756',
            'postgresql query failed',
            'sqlite3.operationalerror',
            'microsoft ole db',
            'you have an error in your sql syntax',
            'warning: mysql',
            'supplied argument is not a valid mysql',
            'column not found',
            'no such table',
            'invalid column name'
        ]

        content_lower = content.lower()
        for error in database_errors:
            if error in content_lower:
                return True
        return False

    def _identify_database_type(self, content):
        """Identify database type from error message"""
        content_lower = content.lower()

        if any(db in content_lower for db in ['mysql', 'mariadb']):
            return 'MySQL/MariaDB'
        elif any(db in content_lower for db in ['postgresql', 'postgres']):
            return 'PostgreSQL'
        elif any(db in content_lower for db in ['oracle', 'ora-']):
            return 'Oracle'
        elif any(db in content_lower for db in ['sqlite']):
            return 'SQLite'
        elif any(db in content_lower for db in ['sql server', 'mssql']):
            return 'SQL Server'
        else:
            return 'Unknown'

    def _extract_database_error(self, content):
        """Extract relevant database error message"""
        lines = content.split('\n')
        for line in lines:
            if any(keyword in line.lower() for keyword in ['error', 'sql', 'syntax', 'exception']):
                return line.strip()[:100]  # Return first 100 chars of error line
        return "Database error detected"

    def _extract_server_info(self, response):
        """Extract server information from response"""
        server_info = {
            'server_header': response.headers.get('server', ''),
            'powered_by': response.headers.get('x-powered-by', ''),
            'content_type': response.headers.get('content-type', ''),
            'connection': response.headers.get('connection', '')
        }
        return server_info

    def _is_detailed_error(self, content):
        """Check if error message contains too much detail"""
        detailed_indicators = [
            'full stack trace',
            'debug information',
            'internal error',
            'system error',
            'exception details',
            'source file:',
            'line number:',
            'method name:'
        ]

        content_lower = content.lower()
        for indicator in detailed_indicators:
            if indicator in content_lower:
                return True
        return False

    def _get_url_parameters(self, response):
        """Extract URL parameters from current URL"""
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(response.url)
        return list(parse_qs(parsed.url.split('?')[-1] if '?' in parsed.url else '').keys())

    def _inject_payload_in_url(self, url, param, payload):
        """Inject payload into URL parameter"""
        from urllib.parse import urlparse, parse_qs, urlencode

        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param] = payload

        query = urlencode(params, doseq=True)
        return parsed._replace(query=query).geturl()

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

    def _prepare_form_data_for_error_testing(self, form, payload):
        """Prepare form data with payload for error testing"""
        data = {}
        for input_field in form['inputs']:
            if input_field['type'] in ['text', 'password', 'search', 'email', 'hidden']:
                data[input_field['name']] = payload
            else:
                data[input_field['name']] = input_field['value']
        return data

    def _analyze_api_error_format(self, content):
        """Analyze API error response format"""
        try:
            # Try to parse as JSON
            json_data = json.loads(content)
            return {
                'format': 'json',
                'has_error_field': 'error' in json_data or 'errors' in json_data,
                'has_message_field': 'message' in json_data or 'msg' in json_data,
                'has_status_field': 'status' in json_data or 'code' in json_data
            }
        except:
            # Check if it's XML
            if content.strip().startswith('<'):
                return {
                    'format': 'xml',
                    'has_error_tag': '<error>' in content.lower() or '<fault>' in content.lower()
                }
            else:
                return {
                    'format': 'text',
                    'structured': False
                }

def main():
    if len(sys.argv) < 2:
        print("Usage: python error_handling_tester.py <target_url>")
        sys.exit(1)

    target_url = sys.argv[1]

    try:
        tester = ErrorHandlingTester(target_url)
        results = tester.run_comprehensive_test()

        if results:
            # Generate report
            report = generate_report(
                target_url=target_url,
                test_results=results,
                test_category='Error Handling',
                timestamp=time.strftime('%Y-%m-%d %H:%M:%S')
            )

            # Save results
            save_findings(report, 'error_handling_test_results.json')

            print(f"\n[*] Test completed. Results saved to error_handling_test_results.json")
        else:
            print("[*] No tests completed successfully")

    except KeyboardInterrupt:
        print("\n[*] Test interrupted by user")
    except Exception as e:
        print(f"[*] Error: {e}")

if __name__ == "__main__":
    main()
#!/usr/bin/env python3
"""
OWASP WSTG Client-Side Testing Framework
WSTG-CLNT-001 through WSTG-CLNT-018
"""

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'core'))

from base_tester import BaseTester
from utils import generate_report, save_findings, analyze_client_side
import requests
import json
import time
import re
from urllib.parse import urljoin, urlparse

class ClientSideTester(BaseTester):
    """Client-Side Security Testing"""

    def __init__(self, target_url):
        super().__init__()
        self.target_url = target_url
        self.session = requests.Session()
        self.findings = []
        self.client_side_results = {}

    def test_dom_based_xss(self):
        """WSTG-CLNT-001 - Test for DOM-Based Cross Site Scripting"""
        print("[*] Testing DOM-Based Cross Site Scripting...")

        try:
            dom_xss_vulnerabilities = []

            # Test for DOM XSS via URL parameters
            dom_xss_payloads = [
                '<script>alert("DOM-XSS")</script>',
                '<img src=x onerror=alert("DOM-XSS")>',
                '"><script>alert("DOM-XSS")</script>',
                '<svg onload=alert("DOM-XSS")>',
                'javascript:alert("DOM-XSS")'
            ]

            response = self.session.get(self.target_url, timeout=10)

            # Look for potential DOM XSS sinks
            dom_sinks = [
                'innerHTML',
                'outerHTML',
                'document.write',
                'eval(',
                'setTimeout(',
                'setInterval(',
                'location.hash',
                'location.search',
                'window.name',
                'localStorage',
                'sessionStorage'
            ]

            for sink in dom_sinks:
                if sink in response.text:
                    # Test with XSS payload in URL parameter
                    for payload in dom_xss_payloads:
                        test_url = f"{self.target_url}#test={payload}"
                        try:
                            test_response = self.session.get(test_url, timeout=10)
                            # Note: Actual DOM XSS detection would require browser automation
                            dom_xss_vulnerabilities.append({
                                'type': 'Potential DOM XSS Sink',
                                'sink': sink,
                                'test_payload': payload,
                                'test_url': test_url,
                                'requires_browser_verification': True,
                                'risk_level': 'High'
                            })
                        except Exception as e:
                            continue

            findings = {
                'test_id': 'WSTG-CLNT-001',
                'test_name': 'DOM-Based Cross Site Scripting Testing',
                'description': 'Testing for DOM-based XSS vulnerabilities',
                'vulnerabilities': dom_xss_vulnerabilities,
                'vulnerability_count': len(dom_xss_vulnerabilities),
                'dom_sinks_found': list(set([v['sink'] for v in dom_xss_vulnerabilities])),
                'risk_level': 'High' if dom_xss_vulnerabilities else 'Low',
                'recommendations': [
                    'Avoid using innerHTML with user input',
                    'Use textContent instead of innerHTML',
                    'Sanitize user input before DOM manipulation',
                    'Implement Content Security Policy (CSP)',
                    'Use modern JavaScript frameworks with built-in XSS protection'
                ]
            }

            self.findings.append(findings)
            return findings

        except Exception as e:
            print(f"[*] Error testing DOM-based XSS: {e}")
            return None

    def test_javascript_execution(self):
        """WSTG-CLNT-002 - Test for JavaScript Execution"""
        print("[*] Testing JavaScript Execution...")

        try:
            js_vulnerabilities = []

            response = self.session.get(self.target_url, timeout=10)

            # Look for dangerous JavaScript functions
            dangerous_functions = [
                'eval(',
                'setTimeout(',
                'setInterval(',
                'Function(',
                'document.write(',
                'innerHTML',
                'outerHTML',
                'insertAdjacentHTML'
            ]

            js_code_analysis = []
            for func in dangerous_functions:
                if func in response.text:
                    js_code_analysis.append({
                        'function': func,
                        'count': response.text.count(func),
                        'requires_input': self._check_function_requires_input(response.text, func)
                    })

            # Check for inline event handlers
            inline_events = [
                'onload=',
                'onclick=',
                'onmouseover=',
                'onerror=',
                'onfocus=',
                'onblur='
            ]

            inline_event_analysis = []
            for event in inline_events:
                if event in response.text:
                    inline_event_analysis.append({
                        'event': event,
                        'count': response.text.count(event)
                    })

            if js_code_analysis or inline_event_analysis:
                js_vulnerabilities.append({
                    'type': 'Potentially Dangerous JavaScript Functions',
                    'functions': js_code_analysis,
                    'inline_events': inline_event_analysis,
                    'risk_level': 'Medium'
                })

            findings = {
                'test_id': 'WSTG-CLNT-002',
                'test_name': 'JavaScript Execution Testing',
                'description': 'Testing for insecure JavaScript execution',
                'vulnerabilities': js_vulnerabilities,
                'javascript_functions_found': js_code_analysis,
                'inline_events_found': inline_event_analysis,
                'risk_level': 'Medium' if js_vulnerabilities else 'Low',
                'recommendations': [
                    'Avoid using eval() and similar functions',
                    'Use modern JavaScript frameworks with security features',
                    'Implement proper input validation',
                    'Use Content Security Policy (CSP)',
                    'Sanitize user input before processing'
                ]
            }

            self.findings.append(findings)
            return findings

        except Exception as e:
            print(f"[*] Error testing JavaScript execution: {e}")
            return None

    def test_html_injection(self):
        """WSTG-CLNT-003 - Test for HTML Injection"""
        print("[*] Testing HTML Injection...")

        try:
            html_vulnerabilities = []

            html_injection_payloads = [
                '<b>bold</b>',
                '<i>italic</i>',
                '<u>underline</u>',
                '<script>alert("HTMLi")</script>',
                '<img src=x onerror=alert("HTMLi")>',
                '<div>div content</div>',
                '<span>span content</span>',
                '<iframe src="javascript:alert(\'HTMLi\')"></iframe>'
            ]

            response = self.session.get(self.target_url, timeout=10)

            # Look for user input points
            input_points = self._find_user_input_points(response)

            for point in input_points:
                for payload in html_injection_payloads:
                    try:
                        test_data = self._prepare_test_data(point, payload)
                        if point.get('method', 'GET').upper() == 'POST':
                            test_response = self.session.post(point['action'], data=test_data, timeout=10)
                        else:
                            test_response = self.session.get(point['action'], params=test_data, timeout=10)

                        # Check if HTML was rendered
                        if self._check_html_rendered(test_response, payload):
                            html_vulnerabilities.append({
                                'type': 'HTML Injection',
                                'input_point': point['action'],
                                'method': point.get('method', 'GET'),
                                'parameter': point.get('parameter', 'unknown'),
                                'payload': payload,
                                'rendered': True,
                                'risk_level': 'High' if '<script' in payload else 'Medium'
                            })
                    except Exception as e:
                        continue

            findings = {
                'test_id': 'WSTG-CLNT-003',
                'test_name': 'HTML Injection Testing',
                'description': 'Testing for HTML injection vulnerabilities',
                'vulnerabilities': html_vulnerabilities,
                'vulnerability_count': len(html_vulnerabilities),
                'risk_level': 'High' if html_vulnerabilities else 'Low',
                'recommendations': [
                    'Encode all user input before rendering',
                    'Use textContent instead of innerHTML',
                    'Implement proper input validation',
                    'Use HTML sanitization libraries',
                    'Apply Content Security Policy (CSP)'
                ]
            }

            self.findings.append(findings)
            return findings

        except Exception as e:
            print(f"[*] Error testing HTML injection: {e}")
            return None

    def test_client_side_resource_manipulation(self):
        """WSTG-CLNT-004 - Test for Client-Side Resource Manipulation"""
        print("[*] Testing Client-Side Resource Manipulation...")

        try:
            resource_vulnerabilities = []

            response = self.session.get(self.target_url, timeout=10)

            # Check for external resource loading
            external_resources = self._find_external_resources(response)

            for resource in external_resources:
                # Test if resources can be manipulated
                try:
                    resource_response = self.session.get(resource, timeout=10)
                    if resource_response.status_code == 200:
                        resource_vulnerabilities.append({
                            'type': 'External Resource Loading',
                            'resource': resource,
                            'content_type': resource_response.headers.get('content-type', ''),
                            'size': len(resource_response.content),
                            'manipulable': self._is_resource_manipulable(resource_response),
                            'risk_level': 'Medium'
                        })
                except Exception as e:
                    continue

            # Check for JavaScript source maps
            if '.map' in response.text or 'sourceMappingURL' in response.text:
                resource_vulnerabilities.append({
                    'type': 'Source Map Disclosure',
                    'description': 'JavaScript source maps may expose source code',
                    'risk_level': 'Low'
                })

            # Check for debug/development resources
            debug_resources = ['debug', 'dev', 'test', 'console', 'logging']
            for resource in debug_resources:
                if resource in response.text.lower():
                    resource_vulnerabilities.append({
                        'type': 'Development Resource',
                        'resource_type': resource,
                        'risk_level': 'Low'
                    })

            findings = {
                'test_id': 'WSTG-CLNT-004',
                'test_name': 'Client-Side Resource Manipulation Testing',
                'description': 'Testing for client-side resource manipulation vulnerabilities',
                'vulnerabilities': resource_vulnerabilities,
                'external_resources_found': len([r for r in resource_vulnerabilities if r['type'] == 'External Resource Loading']),
                'risk_level': 'Medium' if resource_vulnerabilities else 'Low',
                'recommendations': [
                    'Implement Content Security Policy (CSP)',
                    'Use Subresource Integrity (SRI) for external resources',
                    'Remove source maps in production',
                    'Minimize external resource dependencies',
                    'Validate and sanitize all external resources'
                ]
            }

            self.findings.append(findings)
            return findings

        except Exception as e:
            print(f"[*] Error testing client-side resource manipulation: {e}")
            return None

    def test_captcha_bypass(self):
        """WSTG-CLNT-005 - Test for CAPTCHA Bypass"""
        print("[*] Testing CAPTCHA Bypass...")

        try:
            captcha_vulnerabilities = []

            response = self.session.get(self.target_url, timeout=10)

            # Look for CAPTCHA implementations
            captcha_indicators = [
                'captcha',
                'recaptcha',
                'g-recaptcha',
                'hcaptcha',
                'cf-turnstile',
                'verify',
                'challenge'
            ]

            captcha_found = False
            for indicator in captcha_indicators:
                if indicator.lower() in response.text.lower():
                    captcha_found = True
                    break

            if captcha_found:
                # Test CAPTCHA bypass techniques
                bypass_techniques = [
                    'No CAPTCHA response',
                    'Empty CAPTCHA response',
                    'Invalid CAPTCHA response',
                    'CAPTCHA bypass parameter'
                ]

                for technique in bypass_techniques:
                    try:
                        # Look for forms that might have CAPTCHA
                        forms = self._extract_forms(response)
                        for form in forms:
                            if any(keyword in str(form).lower() for keyword in ['submit', 'login', 'register']):
                                # Test form submission without CAPTCHA
                                test_data = self._prepare_form_data_without_captcha(form)
                                test_response = self.session.post(form['action'], data=test_data, timeout=10)

                                if 'success' in test_response.text.lower() or test_response.status_code == 302:
                                    captcha_vulnerabilities.append({
                                        'type': 'CAPTCHA Bypass',
                                        'technique': technique,
                                        'form': form['action'],
                                        'bypass_successful': True,
                                        'risk_level': 'High'
                                    })
                    except Exception as e:
                        continue

            findings = {
                'test_id': 'WSTG-CLNT-005',
                'test_name': 'CAPTCHA Bypass Testing',
                'description': 'Testing for CAPTCHA bypass vulnerabilities',
                'captcha_detected': captcha_found,
                'vulnerabilities': captcha_vulnerabilities,
                'vulnerability_count': len(captcha_vulnerabilities),
                'risk_level': 'High' if captcha_vulnerabilities else 'Low',
                'recommendations': [
                    'Implement server-side CAPTCHA validation',
                    'Use multiple CAPTCHA challenges',
                    'Implement rate limiting',
                    'Use CAPTCHA as part of a layered security approach',
                    'Monitor for CAPTCHA bypass attempts'
                ]
            }

            self.findings.append(findings)
            return findings

        except Exception as e:
            print(f"[*] Error testing CAPTCHA bypass: {e}")
            return None

    def test_clickjacking(self):
        """WSTG-CLNT-006 - Test for Clickjacking"""
        print("[*] Testing Clickjacking...")

        try:
            clickjacking_vulnerabilities = []

            # Check X-Frame-Options header
            response = self.session.get(self.target_url, timeout=10)
            x_frame_options = response.headers.get('X-Frame-Options', '').lower()
            content_security_policy = response.headers.get('Content-Security-Policy', '').lower()

            clickjacking_protection = {
                'x_frame_options': x_frame_options,
                'csp_frame_ancestors': 'frame-ancestors' in content_security_policy,
                'adequate_protection': False
            }

            # Check if protection is adequate
            if x_frame_options in ['deny', 'sameorigin'] or 'frame-ancestors' in content_security_policy:
                clickjacking_protection['adequate_protection'] = True

            if not clickjacking_protection['adequate_protection']:
                clickjacking_vulnerabilities.append({
                    'type': 'Missing Clickjacking Protection',
                    'x_frame_options': x_frame_options or 'Not set',
                    'csp_frame_ancestors': clickjacking_protection['csp_frame_ancestors'],
                    'risk_level': 'Medium'
                })

            findings = {
                'test_id': 'WSTG-CLNT-006',
                'test_name': 'Clickjacking Testing',
                'description': 'Testing for clickjacking vulnerabilities',
                'clickjacking_protection': clickjacking_protection,
                'vulnerabilities': clickjacking_vulnerabilities,
                'vulnerability_count': len(clickjacking_vulnerabilities),
                'risk_level': 'Medium' if clickjacking_vulnerabilities else 'Low',
                'recommendations': [
                    'Implement X-Frame-Options header',
                    'Use Content Security Policy with frame-ancestors',
                    'Consider JavaScript frame-busting techniques',
                    'Test applications in different iframe contexts'
                ]
            }

            self.findings.append(findings)
            return findings

        except Exception as e:
            print(f"[*] Error testing clickjacking: {e}")
            return None

    def test_local_storage_injection(self):
        """WSTG-CLNT-007 - Test for Local Storage Injection"""
        print("[*] Testing Local Storage Injection...")

        try:
            localStorage_vulnerabilities = []

            response = self.session.get(self.target_url, timeout=10)

            # Check for localStorage usage
            localStorage_usage = {
                'localStorage': 'localStorage' in response.text,
                'sessionStorage': 'sessionStorage' in response.text,
                'indexedDB': 'indexedDB' in response.text,
                'webSQL': 'openDatabase' in response.text
            }

            # Look for potential injection points in storage
            storage_injection_patterns = [
                r'localStorage\.[a-zA-Z_$][a-zA-Z0-9_$]*\s*=\s*[^;]+',
                r'sessionStorage\.[a-zA-Z_$][a-zA-Z0-9_$]*\s*=\s*[^;]+',
                r'localStorage\.setItem\([^)]+\)',
                r'sessionStorage\.setItem\([^)]+\)'
            ]

            storage_operations = []
            for pattern in storage_injection_patterns:
                matches = re.findall(pattern, response.text)
                for match in matches:
                    storage_operations.append({
                        'operation': match[:100],  # Limit length
                        'type': 'localStorage' if 'localStorage' in match else 'sessionStorage'
                    })

            if storage_operations:
                localStorage_vulnerabilities.append({
                    'type': 'Potential Storage Injection',
                    'storage_operations': storage_operations,
                    'requires_user_input': self._check_storage_input_dependency(response.text),
                    'risk_level': 'Medium'
                })

            findings = {
                'test_id': 'WSTG-CLNT-007',
                'test_name': 'Local Storage Injection Testing',
                'description': 'Testing for local storage injection vulnerabilities',
                'localStorage_usage': localStorage_usage,
                'vulnerabilities': localStorage_vulnerabilities,
                'storage_operations_found': len(storage_operations),
                'risk_level': 'Medium' if localStorage_vulnerabilities else 'Low',
                'recommendations': [
                    'Sanitize data before storing in localStorage',
                    'Avoid storing sensitive information in client-side storage',
                    'Validate data retrieved from storage',
                    'Use secure storage mechanisms',
                    'Implement proper error handling for storage operations'
                ]
            }

            self.findings.append(findings)
            return findings

        except Exception as e:
            print(f"[*] Error testing local storage injection: {e}")
            return None

    def run_comprehensive_test(self):
        """Run all client-side tests"""
        print("=" * 60)
        print("OWASP WSTG CLIENT-SIDE TESTING")
        print("=" * 60)

        tests = [
            self.test_dom_based_xss,
            self.test_javascript_execution,
            self.test_html_injection,
            self.test_client_side_resource_manipulation,
            self.test_captcha_bypass,
            self.test_clickjacking,
            self.test_local_storage_injection
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

    def _check_function_requires_input(self, content, function):
        """Check if function appears to process user input"""
        input_indicators = ['value', 'innerHTML', 'textContent', 'parameter', 'argument']
        for indicator in input_indicators:
            if function + indicator in content:
                return True
        return False

    def _find_user_input_points(self, response):
        """Find potential user input points in the response"""
        input_points = []

        # Extract forms
        forms = self._extract_forms(response)
        for form in forms:
            input_points.append({
                'action': form['action'],
                'method': form['method'],
                'type': 'form'
            })

        # Extract URL parameters
        parsed = urlparse(response.url)
        if parsed.query:
            input_points.append({
                'action': response.url,
                'method': 'GET',
                'type': 'url_parameter'
            })

        return input_points

    def _prepare_test_data(self, input_point, payload):
        """Prepare test data for injection testing"""
        if input_point.get('type') == 'form':
            # For forms, return simple data structure
            return {'test_field': payload}
        else:
            # For URL parameters
            return {'test': payload}

    def _check_html_rendered(self, response, payload):
        """Check if HTML payload was rendered in response"""
        # Simple check - in real implementation would use browser automation
        if any(tag in response.text for tag in ['<b>', '<i>', '<u>', '<div>', '<span>']):
            return True
        return False

    def _find_external_resources(self, response):
        """Find external resources loaded by the page"""
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(response.text, 'html.parser')

        resources = []

        # Find script sources
        scripts = soup.find_all('script', {'src': True})
        for script in scripts:
            resources.append(script['src'])

        # Find link resources (CSS, etc.)
        links = soup.find_all('link', {'href': True})
        for link in links:
            resources.append(link['href'])

        # Find images
        images = soup.find_all('img', {'src': True})
        for img in images:
            resources.append(img['src'])

        # Filter external resources
        external_resources = []
        for resource in resources:
            if resource.startswith(('http://', 'https://')) and urlparse(resource).netloc != urlparse(self.target_url).netloc:
                external_resources.append(resource)

        return external_resources

    def _is_resource_manipulable(self, response):
        """Check if resource can be manipulated"""
        content_type = response.headers.get('content-type', '')
        size = len(response.content)

        # Simple heuristic - larger JavaScript files might be manipulable
        if 'javascript' in content_type and size > 1000:
            return True
        elif 'css' in content_type and size > 500:
            return True

        return False

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

    def _prepare_form_data_without_captcha(self, form):
        """Prepare form data without CAPTCHA"""
        data = {}
        for inp in form['inputs']:
            if inp['type'] != 'hidden' or 'captcha' not in inp['name'].lower():
                data[inp['name']] = inp['value'] or 'test'
        return data

    def _check_storage_input_dependency(self, content):
        """Check if storage operations depend on user input"""
        input_patterns = ['value', 'form', 'input', 'parameter', 'argument']
        content_lower = content.lower()

        for pattern in input_patterns:
            if pattern in content_lower and 'storage' in content_lower:
                return True

        return False

def main():
    if len(sys.argv) < 2:
        print("Usage: python client_side_tester.py <target_url>")
        sys.exit(1)

    target_url = sys.argv[1]

    try:
        tester = ClientSideTester(target_url)
        results = tester.run_comprehensive_test()

        if results:
            # Generate report
            report = generate_report(
                target_url=target_url,
                test_results=results,
                test_category='Client-Side',
                timestamp=time.strftime('%Y-%m-%d %H:%M:%S')
            )

            # Save results
            save_findings(report, 'client_side_test_results.json')

            print(f"\n[*] Test completed. Results saved to client_side_test_results.json")
        else:
            print("[*] No tests completed successfully")

    except KeyboardInterrupt:
        print("\n[*] Test interrupted by user")
    except Exception as e:
        print(f"[*] Error: {e}")

if __name__ == "__main__":
    main()
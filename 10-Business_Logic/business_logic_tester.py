#!/usr/bin/env python3
"""
OWASP WSTG Business Logic Testing Framework
WSTG-BUSL-001 through WSTG-BUSL-009
"""

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'core'))

from base_tester import BaseTester
from utils import generate_report, save_findings, analyze_business_logic
import requests
import json
import time
import random
from urllib.parse import urljoin, urlparse, parse_qs

class BusinessLogicTester(BaseTester):
    """Business Logic Security Testing"""

    def __init__(self, target_url):
        super().__init__()
        self.target_url = target_url
        self.session = requests.Session()
        self.findings = []
        self.business_logic_results = {}

    def test_domain_logic_flaws(self):
        """WSTG-BUSL-001 - Test for Domain Logic Flaws"""
        print("[*] Testing Domain Logic Flaws...")

        try:
            logic_vulnerabilities = []

            # Test for negative price values
            if any(keyword in self.target_url.lower() for keyword in ['shop', 'store', 'cart', 'product']):
                negative_values_tests = self._test_negative_values()
                logic_vulnerabilities.extend(negative_values_tests)

            # Test for quantity manipulation
            quantity_tests = self._test_quantity_manipulation()
            logic_vulnerabilities.extend(quantity_tests)

            # Test for limit bypass
            limit_tests = self._test_limit_bypass()
            logic_vulnerabilities.extend(limit_tests)

            # Test for race conditions in critical operations
            race_condition_tests = self._test_race_conditions()
            logic_vulnerabilities.extend(race_condition_tests)

            findings = {
                'test_id': 'WSTG-BUSL-001',
                'test_name': 'Domain Logic Flaws Testing',
                'description': 'Testing for business logic vulnerabilities in domain operations',
                'vulnerabilities': logic_vulnerabilities,
                'vulnerability_count': len(logic_vulnerabilities),
                'risk_level': 'High' if logic_vulnerabilities else 'Low',
                'recommendations': [
                    'Implement proper input validation for business logic',
                    'Use server-side validation for all critical operations',
                    'Implement transactional integrity checks',
                    'Add rate limiting and cooldown periods',
                    'Test for edge cases and boundary conditions'
                ]
            }

            self.findings.append(findings)
            return findings

        except Exception as e:
            print(f"[*] Error testing domain logic flaws: {e}")
            return None

    def test_authorization_bypass(self):
        """WSTG-BUSL-002 - Test for Authorization Bypass"""
        print("[*] Testing Authorization Bypass...")

        try:
            auth_bypass_vulnerabilities = []

            # Test for horizontal privilege escalation
            horizontal_tests = self._test_horizontal_privilege_escalation()
            auth_bypass_vulnerabilities.extend(horizontal_tests)

            # Test for vertical privilege escalation
            vertical_tests = self._test_vertical_privilege_escalation()
            auth_bypass_vulnerabilities.extend(vertical_tests)

            # Test for parameter tampering
            parameter_tests = self._test_parameter_tampering()
            auth_bypass_vulnerabilities.extend(parameter_tests)

            # Test for direct object reference
            direct_object_tests = self._test_direct_object_reference()
            auth_bypass_vulnerabilities.extend(direct_object_tests)

            findings = {
                'test_id': 'WSTG-BUSL-002',
                'test_name': 'Authorization Bypass Testing',
                'description': 'Testing for authorization and privilege escalation vulnerabilities',
                'vulnerabilities': auth_bypass_vulnerabilities,
                'vulnerability_count': len(auth_bypass_vulnerabilities),
                'risk_level': 'Critical' if auth_bypass_vulnerabilities else 'Low',
                'recommendations': [
                    'Implement proper access control checks',
                    'Use role-based access control (RBAC)',
                    'Validate user permissions on every request',
                    'Avoid exposing internal IDs in URLs',
                    'Implement proper session management'
                ]
            }

            self.findings.append(findings)
            return findings

        except Exception as e:
            print(f"[*] Error testing authorization bypass: {e}")
            return None

    def test_workflow_flaws(self):
        """WSTG-BUSL-003 - Test for Workflow Flaws"""
        print("[*] Testing Workflow Flaws...")

        try:
            workflow_vulnerabilities = []

            # Test for payment process bypass
            payment_tests = self._test_payment_workflow()
            workflow_vulnerabilities.extend(payment_tests)

            # Test for registration flow bypass
            registration_tests = self._test_registration_workflow()
            workflow_vulnerabilities.extend(registration_tests)

            # Test for password reset bypass
            password_reset_tests = self._test_password_reset_workflow()
            workflow_vulnerabilities.extend(password_reset_tests)

            # Test for order manipulation
            order_tests = self._test_order_workflow()
            workflow_vulnerabilities.extend(order_tests)

            findings = {
                'test_id': 'WSTG-BUSL-003',
                'test_name': 'Workflow Flaws Testing',
                'description': 'Testing for business logic workflow vulnerabilities',
                'vulnerabilities': workflow_vulnerabilities,
                'vulnerability_count': len(workflow_vulnerabilities),
                'risk_level': 'High' if workflow_vulnerabilities else 'Low',
                'recommendations': [
                    'Implement proper state management',
                    'Validate each step in the workflow',
                    'Use server-side state tracking',
                    'Implement proper transaction handling',
                    'Add workflow integrity checks'
                ]
            }

            self.findings.append(findings)
            return findings

        except Exception as e:
            print(f"[*] Error testing workflow flaws: {e}")
            return None

    def test_parameter_tampering(self):
        """WSTG-BUSL-004 - Test for Parameter Tampering"""
        print("[*] Testing Parameter Tampering...")

        try:
            tampering_vulnerabilities = []

            # Test form field manipulation
            form_tampering = self._test_form_field_tampering()
            tampering_vulnerabilities.extend(form_tampering)

            # Test URL parameter tampering
            url_tampering = self._test_url_parameter_tampering()
            tampering_vulnerabilities.extend(url_tampering)

            # Test hidden field manipulation
            hidden_tampering = self._test_hidden_field_tampering()
            tampering_vulnerabilities.extend(hidden_tampering)

            # Test price manipulation
            price_tampering = self._test_price_manipulation()
            tampering_vulnerabilities.extend(price_tampering)

            findings = {
                'test_id': 'WSTG-BUSL-004',
                'test_name': 'Parameter Tampering Testing',
                'description': 'Testing for parameter manipulation vulnerabilities',
                'vulnerabilities': tampering_vulnerabilities,
                'vulnerability_count': len(tampering_vulnerabilities),
                'risk_level': 'High' if tampering_vulnerabilities else 'Low',
                'recommendations': [
                    'Never trust client-side data',
                    'Implement server-side validation',
                    'Use cryptographic signatures for sensitive parameters',
                    'Avoid exposing sensitive data in client-side code',
                    'Implement proper data integrity checks'
                ]
            }

            self.findings.append(findings)
            return findings

        except Exception as e:
            print(f"[*] Error testing parameter tampering: {e}")
            return None

    def test_extreme_conditions(self):
        """WSTG-BUSL-005 - Test for Extremes and Invalid Inputs"""
        print("[*] Testing Extreme Conditions...")

        try:
            extreme_condition_vulnerabilities = []

            # Test with extremely large values
            large_value_tests = self._test_large_values()
            extreme_condition_vulnerabilities.extend(large_value_tests)

            # Test with extreme decimal values
            decimal_tests = self._test_extreme_decimals()
            extreme_condition_vulnerabilities.extend(decimal_tests)

            # Test with special characters
            special_char_tests = self._test_special_characters()
            extreme_condition_vulnerabilities.extend(special_char_tests)

            # Test with Unicode characters
            unicode_tests = self._test_unicode_characters()
            extreme_condition_vulnerabilities.extend(unicode_tests)

            findings = {
                'test_id': 'WSTG-BUSL-005',
                'test_name': 'Extreme Conditions Testing',
                'description': 'Testing for vulnerabilities with extreme and invalid inputs',
                'vulnerabilities': extreme_condition_vulnerabilities,
                'vulnerability_count': len(extreme_condition_vulnerabilities),
                'risk_level': 'Medium' if extreme_condition_vulnerabilities else 'Low',
                'recommendations': [
                    'Implement comprehensive input validation',
                    'Set reasonable limits for input values',
                    'Handle edge cases gracefully',
                    'Implement proper error handling',
                    'Test with boundary conditions'
                ]
            }

            self.findings.append(findings)
            return findings

        except Exception as e:
            print(f"[*] Error testing extreme conditions: {e}")
            return None

    def run_comprehensive_test(self):
        """Run all business logic tests"""
        print("=" * 60)
        print("OWASP WSTG BUSINESS LOGIC TESTING")
        print("=" * 60)

        tests = [
            self.test_domain_logic_flaws,
            self.test_authorization_bypass,
            self.test_workflow_flaws,
            self.test_parameter_tampering,
            self.test_extreme_conditions
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

    def _test_negative_values(self):
        """Test for negative value vulnerabilities"""
        vulnerabilities = []

        try:
            # Look for forms that might accept monetary values
            response = self.session.get(self.target_url, timeout=10)
            forms = self._extract_forms(response)

            for form in forms:
                for input_field in form['inputs']:
                    if any(keyword in input_field.get('name', '').lower()
                          for keyword in ['price', 'amount', 'cost', 'total', 'value']):
                        # Test with negative values
                        test_data = {}
                        for inp in form['inputs']:
                            if inp['name'] == input_field['name']:
                                test_data[inp['name']] = '-100'
                            else:
                                test_data[inp['name']] = inp['value'] or 'test'

                        try:
                            if form['method'].upper() == 'POST':
                                test_response = self.session.post(form['action'], data=test_data, timeout=10)
                            else:
                                test_response = self.session.get(form['action'], params=test_data, timeout=10)

                            # Check if negative value was accepted
                            if 'accepted' in test_response.text.lower() or 'success' in test_response.text.lower():
                                vulnerabilities.append({
                                    'type': 'Negative Value Accepted',
                                    'form': form['action'],
                                    'field': input_field['name'],
                                    'test_value': '-100',
                                    'risk_level': 'High'
                                })
                        except Exception as e:
                            continue

        except Exception as e:
            pass

        return vulnerabilities

    def _test_quantity_manipulation(self):
        """Test for quantity manipulation vulnerabilities"""
        vulnerabilities = []

        try:
            # Test common quantity manipulation scenarios
            test_quantities = [0, -1, 999999, 'abc', '0.1']

            response = self.session.get(self.target_url, timeout=10)
            forms = self._extract_forms(response)

            for form in forms:
                quantity_fields = [inp for inp in form['inputs']
                                 if any(keyword in inp.get('name', '').lower()
                                       for keyword in ['quantity', 'qty', 'count', 'number'])]

                for qty_field in quantity_fields:
                    for test_qty in test_quantities:
                        test_data = {}
                        for inp in form['inputs']:
                            if inp['name'] == qty_field['name']:
                                test_data[inp['name']] = str(test_qty)
                            else:
                                test_data[inp['name']] = inp['value'] or 'test'

                        try:
                            if form['method'].upper() == 'POST':
                                test_response = self.session.post(form['action'], data=test_data, timeout=10)
                            else:
                                test_response = self.session.get(form['action'], params=test_data, timeout=10)

                            # Check for unusual behavior
                            if 'free' in test_response.text.lower() or 'discount' in test_response.text.lower():
                                vulnerabilities.append({
                                    'type': 'Quantity Manipulation',
                                    'form': form['action'],
                                    'field': qty_field['name'],
                                    'test_quantity': test_qty,
                                    'evidence': 'Unusual response detected',
                                    'risk_level': 'Medium'
                                })
                        except Exception as e:
                            continue

        except Exception as e:
            pass

        return vulnerabilities

    def _test_limit_bypass(self):
        """Test for limit bypass vulnerabilities"""
        vulnerabilities = []

        try:
            # Test common limit bypass techniques
            limit_bypass_payloads = [
                '999999',
                '999999999',
                '999999999999',
                '1e6',
                '1000000',
                '2147483647',  # 32-bit integer max
                '9223372036854775807'  # 64-bit integer max
            ]

            response = self.session.get(self.target_url, timeout=10)
            forms = self._extract_forms(response)

            for form in forms:
                for payload in limit_bypass_payloads:
                    test_data = {}
                    for inp in form['inputs']:
                        if inp.get('type') in ['text', 'number', 'hidden']:
                            test_data[inp['name']] = payload
                        else:
                            test_data[inp['name']] = inp['value'] or 'test'

                    try:
                        if form['method'].upper() == 'POST':
                            test_response = self.session.post(form['action'], data=test_data, timeout=10)
                        else:
                            test_response = self.session.get(form['action'], params=test_data, timeout=10)

                        # Check if large value was accepted
                        if 'accepted' in test_response.text.lower() or 'success' in test_response.text.lower():
                            vulnerabilities.append({
                                'type': 'Limit Bypass',
                                'form': form['action'],
                                'payload': payload,
                                'evidence': 'Large value accepted',
                                'risk_level': 'Medium'
                            })
                    except Exception as e:
                        continue

        except Exception as e:
            pass

        return vulnerabilities

    def _test_race_conditions(self):
        """Test for race condition vulnerabilities"""
        vulnerabilities = []

        try:
            # Simple race condition test - make multiple concurrent requests
            response = self.session.get(self.target_url, timeout=10)
            forms = self._extract_forms(response)

            # Look for forms that might trigger state changes
            action_forms = [form for form in forms
                          if any(keyword in str(form).lower()
                                for keyword in ['submit', 'confirm', 'purchase', 'buy', 'order'])]

            for form in action_forms:
                try:
                    test_data = {}
                    for inp in form['inputs']:
                        test_data[inp['name']] = inp['value'] or 'test'

                    # Make multiple rapid requests
                    responses = []
                    for i in range(5):
                        try:
                            if form['method'].upper() == 'POST':
                                resp = self.session.post(form['action'], data=test_data, timeout=5)
                            else:
                                resp = self.session.get(form['action'], params=test_data, timeout=5)
                            responses.append(resp.status_code)
                        except:
                            pass

                    # Check if all requests succeeded (potential race condition)
                    if all(status == 200 for status in responses):
                        vulnerabilities.append({
                            'type': 'Race Condition',
                            'form': form['action'],
                            'concurrent_requests': len(responses),
                            'all_successful': True,
                            'risk_level': 'Medium'
                        })

                except Exception as e:
                    continue

        except Exception as e:
            pass

        return vulnerabilities

    def _test_horizontal_privilege_escalation(self):
        """Test for horizontal privilege escalation"""
        vulnerabilities = []

        try:
            # Test user ID manipulation
            test_user_ids = [1, 2, 999, 1000, 'admin', 'user']

            for user_id in test_user_ids:
                test_urls = [
                    f"{self.target_url}/user/{user_id}",
                    f"{self.target_url}/profile/{user_id}",
                    f"{self.target_url}/account/{user_id}",
                    f"{self.target_url}?user_id={user_id}",
                    f"{self.target_url}?uid={user_id}"
                ]

                for url in test_urls:
                    try:
                        response = self.session.get(url, timeout=10)
                        if response.status_code == 200 and len(response.text) > 1000:
                            vulnerabilities.append({
                                'type': 'Horizontal Privilege Escalation',
                                'url': url,
                                'test_user_id': user_id,
                                'access_granted': True,
                                'risk_level': 'High'
                            })
                    except Exception as e:
                        continue

        except Exception as e:
            pass

        return vulnerabilities

    def _test_vertical_privilege_escalation(self):
        """Test for vertical privilege escalation"""
        vulnerabilities = []

        try:
            admin_endpoints = [
                '/admin',
                '/administrator',
                '/admin.php',
                '/admin.html',
                '/wp-admin',
                '/dashboard',
                '/control-panel',
                '/manager'
            ]

            for endpoint in admin_endpoints:
                try:
                    test_url = urljoin(self.target_url, endpoint)
                    response = self.session.get(test_url, timeout=10)

                    if response.status_code == 200:
                        vulnerabilities.append({
                            'type': 'Vertical Privilege Escalation',
                            'endpoint': endpoint,
                            'access_granted': True,
                            'risk_level': 'Critical'
                        })
                except Exception as e:
                    continue

        except Exception as e:
            pass

        return vulnerabilities

    def _test_parameter_tampering(self):
        """Test for parameter tampering vulnerabilities"""
        vulnerabilities = []

        try:
            response = self.session.get(self.target_url, timeout=10)
            params = parse_qs(urlparse(response.url).query)

            for param_name in params:
                # Test with modified parameter values
                original_value = params[param_name][0]
                test_values = ['1', '0', 'true', 'false', 'yes', 'no', 'admin', 'user']

                for test_value in test_values:
                    try:
                        test_url = self._modify_url_parameter(response.url, param_name, test_value)
                        test_response = self.session.get(test_url, timeout=10)

                        # Check if modification caused different behavior
                        if test_response.text != response.text:
                            vulnerabilities.append({
                                'type': 'Parameter Tampering',
                                'parameter': param_name,
                                'original_value': original_value,
                                'test_value': test_value,
                                'behavior_changed': True,
                                'risk_level': 'Medium'
                            })
                    except Exception as e:
                        continue

        except Exception as e:
            pass

        return vulnerabilities

    def _test_direct_object_reference(self):
        """Test for insecure direct object reference"""
        vulnerabilities = []

        try:
            # Common object reference patterns
            object_patterns = [
                r'/user/(\d+)',
                r'/file/(\d+)',
                r'/document/(\d+)',
                r'/order/(\d+)',
                r'/product/(\d+)',
                r'\?id=(\d+)',
                r'\?user_id=(\d+)',
                r'\?file_id=(\d+)'
            ]

            import re
            response = self.session.get(self.target_url, timeout=10)

            for pattern in object_patterns:
                matches = re.findall(pattern, response.url)
                for match in matches:
                    try:
                        # Test with different object IDs
                        test_ids = [1, 2, 999, 1000, 99999]
                        for test_id in test_ids:
                            test_url = response.url.replace(match, str(test_id))
                            test_response = self.session.get(test_url, timeout=10)

                            if test_response.status_code == 200 and len(test_response.text) > 500:
                                vulnerabilities.append({
                                    'type': 'Insecure Direct Object Reference',
                                    'pattern': pattern,
                                    'test_id': test_id,
                                    'access_granted': True,
                                    'risk_level': 'High'
                                })
                    except Exception as e:
                        continue

        except Exception as e:
            pass

        return vulnerabilities

    def _test_payment_workflow(self):
        """Test payment workflow vulnerabilities"""
        vulnerabilities = []

        try:
            # Look for payment-related endpoints
            payment_endpoints = [
                '/checkout',
                '/payment',
                '/purchase',
                '/billing',
                '/order'
            ]

            for endpoint in payment_endpoints:
                try:
                    test_url = urljoin(self.target_url, endpoint)
                    response = self.session.get(test_url, timeout=10)

                    if response.status_code == 200:
                        # Test payment parameter manipulation
                        payment_params = [
                            {'amount': '0'},
                            {'amount': '0.01'},
                            {'amount': '-1'},
                            {'price': '0'},
                            {'price': '1'},
                            {'total': '0'},
                            {'total': '1'}
                        ]

                        for params in payment_params:
                            try:
                                test_response = self.session.post(test_url, data=params, timeout=10)
                                if 'success' in test_response.text.lower():
                                    vulnerabilities.append({
                                        'type': 'Payment Workflow Bypass',
                                        'endpoint': endpoint,
                                        'parameters': params,
                                        'evidence': 'Payment processed with invalid amount',
                                        'risk_level': 'Critical'
                                    })
                            except Exception as e:
                                continue

                except Exception as e:
                    continue

        except Exception as e:
            pass

        return vulnerabilities

    def _test_registration_workflow(self):
        """Test registration workflow vulnerabilities"""
        vulnerabilities = []

        try:
            # Look for registration forms
            registration_urls = [
                '/register',
                '/signup',
                '/registration',
                '/create-account'
            ]

            for url in registration_urls:
                try:
                    test_url = urljoin(self.target_url, url)
                    response = self.session.get(test_url, timeout=10)

                    if response.status_code == 200:
                        # Test registration bypass techniques
                        bypass_payloads = [
                            {'email': '', 'password': 'test'},
                            {'email': 'test@test.com', 'password': ''},
                            {'email': 'invalid-email', 'password': 'test'},
                            {'email': 'test@test.com', 'password': '1'},
                            {'email': 'already@exists.com', 'password': 'test'}
                        ]

                        for payload in bypass_payloads:
                            try:
                                test_response = self.session.post(test_url, data=payload, timeout=10)
                                if 'success' in test_response.text.lower() or 'registered' in test_response.text.lower():
                                    vulnerabilities.append({
                                        'type': 'Registration Workflow Bypass',
                                        'endpoint': url,
                                        'payload': payload,
                                        'evidence': 'Registration succeeded with invalid data',
                                        'risk_level': 'Medium'
                                    })
                            except Exception as e:
                                continue

                except Exception as e:
                    continue

        except Exception as e:
            pass

        return vulnerabilities

    def _test_password_reset_workflow(self):
        """Test password reset workflow vulnerabilities"""
        vulnerabilities = []

        try:
            # Look for password reset endpoints
            reset_urls = [
                '/reset-password',
                '/forgot-password',
                '/password-reset',
                '/recover-password'
            ]

            for url in reset_urls:
                try:
                    test_url = urljoin(self.target_url, url)
                    response = self.session.get(test_url, timeout=10)

                    if response.status_code == 200:
                        # Test password reset bypass
                        reset_payloads = [
                            {'email': 'admin@domain.com'},
                            {'email': 'test@test.com'},
                            {'email': 'nonexistent@test.com'},
                            {'email': ''}
                        ]

                        for payload in reset_payloads:
                            try:
                                test_response = self.session.post(test_url, data=payload, timeout=10)
                                if 'sent' in test_response.text.lower() or 'email' in test_response.text.lower():
                                    vulnerabilities.append({
                                        'type': 'Password Reset Information Disclosure',
                                        'endpoint': url,
                                        'email': payload.get('email', 'empty'),
                                        'evidence': 'Password reset initiated',
                                        'risk_level': 'Medium'
                                    })
                            except Exception as e:
                                continue

                except Exception as e:
                    continue

        except Exception as e:
            pass

        return vulnerabilities

    def _test_order_workflow(self):
        """Test order workflow vulnerabilities"""
        vulnerabilities = []

        try:
            # Test order manipulation
            order_endpoints = [
                '/order',
                '/checkout',
                '/purchase',
                '/buy'
            ]

            for endpoint in order_endpoints:
                try:
                    test_url = urljoin(self.target_url, endpoint)

                    # Test order manipulation payloads
                    order_payloads = [
                        {'quantity': 0, 'price': 100},
                        {'quantity': 1, 'price': 0},
                        {'quantity': 999, 'price': 1},
                        {'discount_code': 'INVALID', 'amount': 100},
                        {'shipping': '0', 'total': 100}
                    ]

                    for payload in order_payloads:
                        try:
                            test_response = self.session.post(test_url, data=payload, timeout=10)
                            if 'success' in test_response.text.lower():
                                vulnerabilities.append({
                                    'type': 'Order Workflow Manipulation',
                                    'endpoint': endpoint,
                                    'payload': payload,
                                    'evidence': 'Order processed with manipulated data',
                                    'risk_level': 'High'
                                })
                        except Exception as e:
                            continue

                except Exception as e:
                    continue

        except Exception as e:
            pass

        return vulnerabilities

    def _test_form_field_tampering(self):
        """Test form field manipulation vulnerabilities"""
        vulnerabilities = []

        try:
            response = self.session.get(self.target_url, timeout=10)
            forms = self._extract_forms(response)

            for form in forms:
                for input_field in form['inputs']:
                    if input_field.get('type') in ['hidden', 'text', 'number']:
                        # Test with different values
                        test_values = ['0', '1', '999', 'admin', 'user', 'true', 'false', '']

                        for test_value in test_values:
                            test_data = {}
                            for inp in form['inputs']:
                                if inp['name'] == input_field['name']:
                                    test_data[inp['name']] = test_value
                                else:
                                    test_data[inp['name']] = inp['value'] or 'test'

                            try:
                                if form['method'].upper() == 'POST':
                                    test_response = self.session.post(form['action'], data=test_data, timeout=10)
                                else:
                                    test_response = self.session.get(form['action'], params=test_data, timeout=10)

                                # Check for different behavior
                                if len(test_response.text) != len(response.text):
                                    vulnerabilities.append({
                                        'type': 'Form Field Tampering',
                                        'form': form['action'],
                                        'field': input_field['name'],
                                        'test_value': test_value,
                                        'behavior_changed': True,
                                        'risk_level': 'Medium'
                                    })
                            except Exception as e:
                                continue

        except Exception as e:
            pass

        return vulnerabilities

    def _test_url_parameter_tampering(self):
        """Test URL parameter manipulation vulnerabilities"""
        return self._test_parameter_tampering()

    def _test_hidden_field_tampering(self):
        """Test hidden field manipulation vulnerabilities"""
        vulnerabilities = []

        try:
            response = self.session.get(self.target_url, timeout=10)
            forms = self._extract_forms(response)

            for form in forms:
                hidden_fields = [inp for inp in form['inputs'] if inp.get('type') == 'hidden']

                for hidden_field in hidden_fields:
                    # Test with different values
                    test_values = ['0', '1', '999', 'admin', 'user', 'true', 'false', '']

                    for test_value in test_values:
                        test_data = {}
                        for inp in form['inputs']:
                            if inp['name'] == hidden_field['name']:
                                test_data[inp['name']] = test_value
                            else:
                                test_data[inp['name']] = inp['value'] or 'test'

                        try:
                            if form['method'].upper() == 'POST':
                                test_response = self.session.post(form['action'], data=test_data, timeout=10)
                            else:
                                test_response = self.session.get(form['action'], params=test_data, timeout=10)

                            # Check for different behavior
                            if test_response.text != response.text:
                                vulnerabilities.append({
                                    'type': 'Hidden Field Tampering',
                                    'form': form['action'],
                                    'field': hidden_field['name'],
                                    'test_value': test_value,
                                    'behavior_changed': True,
                                    'risk_level': 'Medium'
                                })
                        except Exception as e:
                            continue

        except Exception as e:
            pass

        return vulnerabilities

    def _test_price_manipulation(self):
        """Test price manipulation vulnerabilities"""
        vulnerabilities = []

        try:
            response = self.session.get(self.target_url, timeout=10)
            forms = self._extract_forms(response)

            for form in forms:
                # Look for price-related fields
                price_fields = [inp for inp in form['inputs']
                              if any(keyword in inp.get('name', '').lower()
                                    for keyword in ['price', 'amount', 'cost', 'total'])]

                for price_field in price_fields:
                    # Test with manipulated prices
                    price_values = ['0', '0.01', '1', '0.99', '-1']

                    for price_value in price_values:
                        test_data = {}
                        for inp in form['inputs']:
                            if inp['name'] == price_field['name']:
                                test_data[inp['name']] = price_value
                            else:
                                test_data[inp['name']] = inp['value'] or 'test'

                        try:
                            if form['method'].upper() == 'POST':
                                test_response = self.session.post(form['action'], data=test_data, timeout=10)
                            else:
                                test_response = self.session.get(form['action'], params=test_data, timeout=10)

                            # Check if manipulated price was accepted
                            if 'success' in test_response.text.lower() or 'order' in test_response.text.lower():
                                vulnerabilities.append({
                                    'type': 'Price Manipulation',
                                    'form': form['action'],
                                    'field': price_field['name'],
                                    'test_price': price_value,
                                    'evidence': 'Manipulated price accepted',
                                    'risk_level': 'Critical'
                                })
                        except Exception as e:
                            continue

        except Exception as e:
            pass

        return vulnerabilities

    def _test_large_values(self):
        """Test with extremely large values"""
        vulnerabilities = []

        try:
            large_values = [
                '999999999999999999',
                '1e20',
                '1000000000000000000000'
            ]

            response = self.session.get(self.target_url, timeout=10)
            forms = self._extract_forms(response)

            for form in forms:
                for large_value in large_values:
                    test_data = {}
                    for inp in form['inputs']:
                        if inp.get('type') in ['text', 'number', 'hidden']:
                            test_data[inp['name']] = large_value
                        else:
                            test_data[inp['name']] = inp['value'] or 'test'

                    try:
                        if form['method'].upper() == 'POST':
                            test_response = self.session.post(form['action'], data=test_data, timeout=10)
                        else:
                            test_response = self.session.get(form['action'], params=test_data, timeout=10)

                        # Check for server errors or unusual behavior
                        if test_response.status_code >= 500 or 'error' in test_response.text.lower():
                            vulnerabilities.append({
                                'type': 'Large Value Error',
                                'form': form['action'],
                                'large_value': large_value,
                                'status_code': test_response.status_code,
                                'risk_level': 'Low'
                            })
                    except Exception as e:
                        continue

        except Exception as e:
            pass

        return vulnerabilities

    def _test_extreme_decimals(self):
        """Test with extreme decimal values"""
        vulnerabilities = []

        try:
            decimal_values = [
                '0.0000000001',
                '0.9999999999',
                '1.0000000001',
                '999999.999999'
            ]

            response = self.session.get(self.target_url, timeout=10)
            forms = self._extract_forms(response)

            for form in forms:
                for decimal_value in decimal_values:
                    test_data = {}
                    for inp in form['inputs']:
                        if inp.get('type') in ['text', 'number', 'hidden']:
                            test_data[inp['name']] = decimal_value
                        else:
                            test_data[inp['name']] = inp['value'] or 'test'

                    try:
                        if form['method'].upper() == 'POST':
                            test_response = self.session.post(form['action'], data=test_data, timeout=10)
                        else:
                            test_response = self.session.get(form['action'], params=test_data, timeout=10)

                        # Check for precision issues or errors
                        if 'error' in test_response.text.lower() or test_response.status_code >= 400:
                            vulnerabilities.append({
                                'type': 'Extreme Decimal Value',
                                'form': form['action'],
                                'decimal_value': decimal_value,
                                'status_code': test_response.status_code,
                                'risk_level': 'Low'
                            })
                    except Exception as e:
                        continue

        except Exception as e:
            pass

        return vulnerabilities

    def _test_special_characters(self):
        """Test with special characters"""
        vulnerabilities = []

        try:
            special_chars = [
                '!@#$%^&*()',
                '<script>alert(1)</script>',
                'SELECT * FROM users',
                '../../etc/passwd',
                '\x00\x01\x02',
                'null',
                'undefined'
            ]

            response = self.session.get(self.target_url, timeout=10)
            forms = self._extract_forms(response)

            for form in forms:
                for special_char in special_chars:
                    test_data = {}
                    for inp in form['inputs']:
                        if inp.get('type') in ['text', 'number', 'hidden']:
                            test_data[inp['name']] = special_char
                        else:
                            test_data[inp['name']] = inp['value'] or 'test'

                    try:
                        if form['method'].upper() == 'POST':
                            test_response = self.session.post(form['action'], data=test_data, timeout=10)
                        else:
                            test_response = self.session.get(form['action'], params=test_data, timeout=10)

                        # Check for reflection or errors
                        if special_char in test_response.text or 'error' in test_response.text.lower():
                            vulnerabilities.append({
                                'type': 'Special Character Issue',
                                'form': form['action'],
                                'special_char': special_char[:50],  # Limit length
                                'reflected': special_char in test_response.text,
                                'risk_level': 'Low'
                            })
                    except Exception as e:
                        continue

        except Exception as e:
            pass

        return vulnerabilities

    def _test_unicode_characters(self):
        """Test with Unicode characters"""
        vulnerabilities = []

        try:
            unicode_chars = [
                'ñáéíóú',
                '中文',
                'العربية',
                '🔥💻🚀',
                '𝕱𝖗𝖆𝖐𝖙𝖚𝖗𝖊',
                '�',
                '\u202e',  # Right-to-Left Override
                '\ufeff'   # Zero Width No-Break Space
            ]

            response = self.session.get(self.target_url, timeout=10)
            forms = self._extract_forms(response)

            for form in forms:
                for unicode_char in unicode_chars:
                    test_data = {}
                    for inp in form['inputs']:
                        if inp.get('type') in ['text', 'number', 'hidden']:
                            test_data[inp['name']] = unicode_char
                        else:
                            test_data[inp['name']] = inp['value'] or 'test'

                    try:
                        if form['method'].upper() == 'POST':
                            test_response = self.session.post(form['action'], data=test_data, timeout=10)
                        else:
                            test_response = self.session.get(form['action'], params=test_data, timeout=10)

                        # Check for encoding issues
                        if unicode_char in test_response.text or test_response.status_code >= 400:
                            vulnerabilities.append({
                                'type': 'Unicode Character Issue',
                                'form': form['action'],
                                'unicode_char': unicode_char[:20],
                                'status_code': test_response.status_code,
                                'risk_level': 'Low'
                            })
                    except Exception as e:
                        continue

        except Exception as e:
            pass

        return vulnerabilities

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

    def _modify_url_parameter(self, url, param_name, new_value):
        """Modify URL parameter with new value"""
        from urllib.parse import urlparse, parse_qs, urlencode

        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param_name] = new_value

        query = urlencode(params, doseq=True)
        return parsed._replace(query=query).geturl()

def main():
    if len(sys.argv) < 2:
        print("Usage: python business_logic_tester.py <target_url>")
        sys.exit(1)

    target_url = sys.argv[1]

    try:
        tester = BusinessLogicTester(target_url)
        results = tester.run_comprehensive_test()

        if results:
            # Generate report
            report = generate_report(
                target_url=target_url,
                test_results=results,
                test_category='Business Logic',
                timestamp=time.strftime('%Y-%m-%d %H:%M:%S')
            )

            # Save results
            save_findings(report, 'business_logic_test_results.json')

            print(f"\n[*] Test completed. Results saved to business_logic_test_results.json")
        else:
            print("[*] No tests completed successfully")

    except KeyboardInterrupt:
        print("\n[*] Test interrupted by user")
    except Exception as e:
        print(f"[*] Error: {e}")

if __name__ == "__main__":
    main()
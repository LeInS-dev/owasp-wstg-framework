#!/usr/bin/env python3
"""
OWASP WSTG Session Management Testing Framework
WSTG-SESS-001 through WSTG-SESS-008
"""

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'core'))

from base_tester import BaseTester
from utils import generate_report, save_findings, analyze_cookies
import requests
import json
import time
import random
from urllib.parse import urljoin, urlparse

class SessionManagementTester(BaseTester):
    """Session Management Security Testing"""

    def __init__(self, target_url):
        super().__init__()
        self.target_url = target_url
        self.session = requests.Session()
        self.findings = []
        self.session_data = {
            'cookies': [],
            'tokens': [],
            'csrf_protection': False,
            'session_timeout': None,
            'logout_functionality': False
        }

    def test_session_management_schema(self):
        """WSTG-SESS-001 - Test Session Management Schema"""
        print("[*] Testing Session Management Schema...")

        try:
            # Get initial response
            response = self.session.get(self.target_url)

            # Analyze session cookies
            cookies = self.session.cookies
            for cookie in cookies:
                cookie_info = {
                    'name': cookie.name,
                    'value': cookie.value[:20] + '...' if len(cookie.value) > 20 else cookie.value,
                    'domain': cookie.domain,
                    'path': cookie.path,
                    'secure': cookie.secure,
                    'httponly': cookie._rest.get('httponly', False)
                }
                self.session_data['cookies'].append(cookie_info)

            findings = {
                'test_id': 'WSTG-SESS-001',
                'test_name': 'Session Management Schema Testing',
                'description': 'Analysis of session cookie structure and security attributes',
                'findings': self.session_data['cookies'],
                'risk_level': self._assess_cookie_security(),
                'recommendations': self._get_cookie_recommendations()
            }

            self.findings.append(findings)
            return findings

        except Exception as e:
            print(f"[*] Error testing session schema: {e}")
            return None

    def test_session_token_entropy(self):
        """WSTG-SESS-005 - Test Session Token Entropy"""
        print("[*] Testing Session Token Entropy...")

        try:
            tokens = []

            # Collect multiple session tokens
            for i in range(10):
                self.session = requests.Session()
                response = self.session.get(self.target_url)

                for cookie in self.session.cookies:
                    if any(keyword in cookie.name.lower()
                          for keyword in ['session', 'token', 'auth', 'jsession', 'phpsess']):
                        tokens.append(cookie.value)

                time.sleep(0.5)

            entropy_analysis = self._analyze_token_entropy(tokens)

            findings = {
                'test_id': 'WSTG-SESS-005',
                'test_name': 'Session Token Entropy Testing',
                'description': 'Analysis of session token randomness and entropy',
                'findings': entropy_analysis,
                'risk_level': 'High' if entropy_analysis['low_entropy'] else 'Low',
                'recommendations': ['Use cryptographically secure random session tokens',
                                  'Implement minimum 128-bit entropy for session tokens']
            }

            self.findings.append(findings)
            return findings

        except Exception as e:
            print(f"[*] Error testing token entropy: {e}")
            return None

    def test_session_fixation(self):
        """WSTG-SESS-003 - Test for Session Fixation"""
        print("[*] Testing Session Fixation...")

        try:
            # Get initial session cookie
            initial_session = requests.Session()
            initial_response = initial_session.get(self.target_url)
            initial_cookies = initial_session.cookies.get_dict()

            # Simulate login (if login form exists)
            login_data = self._find_login_form(initial_response)
            if login_data:
                login_response = initial_session.post(
                    urljoin(self.target_url, login_data['action']),
                    data=login_data['data']
                )

                post_login_cookies = initial_session.cookies.get_dict()

                # Check if session ID changed after login
                session_changed = False
                for cookie_name in initial_cookies:
                    if cookie_name in post_login_cookies:
                        if initial_cookies[cookie_name] != post_login_cookies[cookie_name]:
                            session_changed = True
                            break

                findings = {
                    'test_id': 'WSTG-SESS-003',
                    'test_name': 'Session Fixation Testing',
                    'description': 'Testing for session fixation vulnerability',
                    'findings': {
                        'session_changed_after_login': session_changed,
                        'initial_cookies': list(initial_cookies.keys()),
                        'vulnerable': not session_changed
                    },
                    'risk_level': 'High' if not session_changed else 'Low',
                    'recommendations': ['Regenerate session IDs after authentication',
                                      'Implement session timeout mechanisms']
                }

                self.findings.append(findings)
                return findings

        except Exception as e:
            print(f"[*] Error testing session fixation: {e}")
            return None

    def test_logout_functionality(self):
        """WSTG-SESS-004 - Test Logout Functionality"""
        print("[*] Testing Logout Functionality...")

        try:
            # Simulate login session
            session = requests.Session()
            login_response = session.get(self.target_url)

            # Look for logout links/forms
            logout_links = self._find_logout_links(login_response)

            if logout_links:
                for logout_link in logout_links:
                    logout_response = session.get(urljoin(self.target_url, logout_link))

                    # Check if session is invalidated
                    protected_response = session.get(self.target_url)

                    # Simple check: if status code changes or content changes significantly
                    session_invalidated = (protected_response.status_code == 302 or
                                        'login' in protected_response.text.lower())

                    findings = {
                        'test_id': 'WSTG-SESS-004',
                        'test_name': 'Logout Functionality Testing',
                        'description': 'Testing proper session invalidation on logout',
                        'findings': {
                            'logout_links_found': logout_links,
                            'session_invalidated': session_invalidated,
                            'vulnerable': not session_invalidated
                        },
                        'risk_level': 'Medium' if not session_invalidated else 'Low',
                        'recommendations': ['Ensure complete session invalidation on logout',
                                          'Clear all session data and authentication cookies']
                    }

                    self.findings.append(findings)
                    return findings

        except Exception as e:
            print(f"[*] Error testing logout functionality: {e}")
            return None

    def test_csrf_protection(self):
        """WSTG-CSRF-004 - Testing for CSRF"""
        print("[*] Testing CSRF Protection...")

        try:
            response = self.session.get(self.target_url)

            # Look for CSRF tokens in forms
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(response.text, 'html.parser')

            forms = soup.find_all('form')
            csrf_tokens_found = 0

            for form in forms:
                csrf_inputs = form.find_all('input', {'name': lambda x: x and any(
                    keyword in x.lower() for keyword in ['csrf', 'token', '_token', 'authenticity']
                )})
                csrf_tokens_found += len(csrf_inputs)

            # Check for CSRF protection headers
            csrf_headers = response.headers.get('X-Frame-Options', '')

            self.session_data['csrf_protection'] = csrf_tokens_found > 0 or csrf_headers

            findings = {
                'test_id': 'WSTG-CSRF-004',
                'test_name': 'CSRF Protection Testing',
                'description': 'Testing for Cross-Site Request Forgery protection',
                'findings': {
                    'forms_found': len(forms),
                    'csrf_tokens_found': csrf_tokens_found,
                    'csrf_headers': csrf_headers,
                    'csrf_protection': self.session_data['csrf_protection']
                },
                'risk_level': 'High' if not self.session_data['csrf_protection'] else 'Low',
                'recommendations': ['Implement CSRF tokens in all state-changing forms',
                                  'Use SameSite cookie attributes',
                                  'Implement X-Frame-Options headers']
            }

            self.findings.append(findings)
            return findings

        except Exception as e:
            print(f"[*] Error testing CSRF protection: {e}")
            return None

    def run_comprehensive_test(self):
        """Run all session management tests"""
        print("=" * 60)
        print("OWASP WSTG SESSION MANAGEMENT TESTING")
        print("=" * 60)

        tests = [
            self.test_session_management_schema,
            self.test_session_token_entropy,
            self.test_session_fixation,
            self.test_logout_functionality,
            self.test_csrf_protection
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

    def _assess_cookie_security(self):
        """Assess the security of session cookies"""
        issues = []

        for cookie in self.session_data['cookies']:
            if not cookie['secure']:
                issues.append(f"Cookie {cookie['name']} not marked as Secure")
            if not cookie['httponly']:
                issues.append(f"Cookie {cookie['name']} not marked as HttpOnly")
            if cookie['path'] == '/':
                issues.append(f"Cookie {cookie['name']} has broad path scope")

        return 'High' if len(issues) > 2 else 'Medium' if issues else 'Low'

    def _get_cookie_recommendations(self):
        """Get cookie security recommendations"""
        return [
            'Set Secure flag for all session cookies',
            'Set HttpOnly flag for session cookies',
            'Use specific Path attribute instead of root',
            'Implement SameSite attribute for CSRF protection',
            'Use short session timeouts'
        ]

    def _analyze_token_entropy(self, tokens):
        """Analyze entropy of session tokens"""
        if len(tokens) < 2:
            return {'low_entropy': True, 'analysis': 'Insufficient tokens for analysis'}

        # Simple entropy analysis
        unique_chars = set(''.join(tokens))
        estimated_entropy = len(unique_chars) * 3.321928  # log2

        return {
            'low_entropy': estimated_entropy < 64,
            'entropy_bits': estimated_entropy,
            'unique_characters': len(unique_chars),
            'token_length': len(tokens[0]) if tokens else 0
        }

    def _find_login_form(self, response):
        """Find login form in response"""
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(response.text, 'html.parser')

        forms = soup.find_all('form')
        for form in forms:
            if any(keyword in str(form).lower() for keyword in ['login', 'signin', 'auth']):
                inputs = form.find_all('input', {'type': ['text', 'password', 'email']})
                if inputs:
                    action = form.get('action', '')
                    return {
                        'action': action,
                        'data': {'username': 'test', 'password': 'test'}
                    }
        return None

    def _find_logout_links(self, response):
        """Find logout links in response"""
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(response.text, 'html.parser')

        logout_links = []
        links = soup.find_all('a')
        for link in links:
            if any(keyword in str(link).lower() for keyword in ['logout', 'signout', 'exit']):
                href = link.get('href', '')
                if href:
                    logout_links.append(href)

        return logout_links

def main():
    if len(sys.argv) < 2:
        print("Usage: python session_testing.py <target_url>")
        sys.exit(1)

    target_url = sys.argv[1]

    try:
        tester = SessionManagementTester(target_url)
        results = tester.run_comprehensive_test()

        if results:
            # Generate report
            report = generate_report(
                target_url=target_url,
                test_results=results,
                test_category='Session Management',
                timestamp=time.strftime('%Y-%m-%d %H:%M:%S')
            )

            # Save results
            save_findings(report, 'session_management_test_results.json')

            print(f"\n[*] Test completed. Results saved to session_management_test_results.json")
        else:
            print("[*] No tests completed successfully")

    except KeyboardInterrupt:
        print("\n[*] Test interrupted by user")
    except Exception as e:
        print(f"[*] Error: {e}")

if __name__ == "__main__":
    main()
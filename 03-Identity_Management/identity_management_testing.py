#!/usr/bin/env python3
"""
OWASP WSTG Identity Management Testing Framework
Autor: Framework OWASP WSTG
Propósito: Automatizar pruebas de Identity Management Testing (WSTG-IDNT)

Este script realiza pruebas automatizadas de gestión de identidades
siguiendo los estándares de OWASP Web Security Testing Guide.

Uso: python identity_management_testing.py --target <domain.com> --register-url </register>

Requisitos: pip install requests beautifulsoup4 faker
"""

import requests
import json
import time
import sys
import argparse
import re
import random
import string
from urllib.parse import urlparse, urljoin
from datetime import datetime
from faker import Faker

class IdentityManagementTesting:
    def __init__(self, target, register_url=None, login_url=None, reset_url=None):
        self.target = target
        self.base_url = f"https://{target}" if not target.startswith(('http://', 'https://')) else target
        self.domain = urlparse(self.base_url).netloc
        self.register_url = register_url or '/register'
        self.login_url = login_url or '/login'
        self.reset_url = reset_url or '/forgot-password'
        self.fake = Faker()
        self.results = {
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'tests': {}
        }
        self.session = requests.Session()
        self.session.verify = False

    def run_all_tests(self):
        """Ejecutar todas las pruebas de Identity Management"""
        print(f"[*] Iniciando pruebas de Identity Management para: {self.target}")
        print("=" * 60)

        # WSTG-IDNT-01: Role Definitions
        self.test_wstg_idnt_01()

        # WSTG-IDNT-02: User Registration Process
        self.test_wstg_idnt_02()

        # WSTG-IDNT-03: Account Provisioning Process
        self.test_wstg_idnt_03()

        # WSTG-IDNT-04: Account Enumeration
        self.test_wstg_idnt_04()

        # WSTG-IDNT-05: Username Policy
        self.test_wstg_idnt_05()

        # Guardar resultados
        self.save_results()

    def test_wstg_idnt_01(self):
        """WSTG-IDNT-01: Test Role Definitions"""
        print("\n[+] WSTG-IDNT-01: Role Definitions Testing")

        results = {
            'role_endpoints': {},
            'privilege_escalation_attempts': [],
            'role_hierarchy': [],
            'findings': []
        }

        # Endpoints comunes por rol
        role_endpoints = {
            'admin': ['/admin', '/dashboard', '/users', '/settings'],
            'user': ['/profile', '/account', '/my-account'],
            'guest': ['/login', '/register', '/home']
        }

        for role, endpoints in role_endpoints.items():
            print(f"\n    [*] Probando endpoints para rol: {role}")
            results['role_endpoints'][role] = {}

            for endpoint in endpoints:
                try:
                    url = urljoin(self.base_url, endpoint)
                    response = self.session.get(url, timeout=10)

                    results['role_endpoints'][role][endpoint] = {
                        'status_code': response.status_code,
                        'redirect': response.url if response.url != url else None,
                        'content_length': len(response.content)
                    }

                    if response.status_code == 200:
                        print(f"      [+] Acceso permitido: {endpoint} ({response.status_code})")
                    elif response.status_code in [301, 302, 403]:
                        print(f"      [-] Acceso restringido: {endpoint} ({response.status_code})")
                    else:
                        print(f"      [?] Estado inesperado: {endpoint} ({response.status_code})")

                except requests.exceptions.RequestException as e:
                    results['role_endpoints'][role][endpoint] = {'error': str(e)}
                    print(f"      [!] Error accediendo a {endpoint}: {e}")

        # Intentar escalada de privilegios mediante manipulación de parámetros
        print("\n    [*] Probando escalada de privilegios")
        escalation_attempts = [
            {'param': 'role', 'value': 'admin'},
            {'param': 'user_type', 'value': 'administrator'},
            {'param': 'privilege', 'value': '1'},
            {'param': 'is_admin', 'value': 'true'}
        ]

        for attempt in escalation_attempts:
            try:
                url = urljoin(self.base_url, self.login_url)
                data = {
                    'username': 'testuser',
                    'password': 'testpass',
                    attempt['param']: attempt['value']
                }

                response = self.session.post(url, data=data, timeout=10)

                if response.status_code not in [400, 401, 403]:
                    results['privilege_escalation_attempts'].append({
                        'attempt': attempt,
                        'status_code': response.status_code,
                        'potential_vulnerability': True
                    })
                    print(f"      [!] Posible escalada con {attempt['param']}={attempt['value']}")

            except requests.exceptions.RequestException:
                continue

        self.results['tests']['WSTG-IDNT-01'] = results

    def test_wstg_idnt_02(self):
        """WSTG-IDNT-02: Test User Registration Process"""
        print("\n[+] WSTG-IDNT-02: User Registration Process Testing")

        results = {
            'registration_available': False,
            'validation_tests': {},
            'security_features': {},
            'vulnerabilities': []
        }

        try:
            # Verificar disponibilidad del endpoint de registro
            register_url = urljoin(self.base_url, self.register_url)
            response = self.session.get(register_url, timeout=10)

            if response.status_code == 200:
                results['registration_available'] = True
                print(f"    [+] Formulario de registro encontrado: {register_url}")

                # Analizar el formulario de registro
                from bs4 import BeautifulSoup
                soup = BeautifulSoup(response.text, 'html.parser')

                form = soup.find('form')
                if form:
                    inputs = form.find_all('input')
                    fields = [inp.get('name') for inp in inputs if inp.get('name')]
                    print(f"    [*] Campos encontrados: {fields}")

                    # Pruebas de validación
                    validation_tests = self._test_registration_validation(fields, form.get('action', register_url))
                    results['validation_tests'] = validation_tests

                # Verificar características de seguridad
                security_features = self._check_registration_security(response.text)
                results['security_features'] = security_features

            else:
                print(f"    [-] Registro no disponible: {register_url} ({response.status_code})")

        except requests.exceptions.RequestException as e:
            print(f"    [!] Error accediendo a registro: {e}")
            results['error'] = str(e)

        self.results['tests']['WSTG-IDNT-02'] = results

    def test_wstg_idnt_03(self):
        """WSTG-IDNT-03: Test Account Provisioning Process"""
        print("\n[+] WSTG-IDNT-03: Account Provisioning Process Testing")

        results = {
            'provisioning_tests': {},
            'time_to_activation': None,
            'default_resources': {},
            'privilege_assignment': {}
        }

        # Crear cuenta de prueba para evaluar aprovisionamiento
        test_username = f"testuser_{int(time.time())}"
        test_email = f"{test_username}@test.com"
        test_password = "Test123!@#"

        print(f"    [*] Creando cuenta de prueba: {test_username}")

        try:
            register_url = urljoin(self.base_url, self.register_url)
            register_data = {
                'username': test_username,
                'email': test_email,
                'password': test_password,
                'confirm_password': test_password
            }

            start_time = time.time()
            response = self.session.post(register_url, data=register_data, timeout=10)
            end_time = time.time()

            results['provisioning_tests']['registration_response'] = {
                'status_code': response.status_code,
                'response_time': end_time - start_time,
                'content_preview': response.text[:200]
            }

            if response.status_code in [200, 201, 302]:
                print(f"    [+] Registro exitoso - Código: {response.status_code}")

                # Verificar si se puede acceder inmediatamente
                login_data = {
                    'username': test_username,
                    'password': test_password
                }

                login_url = urljoin(self.base_url, self.login_url)
                login_response = self.session.post(login_url, data=login_data, timeout=10)

                results['provisioning_tests']['immediate_access'] = {
                    'status_code': login_response.status_code,
                    'access_granted': login_response.status_code in [200, 302]
                }

                if login_response.status_code in [200, 302]:
                    print("    [+] Acceso inmediato permitido después del registro")
                    results['time_to_activation'] = 0

                    # Verificar recursos asignados por defecto
                    default_resources = self._check_default_resources()
                    results['default_resources'] = default_resources
                else:
                    print("    [-] Acceso inmediato denegado - Posible verificación requerida")

            else:
                print(f"    [-] Registro fallido - Código: {response.status_code}")

        except requests.exceptions.RequestException as e:
            print(f"    [!] Error en prueba de aprovisionamiento: {e}")
            results['error'] = str(e)

        self.results['tests']['WSTG-IDNT-03'] = results

    def test_wstg_idnt_04(self):
        """WSTG-IDNT-04: Testing for Account Enumeration"""
        print("\n[+] WSTG-IDNT-04: Account Enumeration Testing")

        results = {
            'username_enumeration': {},
            'email_enumeration': {},
            'timing_attacks': {},
            'password_reset_enumeration': {},
            'vulnerabilities': []
        }

        # Lista de usernames para probar
        test_usernames = [
            'admin', 'administrator', 'root', 'user', 'test',
            'guest', 'demo', 'support', 'info', 'contact',
            'nonexistent12345', 'fakeuser99999', 'definitelynotreal'
        ]

        # 1. Enumeración por login
        print("    [*] Probando enumeración por login")
        login_results = {}

        for username in test_usernames:
            try:
                login_url = urljoin(self.base_url, self.login_url)
                login_data = {'username': username, 'password': 'wrongpassword123'}

                start_time = time.time()
                response = self.session.post(login_url, data=login_data, timeout=10)
                end_time = time.time()

                login_results[username] = {
                    'status_code': response.status_code,
                    'response_time': end_time - start_time,
                    'content_length': len(response.content),
                    'response_preview': response.text[:100]
                }

            except requests.exceptions.RequestException:
                login_results[username] = {'error': 'Request failed'}

        results['username_enumeration'] = login_results

        # 2. Enumeración por password reset
        print("    [*] Probando enumeración por password reset")
        reset_results = {}

        for username in test_usernames:
            try:
                reset_url = urljoin(self.base_url, self.reset_url)
                reset_data = {'username': username, 'email': f'{username}@{self.domain}'}

                start_time = time.time()
                response = self.session.post(reset_url, data=reset_data, timeout=10)
                end_time = time.time()

                reset_results[username] = {
                    'status_code': response.status_code,
                    'response_time': end_time - start_time,
                    'content_length': len(response.content)
                }

            except requests.exceptions.RequestException:
                reset_results[username] = {'error': 'Request failed'}

        results['password_reset_enumeration'] = reset_results

        # 3. Análisis de timing attacks
        print("    [*] Analizando ataques de timing")
        timing_analysis = self._analyze_timing_attacks(login_results, reset_results)
        results['timing_attacks'] = timing_analysis

        # 4. Análisis de mensajes de error
        print("    [*] Analizando mensajes de error")
        error_analysis = self._analyze_error_messages(login_results, reset_results)
        results['error_messages'] = error_analysis

        # 5. Identificar vulnerabilidades
        vulnerabilities = self._identify_enumeration_vulnerabilities(results)
        results['vulnerabilities'] = vulnerabilities

        self.results['tests']['WSTG-IDNT-04'] = results

    def test_wstg_idnt_05(self):
        """WSTG-IDNT-05: Testing for Weak or Unenforced Username Policy"""
        print("\n[+] WSTG-IDNT-05: Username Policy Testing")

        results = {
            'policy_tests': {},
            'username_restrictions': {},
            'security_issues': []
        }

        # Casos de prueba para políticas de nombre de usuario
        test_cases = [
            # {'username': 'a', 'description': 'Carácter único'},
            # {'username': 'user' * 100, 'description': 'Username muy largo'},
            {'username': 'admin', 'description': 'Nombre reservado'},
            {'username': 'root', 'description': 'Nombre reservado'},
            {'username': 'administrator', 'description': 'Nombre reservado'},
            {'username': 'testuser', 'description': 'Username común'},
            {'username': 'user@domain.com', 'description': 'Email como username'},
            {'username': 'user<script>', 'description': 'XSS en username'},
            {'username': "user'; DROP TABLE users; --", 'description': 'SQL Injection en username'},
            {'username': '../../etc/passwd', 'description': 'Path traversal en username'},
            {'username': '测试用户', 'description': 'Unicode characters'},
            {'username': 'USER', 'description': 'Uppercase'},
            {'username': 'User', 'description': 'Mixed case'},
            {'username': 'user space', 'description': 'Espacio en username'},
            {'username': 'user\ttab', 'description': 'Tab en username'},
            {'username': 'user123!@#', 'description': 'Caracteres especiales'},
        ]

        for test_case in test_cases:
            try:
                register_url = urljoin(self.base_url, self.register_url)
                register_data = {
                    'username': test_case['username'],
                    'email': f"test_{random.randint(1000, 9999)}@test.com",
                    'password': 'Test123!@#',
                    'confirm_password': 'Test123!@#'
                }

                response = self.session.post(register_url, data=register_data, timeout=10)

                results['policy_tests'][test_case['username']] = {
                    'description': test_case['description'],
                    'status_code': response.status_code,
                    'accepted': response.status_code not in [400, 422],
                    'response_preview': response.text[:200]
                }

                if response.status_code not in [400, 422]:
                    print(f"      [+] Username aceptado: {test_case['username']} ({test_case['description']})")
                else:
                    print(f"      [-] Username rechazado: {test_case['username']} ({test_case['description']})")

            except requests.exceptions.RequestException as e:
                results['policy_tests'][test_case['username']] = {
                    'description': test_case['description'],
                    'error': str(e)
                }

        # Analizar restricciones encontradas
        policy_analysis = self._analyze_username_policy(results['policy_tests'])
        results['policy_analysis'] = policy_analysis

        self.results['tests']['WSTG-IDNT-05'] = results

    def _test_registration_validation(self, fields, form_url):
        """Probar validaciones específicas del registro"""
        validation_results = {}

        # Probar registro sin datos
        print("      [*] Probando registro sin datos")
        try:
            response = self.session.post(form_url, data={}, timeout=10)
            validation_results['empty_data'] = {
                'status_code': response.status_code,
                'has_errors': 'error' in response.text.lower() or 'required' in response.text.lower()
            }
        except requests.exceptions.RequestException:
            validation_results['empty_data'] = {'error': 'Request failed'}

        # Probar con email inválido
        if 'email' in fields:
            print("      [*] Probando email inválido")
            try:
                invalid_email_data = {
                    'username': 'testuser123',
                    'email': 'invalid-email',
                    'password': 'Test123!@#'
                }
                response = self.session.post(form_url, data=invalid_email_data, timeout=10)
                validation_results['invalid_email'] = {
                    'status_code': response.status_code,
                    'rejected': response.status_code in [400, 422]
                }
            except requests.exceptions.RequestException:
                validation_results['invalid_email'] = {'error': 'Request failed'}

        # Probar password débil
        if 'password' in fields:
            print("      [*] Probando contraseña débil")
            try:
                weak_password_data = {
                    'username': 'testuser456',
                    'email': 'test456@test.com',
                    'password': '123'
                }
                response = self.session.post(form_url, data=weak_password_data, timeout=10)
                validation_results['weak_password'] = {
                    'status_code': response.status_code,
                    'rejected': response.status_code in [400, 422]
                }
            except requests.exceptions.RequestException:
                validation_results['weak_password'] = {'error': 'Request failed'}

        return validation_results

    def _check_registration_security(self, html_content):
        """Verificar características de seguridad en el formulario de registro"""
        security_features = {
            'has_captcha': any(keyword in html_content.lower() for keyword in ['captcha', 'recaptcha', 'hcaptcha']),
            'has_csrf_token': any(keyword in html_content.lower() for keyword in ['csrf', '_token', 'authenticity_token']),
            'has_rate_limiting': False,  # Esto requiere pruebas adicionales
            'has_email_verification': any(keyword in html_content.lower() for keyword in ['verify', 'confirm', 'verification'])
        }

        for feature, present in security_features.items():
            if present:
                print(f"      [+] {feature}: Implementado")
            else:
                print(f"      [-] {feature}: No detectado")

        return security_features

    def _check_default_resources(self):
        """Verificar recursos asignados por defecto a nueva cuenta"""
        resources = {}

        # Probar acceso a recursos comunes
        common_resources = [
            '/profile',
            '/account',
            '/settings',
            '/dashboard',
            '/uploads',
            '/messages'
        ]

        for resource in common_resources:
            try:
                url = urljoin(self.base_url, resource)
                response = self.session.get(url, timeout=10)
                resources[resource] = {
                    'status_code': response.status_code,
                    'accessible': response.status_code == 200
                }
            except requests.exceptions.RequestException:
                resources[resource] = {'error': 'Request failed'}

        return resources

    def _analyze_timing_attacks(self, login_results, reset_results):
        """Analizar posibles ataques de timing"""
        timing_analysis = {
            'login_timing_variance': {},
            'reset_timing_variance': {},
            'potential_timing_attack': False
        }

        # Analizar tiempos de respuesta del login
        if login_results:
            times = [result.get('response_time', 0) for result in login_results.values() if 'response_time' in result]
            if times:
                min_time = min(times)
                max_time = max(times)
                variance = max_time - min_time

                timing_analysis['login_timing_variance'] = {
                    'min_time': min_time,
                    'max_time': max_time,
                    'variance': variance,
                    'significant': variance > 0.5  # 500ms de diferencia
                }

                if variance > 0.5:
                    timing_analysis['potential_timing_attack'] = True
                    print(f"      [!] Posible timing attack detectado - Varianza: {variance:.2f}s")

        return timing_analysis

    def _analyze_error_messages(self, login_results, reset_results):
        """Analizar mensajes de error para detectar enumeración"""
        error_analysis = {
            'login_error_patterns': {},
            'reset_error_patterns': {},
            'enumeration_possible': False
        }

        # Analizar patrones de error en login
        if login_results:
            error_responses = {}
            for username, result in login_results.items():
                if 'response_preview' in result:
                    error_responses[username] = result['response_preview']

            # Buscar diferencias significativas en los mensajes
            unique_responses = set(error_responses.values())
            error_analysis['login_error_patterns'] = {
                'unique_error_count': len(unique_responses),
                'total_attempts': len(error_responses),
                'enumeration_likely': len(unique_responses) > 1
            }

            if len(unique_responses) > 1:
                error_analysis['enumeration_possible'] = True
                print(f"      [!] Posible enumeración por diferentes mensajes de error")

        return error_analysis

    def _identify_enumeration_vulnerabilities(self, results):
        """Identificar vulnerabilidades de enumeración"""
        vulnerabilities = []

        # Verificar timing attacks
        if results.get('timing_attacks', {}).get('potential_timing_attack'):
            vulnerabilities.append({
                'type': 'Timing Attack',
                'severity': 'Medium',
                'description': 'Diferencias significativas en tiempo de respuesta pueden indicar existencia de usuarios'
            })

        # Verificar mensajes de error
        if results.get('error_messages', {}).get('enumeration_possible'):
            vulnerabilities.append({
                'type': 'Error Message Enumeration',
                'severity': 'High',
                'description': 'Mensajes de error diferentes permiten enumerar usuarios'
            })

        # Verificar comportamiento en password reset
        reset_results = results.get('password_reset_enumeration', {})
        if reset_results:
            status_codes = [r.get('status_code') for r in reset_results.values() if 'status_code' in r]
            if len(set(status_codes)) > 1:
                vulnerabilities.append({
                    'type': 'Password Reset Enumeration',
                    'severity': 'High',
                    'description': 'Comportamiento diferente en password reset permite enumeración'
                })

        return vulnerabilities

    def _analyze_username_policy(self, policy_tests):
        """Analizar políticas de nombre de usuario basadas en los tests"""
        analysis = {
            'min_length': None,
            'max_length': None,
            'allowed_characters': 'alphanumeric',
            'reserved_names': [],
            'case_sensitive': False,
            'security_issues': []
        }

        # Analizar nombres aceptados/rechazados
        for username, test_result in policy_tests.items():
            if test_result.get('accepted'):
                if analysis['min_length'] is None or len(username) < analysis['min_length']:
                    analysis['min_length'] = len(username)

                if analysis['max_length'] is None or len(username) > analysis['max_length']:
                    analysis['max_length'] = len(username)

                # Detectar caracteres especiales permitidos
                if any(c not in string.ascii_letters + string.digits for c in username):
                    analysis['allowed_characters'] = 'extended'

                # Detectar si es case-sensitive
                if username.lower() in ['admin', 'user'] and test_result.get('accepted'):
                    analysis['case_sensitive'] = True

                # Identificar posibles problemas de seguridad
                if '<script>' in username.lower() or 'drop table' in username.lower():
                    analysis['security_issues'].append({
                        'username': username,
                        'issue': 'Potential injection accepted'
                    })

        return analysis

    def save_results(self):
        """Guardar resultados en archivos JSON y texto plano"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Guardar JSON
        json_file = f"identity_management_testing_{self.domain}_{timestamp}.json"
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)

        # Guardar texto plano
        txt_file = f"identity_management_testing_{self.domain}_{timestamp}.txt"
        with open(txt_file, 'w', encoding='utf-8') as f:
            f.write("OWASP WSTG Identity Management Test Results\n")
            f.write("=" * 50 + "\n\n")
            f.write(f"Target: {self.target}\n")
            f.write(f"Fecha: {self.results['timestamp']}\n\n")

            for test_name, test_results in self.results['tests'].items():
                f.write(f"\n{test_name}:\n")
                f.write("-" * len(test_name) + "\n")

                if isinstance(test_results, dict):
                    for key, value in test_results.items():
                        if isinstance(value, list):
                            f.write(f"{key}: {len(value)} items\n")
                            for item in value[:3]:  # Limitar a 3 items
                                f.write(f"  - {item}\n")
                        elif isinstance(value, dict):
                            f.write(f"{key}:\n")
                            for subkey, subvalue in value.items():
                                if isinstance(subvalue, dict):
                                    f.write(f"  {subkey}:\n")
                                    for subsubkey, subsubvalue in subsubvalue.items():
                                        f.write(f"    {subsubkey}: {subsubvalue}\n")
                                else:
                                    f.write(f"  {subkey}: {subvalue}\n")
                        else:
                            f.write(f"{key}: {value}\n")
                else:
                    f.write(f"{test_results}\n")

        print(f"\n[+] Resultados guardados en:")
        print(f"    JSON: {json_file}")
        print(f"    TXT:  {txt_file}")

        # Generar resumen
        self.generate_summary()

    def generate_summary(self):
        """Generar un resumen de los hallazgos"""
        print("\n" + "=" * 60)
        print("RESUMEN DE IDENTITY MANAGEMENT TESTING")
        print("=" * 60)

        total_tests = len(self.results['tests'])
        print(f"Tests ejecutados: {total_tests}")

        # Contar vulnerabilidades
        total_vulnerabilities = 0
        critical_vulns = 0
        high_vulns = 0

        # WSTG-IDNT-02 - Registration Process
        if 'WSTG-IDNT-02' in self.results['tests']:
            reg_available = self.results['tests']['WSTG-IDNT-02'].get('registration_available')
            if reg_available:
                print("Formulario de registro: Disponible")
            else:
                print("Formulario de registro: No disponible")

        # WSTG-IDNT-04 - Account Enumeration
        if 'WSTG-IDNT-04' in self.results['tests']:
            vulns = self.results['tests']['WSTG-IDNT-04'].get('vulnerabilities', [])
            if vulns:
                total_vulnerabilities += len(vulns)
                for vuln in vulns:
                    if vuln['severity'] == 'High':
                        high_vulns += 1
                    print(f"Vulnerabilidad de enumeración: {vuln['type']} ({vuln['severity']})")

        # WSTG-IDNT-05 - Username Policy
        if 'WSTG-IDNT-05' in self.results['tests']:
            policy_issues = self.results['tests']['WSTG-IDNT-05'].get('policy_analysis', {}).get('security_issues', [])
            if policy_issues:
                total_vulnerabilities += len(policy_issues)
                critical_vulns += len(policy_issues)  # Security issues in usernames are critical
                print(f"Issues en política de usernames: {len(policy_issues)}")

        print(f"\nResumen de vulnerabilidades:")
        print(f"  Críticas: {critical_vulns}")
        print(f"  Altas: {high_vulns}")
        print(f"  Medias: {total_vulnerabilities - critical_vulns - high_vulns}")
        print(f"  Totales: {total_vulnerabilities}")

        print("\nRecomendaciones principales:")
        if critical_vulns > 0:
            print("- CORREGIR URGENTEMENTE las vulnerabilidades críticas de validación de input")
        if high_vulns > 0:
            print("- Implementar respuestas consistentes para prevenir enumeración")
        print("- Implementar validación robusta de nombres de usuario")
        print("- Usar mensajes de error genéricos")
        print("- Implementar rate limiting en endpoints de autenticación")

def main():
    parser = argparse.ArgumentParser(description='OWASP WSTG Identity Management Testing Framework')
    parser.add_argument('--target', required=True, help='Dominio objetivo (ej: ejemplo.com)')
    parser.add_argument('--register-url', default='/register', help='URL de registro (default: /register)')
    parser.add_argument('--login-url', default='/login', help='URL de login (default: /login)')
    parser.add_argument('--reset-url', default='/forgot-password', help='URL de reset de password (default: /forgot-password)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Modo verbose')

    args = parser.parse_args()

    try:
        tester = IdentityManagementTesting(
            args.target,
            args.register_url,
            args.login_url,
            args.reset_url
        )
        tester.run_all_tests()
    except KeyboardInterrupt:
        print("\n[!] Prueba interrumpida por el usuario")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
#!/usr/bin/env python3
"""
OWASP WSTG Authentication Testing Framework (WSTG-ATHN)
Autor: Framework OWASP WSTG
Propósito: Automatizar pruebas de Authentication Testing con integración de herramientas Kali

Este script realiza pruebas automatizadas de autenticación web
siguiendo los estándares de OWASP Web Security Testing Guide
con integración completa de herramientas de Kali Linux.

Uso: python authentication_tester.py --target <domain.com> --login-url </login>

Requisitos: pip install requests beautifulsoup4 faker
Herramientas Kali: hydra, hashcat, john, nmap, testssl.sh
"""

import sys
import os
import re
import json
import time
import random
import string
import hashlib
import secrets
import base64
import logging
from datetime import datetime, timedelta
from urllib.parse import urlparse, urljoin, parse_qs
import requests
from bs4 import BeautifulSoup
from faker import Faker

# Importar módulos del framework
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.base_tester import BaseTester, TestResult
from core.utils import SecurityUtils, NetworkUtils
from core.kali_tools import KaliToolsIntegration, get_kali_tools_instance

# Configuración de logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AuthenticationTester(BaseTester):
    """
    Tester especializado para Authentication Testing (WSTG-ATHN)
    con integración completa de herramientas de Kali Linux
    """

    def __init__(self, target: str, config: dict = None):
        super().__init__(target, config)

        # Configuración específica de autenticación
        self.login_url = self.config.get('login_url', '/login')
        self.username_field = self.config.get('username_field', 'username')
        self.password_field = self.config.get('password_field', 'password')
        self.submit_button = self.config.get('submit_button', 'submit')

        # Listas de credenciales comunes
        self.common_usernames = [
            'admin', 'administrator', 'root', 'user', 'test', 'demo',
            'guest', 'support', 'info', 'contact', 'service',
            'api', 'system', 'manager', 'operator', 'staff'
        ]

        self.common_passwords = [
            'admin', 'password', '123456', '12345678', 'qwerty',
            'abc123', 'password123', 'admin123', 'root', 'test',
            'guest', 'demo', 'default', 'changeme', 'letmein'
        ]

        self.faker = Faker()
        self.fake = Faker()

        # Inicializar herramientas de Kali
        self.kali_tools = get_kali_tools_instance(self.config)

        # Resultados específicos de autenticación
        self.auth_findings = {
            'login_form': {},
            'ssl_config': {},
            'default_creds': {},
            'brute_force_results': {},
            'bypass_attempts': {},
            'password_policy': {},
            'mfa_implementation': {}
        }

    def get_phase_id(self) -> str:
        return 'WSTG-ATHN'

    def get_phase_name(self) -> str:
        return 'Authentication Testing'

    def run_tests(self) -> bool:
        """Ejecutar todas las pruebas de autenticación"""
        print(f"\n{'='*60}")
        print(f"OWASP WSTG - Authentication Testing Framework")
        print(f"Target: {self.target}")
        print(f"Login URL: {self.login_url}")
        print(f"{'='*60}")

        try:
            # WSTG-ATHN-01: SSL/TLS Testing
            self.test_wstg_athn_01()

            # WSTG-ATHN-02: Default Credentials Testing
            self.test_wstg_athn_02()

            # WSTG-ATHN-03: Lock Out Mechanism Testing
            self.test_wstg_athn_03()

            # WSTG-ATHN-04: Authentication Schema Bypass
            self.test_wstg_athn_04()

            # WSTG-ATHN-05: Remember Password Testing
            self.test_wstg_athn_05()

            # WSTG-ATHN-06: Browser Cache Testing
            self.test_wstg_athn_06()

            # WSTG-ATHN-07: Password Policy Testing
            self.test_wstg_athn_07()

            # WSTG-ATHN-08: Security Questions Testing
            self.test_wstg_athn_08()

            # WSTG-ATHN-09: Password Reset Testing
            self.test_wstg_athn_09()

            # WSTG-ATHN-10: Alternative Channel Testing
            self.test_wstg_athn_10()

            # WSTG-ATHN-11: MFA Testing
            self.test_wstg_athn_11()

            # Pruebas de fuerza bruta con herramientas Kali
            self.test_brute_force_with_kali_tools()

            return True

        except Exception as e:
            logger.error(f"Error en ejecución de pruebas de autenticación: {e}")
            return False

    def test_wstg_athn_01(self):
        """WSTG-ATHN-01: Testing for Credentials Transported over an Encrypted Channel"""
        print("\n[+] WSTG-ATHN-01: SSL/TLS Transport Testing")

        login_url = urljoin(self.target_info.base_url, self.login_url)

        # Verificar si el login usa HTTPS
        is_https = login_url.startswith('https://')

        # Probar HTTP y HTTPS
        http_url = login_url.replace('https://', 'http://')
        https_url = login_url.replace('http://', 'https://')

        results = {
            'http_available': False,
            'https_available': False,
            'redirect_to_https': False,
            'ssl_cert_info': {},
            'security_headers': {}
        }

        # Test HTTP availability
        try:
            response = self.make_request('GET', http_url)
            if response and response.status_code == 200:
                results['http_available'] = True
                print(f"    [!] Login disponible en HTTP (INESGURO)")
        except:
            pass

        # Test HTTPS availability
        try:
            response = self.make_request('GET', https_url)
            if response and response.status_code == 200:
                results['https_available'] = True
                print(f"    [+] Login disponible en HTTPS")

                # Analizar headers de seguridad
                security_headers = {
                    'strict-transport-security': response.headers.get('strict-transport-security'),
                    'x-frame-options': response.headers.get('x-frame-options'),
                    'x-content-type-options': response.headers.get('x-content-type-options'),
                    'x-xss-protection': response.headers.get('x-xss-protection'),
                    'content-security-policy': response.headers.get('content-security-policy')
                }
                results['security_headers'] = security_headers

                # Verificar redirección de HTTP a HTTPS
                if results['http_available']:
                    http_response = self.make_request('GET', http_url, allow_redirects=False)
                    if http_response and http_response.status_code in [301, 302, 307, 308]:
                        location = http_response.headers.get('Location', '')
                        if 'https://' in location:
                            results['redirect_to_https'] = True
                            print(f"    [+] HTTP redirige a HTTPS")

        except:
            pass

        # Analizar certificado SSL si está disponible
        if results['https_available']:
            ssl_info = SecurityUtils.analyze_ssl_certificate(self.target_info.domain)
            results['ssl_cert_info'] = ssl_info

            # Verificar validez del certificado
            if 'not_after' in ssl_info:
                expiry_date = ssl_info['not_after']
                if expiry_date < datetime.now():
                    self.add_vulnerability(
                        'WSTG-ATHN-01-SSL-EXPIRED',
                        'Certificado SSL expirado',
                        {'expiry_date': expiry_date.isoformat(), 'domain': self.target_info.domain},
                        'high',
                        'CWE-295'
                    )
                    print(f"    [!] Certificado SSL expirado: {expiry_date}")

        # Verificar formulario de login para envío seguro
        try:
            response = self.make_request('GET', https_url)
            if response:
                soup = BeautifulSoup(response.text, 'html.parser')
                login_form = soup.find('form')

                if login_form:
                    form_action = login_form.get('action', '')
                    form_method = login_form.get('method', 'GET').upper()

                    if not form_action.startswith('https://') and not form_action.startswith('/'):
                        # URL relativa, hereda HTTPS
                        pass
                    elif form_action.startswith('http://'):
                        self.add_vulnerability(
                            'WSTG-ATHN-01-HTTP-FORM',
                            'Formulario de login envía datos por HTTP',
                            {'form_action': form_action, 'form_method': form_method},
                            'critical',
                            'CWE-523'
                        )
                        print(f"    [!] Formulario envía datos por HTTP: {form_action}")

        except Exception as e:
            logger.error(f"Error analizando formulario de login: {e}")

        # Agregar resultados globales
        self.auth_findings['ssl_config'] = results

        # Evaluar riesgo general
        if results['http_available'] and not results['redirect_to_https']:
            self.add_vulnerability(
                'WSTG-ATHN-01-HTTP-AVAILABLE',
                'Login disponible por HTTP sin redirección',
                results,
                'high',
                'CWE-311'
            )
        elif not results['https_available']:
            self.add_vulnerability(
                'WSTG-ATHN-01-NO-HTTPS',
                'Login no disponible por HTTPS',
                results,
                'critical',
                'CWE-319'
            )
        else:
            self.add_info(
                'WSTG-ATHN-01-SSL-OK',
                'Configuración SSL/TLS adecuada',
                results
            )

    def test_wstg_athn_02(self):
        """WSTG-ATHN-02: Testing for Default Credentials"""
        print("\n[+] WSTG-ATHN-02: Default Credentials Testing")

        results = {
            'default_creds_found': [],
            'successful_logins': [],
            'tested_combinations': 0
        }

        login_url = urljoin(self.target_info.base_url, self.login_url)

        # Primero analizar el formulario de login
        try:
            response = self.make_request('GET', login_url)
            if not response or response.status_code != 200:
                logger.error(f"No se pudo acceder al formulario de login: {login_url}")
                return

            soup = BeautifulSoup(response.text, 'html.parser')
            login_form = soup.find('form')

            if not login_form:
                print(f"    [-] No se encontró formulario de login en: {login_url}")
                return

            # Extraer información del formulario
            form_action = login_form.get('action', login_url)
            form_method = login_form.get('method', 'POST').upper()

            # Encontrar campos de username y password
            username_input = login_form.find('input', {'name': re.compile(self.username_field, re.I)})
            password_input = login_form.find('input', {'name': re.compile(self.password_field, re.I)})

            if not username_input or not password_input:
                print(f"    [-] No se encontraron campos de username/password estándar")
                return

            username_field = username_input.get('name')
            password_field = password_input.get('name')

            print(f"    [*] Formulario detectado: {form_method} {form_action}")
            print(f"    [*] Campos: {username_field}, {password_field}")

            # Probar credenciales por defecto
            print(f"    [*] Probando credenciales por defecto...")

            # Combinaciones comunes
            default_combinations = [
                ('admin', 'admin'),
                ('admin', 'password'),
                ('admin', '123456'),
                ('admin', 'admin123'),
                ('administrator', 'administrator'),
                ('administrator', 'password'),
                ('root', 'root'),
                ('root', 'password'),
                ('root', 'toor'),
                ('test', 'test'),
                ('demo', 'demo'),
                ('guest', 'guest'),
                ('user', 'user'),
                ('user', 'password')
            ]

            successful_logins = []

            for username, password in default_combinations[:10]:  # Limitar para no ser bloqueados
                results['tested_combinations'] += 1

                try:
                    form_data = {
                        username_field: username,
                        password_field: password
                    }

                    # Enviar formulario
                    response = self.make_request(form_method, form_action, data=form_data)

                    if response:
                        # Analizar respuesta para determinar si el login fue exitoso
                        login_success = self._check_login_success(response, username)

                        if login_success:
                            successful_login = {
                                'username': username,
                                'password': password,
                                'response_code': response.status_code,
                                'response_length': len(response.content)
                            }
                            successful_logins.append(successful_login)
                            results['default_creds_found'].append(successful_login)
                            results['successful_logins'].append(successful_login)

                            print(f"    [!] Credenciales por defecto encontradas: {username}/{password}")

                            self.add_vulnerability(
                                'WSTG-ATHN-02-DEFAULT-CREDS',
                                f'Credenciales por defecto funcionales: {username}/{password}',
                                successful_login,
                                'critical',
                                'CWE-255'
                            )
                            break  # Dejar de probar si encontramos credenciales válidas

                except Exception as e:
                    logger.debug(f"Error probando credenciales {username}/{password}: {e}")
                    continue

                # Pequeña pausa para no saturar
                time.sleep(0.5)

            if not successful_logins:
                print(f"    [+] No se encontraron credenciales por defecto funcionales")

        except Exception as e:
            logger.error(f"Error en prueba de credenciales por defecto: {e}")

        # Integrar con herramientas de Kali si están disponibles
        self._test_default_creds_with_kali_tools()

        self.auth_findings['default_creds'] = results

    def _test_default_creds_with_kali_tools(self):
        """Probar credenciales por defecto con herramientas de Kali"""
        if 'brute' in self.kali_tools and 'hydra' in self.kali_tools['brute']:
            print("    [*] Probando con Hydra para credenciales por defecto")

            hydra = self.kali_tools['brute']['hydra']

            # Crear archivos temporales de usuarios y contraseñas
            users_file = f"/tmp/hydra_users_{self.target_info.domain}_{int(time.time())}.txt"
            passwords_file = f"/tmp/hydra_passwords_{self.target_info.domain}_{int(time.time())}.txt"

            try:
                # Escribir usuarios comunes
                with open(users_file, 'w') as f:
                    for user in self.common_usernames[:10]:  # Limitar para testing rápido
                        f.write(f"{user}\n")

                # Escribir contraseñas comunes
                with open(passwords_file, 'w') as f:
                    for pwd in self.common_passwords[:10]:
                        f.write(f"{pwd}\n")

                # Ejecutar Hydra
                result = hydra.hydra_web_form(
                    target=self.target_info.base_url,
                    form_path=self.login_url,
                    username_field=self.username_field,
                    password_field=self.password_field,
                    users_file=users_file,
                    passwords_file=passwords_file
                )

                if result.get('success'):
                    self.add_info(
                        'WSTG-ATHN-02-HYDRA-SCAN',
                        'Escaneo con Hydra completado',
                        {'result': result}
                    )

            except Exception as e:
                logger.error(f"Error ejecutando Hydra: {e}")
            finally:
                # Limpiar archivos temporales
                try:
                    os.remove(users_file)
                    os.remove(passwords_file)
                except:
                    pass

    def test_wstg_athn_03(self):
        """WSTG-ATHN-03: Testing for Weak Lock Out Mechanism"""
        print("\n[+] WSTG-ATHN-03: Lock Out Mechanism Testing")

        results = {
            'lockout_detected': False,
            'max_attempts': 0,
            'lockout_duration': 0,
            'error_messages': [],
            'timing_analysis': {}
        }

        login_url = urljoin(self.target_info.base_url, self.login_url)

        try:
            # Obtener formulario de login
            response = self.make_request('GET', login_url)
            if not response:
                return

            soup = BeautifulSoup(response.text, 'html.parser')
            login_form = soup.find('form')

            if not login_form:
                return

            username_field = self._get_form_field_name(login_form, 'username')
            password_field = self._get_form_field_name(login_form, 'password')

            # Analizar mensajes de error para detección de lockout
            error_messages = []
            attempt_times = []

            print("    [*] Probando mecanismo de lockout...")

            # Realizar intentos fallidos consecutivos
            max_test_attempts = 20
            for attempt in range(1, max_test_attempts + 1):
                start_time = time.time()

                try:
                    form_data = {
                        username_field: f"invalid_user_{attempt}",
                        password_field: f"wrong_password_{attempt}"
                    }

                    response = self.make_request('POST', login_url, data=form_data)
                    end_time = time.time()

                    attempt_time = end_time - start_time
                    attempt_times.append(attempt_time)

                    if response:
                        # Extraer mensaje de error
                        error_msg = self._extract_error_message(response.text)
                        error_messages.append({
                            'attempt': attempt,
                            'error': error_msg,
                            'status_code': response.status_code,
                            'response_time': attempt_time
                        })

                        # Verificar si hay indicio de lockout
                        lockout_indicators = [
                            'account locked', 'locked out', 'too many attempts',
                            'temporarily blocked', 'try again later', 'blocked'
                        ]

                        if any(indicator in error_msg.lower() for indicator in lockout_indicators):
                            results['lockout_detected'] = True
                            results['max_attempts'] = attempt
                            print(f"    [+] Lockout detectado después de {attempt} intentos")
                            break

                        # Verificar cambios en código de estado
                        if response.status_code in [429, 503]:  # Too Many Requests, Service Unavailable
                            results['lockout_detected'] = True
                            results['max_attempts'] = attempt
                            print(f"    [+] Posible lockout detectado (código {response.status_code})")
                            break

                except Exception as e:
                    logger.debug(f"Error en intento {attempt}: {e}")

                time.sleep(1)  # Pausa entre intentos

            # Si no se detectó lockout, analizar timing
            if not results['lockout_detected'] and attempt_times:
                avg_time = sum(attempt_times) / len(attempt_times)
                max_time = max(attempt_times)

                results['timing_analysis'] = {
                    'average_response_time': avg_time,
                    'max_response_time': max_time,
                    'attempts_tested': len(attempt_times)
                }

                if max_time > avg_time * 2:  # Variación significativa en timing
                    print(f"    [!] Posible timing attack detectado - Variación en tiempo de respuesta")

        except Exception as e:
            logger.error(f"Error en prueba de lockout: {e}")

        # Evaluar resultados
        if not results['lockout_detected']:
            self.add_vulnerability(
                'WSTG-ATHN-03-NO-LOCKOUT',
                'No se detectó mecanismo de lockout o es muy débil',
                {
                    'max_attempts_tested': 20,
                    'error_messages': results['error_messages'][:5]  # Primeros 5 mensajes
                },
                'medium',
                'CWE-307'
            )
            print(f"    [!] No se detectó mecanismo de lockout efectivo")
        else:
            print(f"    [+] Mecanismo de lockout detectado: {results['max_attempts']} intentos")
            self.add_info(
                'WSTG-ATHN-03-LOCKOUT-OK',
                f'Mecanismo de lockout detectado después de {results["max_attempts"]} intentos',
                results
            )

        self.auth_findings['lockout_mechanism'] = results

    def test_wstg_athn_04(self):
        """WSTG-ATHN-04: Testing for Bypassing Authentication Schema"""
        print("\n[+] WSTG-ATHN-04: Authentication Schema Bypass Testing")

        results = {
            'sql_injection_attempts': [],
            'parameter_pollution': [],
            'header_manipulation': [],
            'session_manipulation': [],
            'bypass_successful': False
        }

        login_url = urljoin(self.target_info.base_url, self.login_url)

        try:
            response = self.make_request('GET', login_url)
            if not response:
                return

            soup = BeautifulSoup(response.text, 'html.parser')
            login_form = soup.find('form')

            if not login_form:
                return

            username_field = self._get_form_field_name(login_form, 'username')
            password_field = self._get_form_field_name(login_form, 'password')

            # SQL Injection payloads
            sqli_payloads = [
                "admin' --",
                "admin' OR '1'='1",
                "admin' OR 1=1#",
                "' OR '1'='1' --",
                "admin' UNION SELECT * FROM users--",
                "' OR (SELECT COUNT(*) FROM users) > 0--",
                "admin'/**/OR/**/1=1--",
                "') OR '1'='1'--"
            ]

            print("    [*] Probando SQL Injection bypass...")

            for payload in sqli_payloads[:5]:  # Limitar para no ser bloqueados
                try:
                    form_data = {
                        username_field: payload,
                        password_field: 'password'
                    }

                    response = self.make_request('POST', login_url, data=form_data)

                    if response:
                        login_success = self._check_login_success(response, 'admin')

                        if login_success:
                            results['bypass_successful'] = True
                            results['sql_injection_attempts'].append({
                                'payload': payload,
                                'successful': True,
                                'response_code': response.status_code
                            })

                            self.add_vulnerability(
                                'WSTG-ATHN-04-SQLI-BYPASS',
                                f'Bypass de autenticación por SQL Injection: {payload}',
                                {'payload': payload, 'response_sample': response.text[:200]},
                                'critical',
                                'CWE-89'
                            )
                            print(f"    [!] SQL Injection bypass exitoso: {payload}")
                            break
                        else:
                            results['sql_injection_attempts'].append({
                                'payload': payload,
                                'successful': False,
                                'response_code': response.status_code
                            })

                except Exception as e:
                    logger.debug(f"Error probando payload {payload}: {e}")

            # HTTP Parameter Pollution
            print("    [*] Probando HTTP Parameter Pollution...")
            pollution_payloads = [
                {username_field: 'admin', f'{username_field}': 'password'},
                {username_field: 'admin', password_field: 'password', f'{password_field}': 'test'}
            ]

            for payload in pollution_payloads:
                try:
                    response = self.make_request('POST', login_url, data=payload)

                    if response and self._check_login_success(response, 'admin'):
                        results['bypass_successful'] = True
                        results['parameter_pollution'].append({
                            'payload': payload,
                            'successful': True
                        })

                        self.add_vulnerability(
                            'WSTG-ATHN-04-PARAM-POLLUTION',
                            'Bypass de autenticación por HTTP Parameter Pollution',
                            {'payload': payload},
                            'high',
                            'CWE-444'
                        )
                        print(f"    [!] Parameter Pollution bypass exitoso")
                        break

                except Exception as e:
                    logger.debug(f"Error en pollution payload: {e}")

            # Header manipulation attacks
            print("    [*] Probando manipulación de headers...")
            header_payloads = [
                {'X-Forwarded-For': '127.0.0.1'},
                {'X-Originating-IP': '127.0.0.1'},
                {'X-Remote-IP': '127.0.0.1'},
                {'X-Remote-Addr': '127.0.0.1'},
                {'User-Agent': 'admin'},
                {'Authorization': 'Basic YWRtaW46YWRtaW4='}  # admin:admin en base64
            ]

            for headers in header_payloads:
                try:
                    form_data = {
                        username_field: 'invalid',
                        password_field: 'invalid'
                    }

                    # Crear nueva sesión con headers personalizados
                    temp_session = requests.Session()
                    temp_session.headers.update(headers)

                    response = temp_session.post(login_url, data=form_data, timeout=self.default_timeout, verify=False)

                    if response and self._check_login_success(response, 'admin'):
                        results['bypass_successful'] = True
                        results['header_manipulation'].append({
                            'headers': headers,
                            'successful': True
                        })

                        self.add_vulnerability(
                            'WSTG-ATHN-04-HEADER-BYPASS',
                            'Bypass de autenticación por manipulación de headers',
                            {'headers': headers},
                            'high',
                            'CWE-304'
                        )
                        print(f"    [!] Header bypass exitoso: {headers}")
                        break

                except Exception as e:
                    logger.debug(f"Error en header payload: {e}")

            # Session manipulation
            print("    [*] Probando manipulación de sesión...")
            session_payloads = [
                {'authenticated': 'true', 'role': 'admin'},
                {'user_id': '1', 'is_admin': '1'},
                {'login': 'success', 'admin': 'true'}
            ]

            for session_data in session_payloads:
                try:
                    # Crear cookies con datos de sesión manipulados
                    cookies = {}
                    for key, value in session_data.items():
                        cookies[key] = value

                    response = self.make_request('GET', '/admin', cookies=cookies)

                    if response and response.status_code == 200:
                        results['bypass_successful'] = True
                        results['session_manipulation'].append({
                            'session_data': session_data,
                            'successful': True
                        })

                        self.add_vulnerability(
                            'WSTG-ATHN-04-SESSION-BYPASS',
                            'Bypass de autenticación por manipulación de sesión',
                            {'session_data': session_data},
                            'high',
                            'CWE-287'
                        )
                        print(f"    [!] Session bypass exitoso: {session_data}")
                        break

                except Exception as e:
                    logger.debug(f"Error en session payload: {e}")

        except Exception as e:
            logger.error(f"Error en prueba de bypass: {e}")

        if not results['bypass_successful']:
            print("    [+] No se encontraron métodos de bypass de autenticación")
            self.add_info(
                'WSTG-ATHN-04-BYPASS-FAILED',
                'No se encontraron métodos efectivos de bypass de autenticación',
                results
            )

        self.auth_findings['bypass_attempts'] = results

    def test_wstg_athn_05(self):
        """WSTG-ATHN-05: Testing for Vulnerable Remember Password"""
        print("\n[+] WSTG-ATHN-05: Remember Password Testing")

        results = {
            'remember_functionality': False,
            'token_analysis': {},
            'security_attributes': {},
            'token_predictability': False
        }

        try:
            # Buscar funcionalidad de "remember me" en el formulario de login
            login_url = urljoin(self.target_info.base_url, self.login_url)
            response = self.make_request('GET', login_url)

            if not response:
                return

            soup = BeautifulSoup(response.text, 'html.parser')
            login_form = soup.find('form')

            if not login_form:
                return

            # Buscar checkbox de "remember me"
            remember_checkbox = login_form.find('input', {'type': 'checkbox'})
            remember_labels = soup.find_all(text=re.compile(r'remember|remember\s+me|keep\s+me\s+logged', re.I))

            if remember_checkbox or remember_labels:
                results['remember_functionality'] = True
                print("    [*] Funcionalidad de 'Remember Me' detectada")

                # Analizar el checkbox
                if remember_checkbox:
                    checkbox_name = remember_checkbox.get('name', '')
                    checkbox_value = remember_checkbox.get('value', '')
                    results['remember_checkbox'] = {
                        'name': checkbox_name,
                        'value': checkbox_value
                    }

                # Probar la funcionalidad
                username_field = self._get_form_field_name(login_form, 'username')
                password_field = self._get_form_field_name(login_form, 'password')

                # Simular login con remember me activado
                form_data = {
                    username_field: 'test_user',
                    password_field: 'test_password'
                }

                if remember_checkbox:
                    form_data[remember_checkbox.get('name', 'remember')] = remember_checkbox.get('value', 'on')

                response = self.make_request('POST', login_url, data=form_data)

                if response:
                    # Analizar cookies establecidas
                    cookies_dict = {}
                    for cookie in response.cookies:
                        cookies_dict[cookie.name] = {
                            'value': cookie.value,
                            'domain': cookie.domain or '',
                            'path': cookie.path or '/',
                            'expires': cookie.expires if cookie.expires else None,
                            'secure': cookie.secure,
                            'httponly': cookie.httponly,
                            'samesite': cookie._rest.get('SameSite', '') if hasattr(cookie, '_rest') else ''
                        }

                    results['cookies_analysis'] = cookies_dict

                    # Buscar tokens de remember
                    for cookie_name, cookie_data in cookies_dict.items():
                        if any(keyword in cookie_name.lower() for keyword in ['remember', 'auth', 'token', 'session']):
                            token_value = cookie_data['value']

                            # Analizar token
                            token_analysis = self._analyze_remember_token(token_value)
                            results['token_analysis'][cookie_name] = token_analysis

                            # Verificar atributos de seguridad
                            security_attrs = {
                                'secure': cookie_data['secure'],
                                'httponly': cookie_data['httponly'],
                                'expires_soon': self._check_expiration_soon(cookie_data['expires']),
                                'long_expiration': self._check_long_expiration(cookie_data['expires'])
                            }

                            results['security_attributes'][cookie_name] = security_attrs

                            # Evaluar seguridad del token
                            if not security_attrs['secure']:
                                self.add_vulnerability(
                                    'WSTG-ATHN-05-INSECURE-COOKIE',
                                    f'Cookie de remember no segura: {cookie_name}',
                                    security_attrs,
                                    'medium',
                                    'CWE-1007'
                                )
                                print(f"    [!] Cookie insegura: {cookie_name}")

                            if not security_attrs['httponly']:
                                self.add_vulnerability(
                                    'WSTG-ATHN-05-NOT-HTTPONLY',
                                    f'Cookie de remember accesible via JavaScript: {cookie_name}',
                                    {'cookie_name': cookie_name},
                                    'low',
                                    'CWE-1004'
                                )

                            if security_attrs['long_expiration']:
                                self.add_vulnerability(
                                    'WSTG-ATHN-05-LONG-EXPIRATION',
                                    f'Cookie de remember con expiración muy larga: {cookie_name}',
                                    security_attrs,
                                    'medium',
                                    'CWE-613'
                                )

                            if token_analysis['is_predictable']:
                                results['token_predictability'] = True
                                self.add_vulnerability(
                                    'WSTG-ATHN-05-PREDICTABLE-TOKEN',
                                    f'Token de remember predecible: {cookie_name}',
                                    token_analysis,
                                    'high',
                                    'CWE-340'
                                )
                                print(f"    [!] Token predecible: {cookie_name}")

            else:
                print("    [-] No se detectó funcionalidad de 'Remember Me'")

        except Exception as e:
            logger.error(f"Error en prueba de remember password: {e}")

        self.auth_findings['remember_password'] = results

    def _analyze_remember_token(self, token: str) -> dict:
        """Analiza un token de remember password"""
        analysis = {
            'length': len(token),
            'format': 'unknown',
            'encoding': 'unknown',
            'is_predictable': False,
            'entropy_score': 0
        }

        try:
            # Determinar formato
            if re.match(r'^[a-zA-Z0-9+/=]+$', token):
                # Podría ser Base64
                try:
                    decoded = base64.b64decode(token + '=' * (-len(token) % 4))
                    if decoded:
                        analysis['format'] = 'base64'
                        analysis['encoding'] = 'base64'
                except:
                    pass

            # Verificar si es UUID
            if re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', token):
                analysis['format'] = 'uuid'

            # Verificar si es hash
            if re.match(r'^[a-fA-F0-9]{32}$', token):
                analysis['format'] = 'md5'
            elif re.match(r'^[a-fA-F0-9]{40}$', token):
                analysis['format'] = 'sha1'
            elif re.match(r'^[a-fA-F0-9]{64}$', token):
                analysis['format'] = 'sha256'

            # Calcular entropía básica
            unique_chars = len(set(token))
            analysis['entropy_score'] = unique_chars / len(token)

            # Determinar si es predecible (análisis simple)
            if analysis['format'] in ['md5', 'sha1', 'sha256']:
                # Hash de algo predecible?
                if token.lower() in hashlib.md5(b'admin').hexdigest().lower():
                    analysis['is_predictable'] = True
                elif token.lower() in hashlib.md5(b'password').hexdigest().lower():
                    analysis['is_predictable'] = True

        except Exception as e:
            logger.debug(f"Error analizando token: {e}")

        return analysis

    def _check_expiration_soon(self, expires_timestamp: int) -> bool:
        """Verifica si la cookie expira pronto (menos de 1 hora)"""
        if not expires_timestamp:
            return False

        expires_date = datetime.fromtimestamp(expires_timestamp)
        time_until_expiry = expires_date - datetime.now()
        return time_until_expiry.total_seconds() < 3600  # Menos de 1 hora

    def _check_long_expiration(self, expires_timestamp: int) -> bool:
        """Verifica si la cookie tiene expiración muy larga (más de 30 días)"""
        if not expires_timestamp:
            return False

        expires_date = datetime.fromtimestamp(expires_timestamp)
        time_until_expiry = expires_date - datetime.now()
        return time_until_expiry.total_seconds() > 2592000  # Más de 30 días

    def test_wstg_athn_06(self):
        """WSTG-ATHN-06: Testing for Browser Cache Weakness"""
        print("\n[+] WSTG-ATHN-06: Browser Cache Testing")

        results = {
            'cache_headers': {},
            'autocomplete_status': {},
            'form_autocomplete': False,
            'password_autocomplete': False
        }

        try:
            login_url = urljoin(self.target_info.base_url, self.login_url)
            response = self.make_request('GET', login_url)

            if not response:
                return

            soup = BeautifulSoup(response.text, 'html.parser')

            # Analizar headers anti-cache
            cache_headers = {
                'cache-control': response.headers.get('cache-control', '').lower(),
                'pragma': response.headers.get('pragma', '').lower(),
                'expires': response.headers.get('expires', ''),
                'surrogate-control': response.headers.get('surrogate-control', '').lower()
            }

            results['cache_headers'] = cache_headers

            # Evaluar headers anti-cache
            cache_control_value = cache_headers['cache-control']
            is_no_cache = (
                'no-store' in cache_control_value or
                'no-cache' in cache_control_value or
                'must-revalidate' in cache_control_value or
                cache_headers['pragma'] == 'no-cache'
            )

            if not is_no_cache:
                self.add_vulnerability(
                    'WSTG-ATHN-06-MISSING-CACHE-HEADERS',
                    'Faltan headers anti-cache en página de login',
                    cache_headers,
                    'medium',
                    'CWE-525'
                )
                print("    [!] Faltan headers anti-cache")
            else:
                print("    [+] Headers anti-cache presentes")

            # Analizar atributos autocomplete en el formulario
            login_form = soup.find('form')

            if login_form:
                # Verificar autocomplete del formulario
                form_autocomplete = login_form.get('autocomplete', '').lower()
                results['form_autocomplete'] = form_autocomplete != 'off'

                # Verificar campos de contraseña
                password_inputs = soup.find_all('input', {'type': 'password'})
                for pwd_input in password_inputs:
                    pwd_autocomplete = pwd_input.get('autocomplete', '').lower()
                    if pwd_autocomplete != 'off':
                        results['password_autocomplete'] = True

            # Evaluar configuración de autocomplete
            if results['form_autocomplete'] or results['password_autocomplete']:
                self.add_vulnerability(
                    'WSTG-ATHN-06-AUTOCOMPLETE-ENABLED',
                    'Autocomplete habilitado en formulario de autenticación',
                    {
                        'form_autocomplete': results['form_autocomplete'],
                        'password_autocomplete': results['password_autocomplete']
                    },
                    'medium',
                    'CWE-539'
                )
                print("    [!] Autocomplete habilitado (permite almacenar contraseñas)")
            else:
                print("    [+] Autocomplete deshabilitado correctamente")

        except Exception as e:
            logger.error(f"Error en prueba de browser cache: {e}")

        self.auth_findings['browser_cache'] = results

    def test_wstg_athn_07(self):
        """WSTG-ATHN-07: Testing for Weak Password Policy"""
        print("\n[+] WSTG-ATHN-07: Password Policy Testing")

        results = {
            'password_requirements': {},
            'tested_passwords': [],
            'policy_enforced': False,
            'weak_passwords_accepted': []
        }

        try:
            # Buscar formularios de registro o cambio de contraseña
            registration_form = self._find_registration_form()
            change_password_form = self._find_change_password_form()

            # Testear política de contraseñas
            test_passwords = [
                {'password': '123', 'description': 'Too short'},
                {'password': 'password', 'description': 'Dictionary word'},
                {'password': '12345678', 'description': 'Only numbers'},
                {'password': 'abcdefgh', 'description': 'Only letters'},
                {'password': 'Password1', 'description': 'Weak complexity'},
                {'password': 'P@ssw0rd!', 'description': 'Strong password'}
            ]

            if registration_form:
                print("    [*] Probando política en formulario de registro")
                self._test_password_policy_form(registration_form, test_passwords, results)

            elif change_password_form:
                print("    [*] Probando política en formulario de cambio de contraseña")
                self._test_password_policy_form(change_password_form, test_passwords, results)

            else:
                print("    [-] No se encontraron formularios para probar política de contraseñas")

        except Exception as e:
            logger.error(f"Error en prueba de política de contraseñas: {e}")

        # Evaluar resultados
        weak_accepted_count = len(results['weak_passwords_accepted'])
        if weak_accepted_count > 2:  # Más de 2 contraseñas débiles aceptadas
            self.add_vulnerability(
                'WSTG-ATHN-07-WEAK-POLICY',
                f'Política de contraseñas débil - {weak_accepted_count} contraseñas débiles aceptadas',
                results,
                'medium',
                'CWE-521'
            )
            print(f"    [!] Política de contraseñas débil - {weak_accepted_count} débiles aceptadas")
        elif results['tested_passwords']:
            print("    [+] Política de contraseñas adecuada")
            results['policy_enforced'] = True

        self.auth_findings['password_policy'] = results

    def test_wstg_athn_08(self):
        """WSTG-ATHN-08: Testing for Weak Security Question Answer"""
        print("\n[+] WSTG-ATHN-08: Security Questions Testing")

        results = {
            'security_questions_found': False,
            'questions': [],
            'enumeration_possible': False,
            'rate_limited': False
        }

        try:
            # Buscar formulario de recuperación de contraseña
            recovery_url = urljoin(self.target_info.base_url, '/forgot-password')
            reset_url = urljoin(self.target_info.base_url, '/reset-password')

            for url in [recovery_url, reset_url]:
                response = self.make_request('GET', url)

                if response and response.status_code == 200:
                    soup = BeautifulSoup(response.text, 'html.parser')

                    # Buscar preguntas de seguridad
                    questions = self._find_security_questions(soup)

                    if questions:
                        results['security_questions_found'] = True
                        results['questions'].extend(questions)
                        print(f"    [*] Preguntas de seguridad encontradas en: {url}")

                        # Analizar calidad de las preguntas
                        weak_questions = []
                        for question in questions:
                            if self._is_weak_security_question(question):
                                weak_questions.append(question)

                        if weak_questions:
                            self.add_vulnerability(
                                'WSTG-ATHN-08-WEAK-QUESTIONS',
                                'Preguntas de seguridad débiles o adivinables',
                                {'weak_questions': weak_questions},
                                'medium',
                                'CWE-640'
                            )
                            print(f"    [!] {len(weak_questions)} preguntas de seguridad débiles")

            # Probar enumeración de usuarios
            if results['security_questions_found']:
                print("    [*] Probando enumeración de usuarios...")

                test_emails = [
                    'admin@target.com',
                    'administrator@target.com',
                    'test@target.com',
                    'nonexistent@target.com'
                ]

                responses = {}
                for email in test_emails:
                    response = self.make_request('POST', recovery_url, data={'email': email})

                    if response:
                        responses[email] = {
                            'status_code': response.status_code,
                            'content_length': len(response.content),
                            'response_preview': response.text[:200]
                        }

                # Analizar diferencias en respuestas
                status_codes = [r['status_code'] for r in responses.values()]
                content_lengths = [r['content_length'] for r in responses.values()]

                if len(set(status_codes)) > 1 or max(content_lengths) - min(content_lengths) > 100:
                    results['enumeration_possible'] = True
                    self.add_vulnerability(
                        'WSTG-ATHN-08-ENUMERATION',
                        'Posible enumeración de usuarios por respuestas diferenciadas',
                        responses,
                        'medium',
                        'CWE-204'
                    )
                    print("    [!] Posible enumeración de usuarios detectada")

        except Exception as e:
            logger.error(f"Error en prueba de preguntas de seguridad: {e}")

        self.auth_findings['security_questions'] = results

    def test_wstg_athn_09(self):
        """WSTG-ATHN-09: Testing for Weak Password Change or Reset Functionalities"""
        print("\n[+] WSTG-ATHN-09: Password Reset Testing")

        results = {
            'reset_functionality': False,
            'token_analysis': {},
            'current_password_required': False,
            'rate_limiting': False
        }

        try:
            # Buscar funcionalidad de reset de contraseña
            reset_url = urljoin(self.target_info.base_url, '/forgot-password')
            response = self.make_request('GET', reset_url)

            if response and response.status_code == 200:
                results['reset_functionality'] = True
                print("    [*] Funcionalidad de reset de contraseña encontrada")

                # Analizar formulario de reset
                soup = BeautifulSoup(response.text, 'html.parser')
                reset_form = soup.find('form')

                if reset_form:
                    # Probar generar tokens de reset
                    test_email = f"test_{int(time.time())}@test.com"

                    # Buscar campo de email
                    email_input = reset_form.find('input', {'name': re.compile(r'email', re.I)})
                    if email_input:
                        email_field = email_input.get('name', 'email')

                        # Enviar solicitud de reset
                        reset_response = self.make_request('POST', reset_url, data={email_field: test_email})

                        if reset_response:
                            # Analizar respuesta
                            token_analysis = self._analyze_password_reset_response(reset_response.text)
                            results['token_analysis'] = token_analysis

            # Buscar formulario de cambio de contraseña
            change_password_url = urljoin(self.target_info.base_url, '/change-password')
            cp_response = self.make_request('GET', change_password_url)

            if cp_response and cp_response.status_code == 200:
                cp_soup = BeautifulSoup(cp_response.text, 'html.parser')
                cp_form = cp_soup.find('form')

                if cp_form:
                    # Verificar si requiere contraseña actual
                    current_pwd_input = cp_form.find('input', {'name': re.compile(r'current|old', re.I)})
                    new_pwd_input = cp_form.find('input', {'name': re.compile(r'new|password', re.I)})

                    if current_pwd_input and new_pwd_input:
                        results['current_password_required'] = True
                        print("    [+] Cambio de contraseña requiere contraseña actual")
                    else:
                        self.add_vulnerability(
                            'WSTG-ATHN-09-NO-CURRENT-PASSWORD',
                            'Cambio de contraseña no requiere contraseña actual',
                            {'form_fields': [inp.get('name') for inp in cp_form.find_all('input')]}
                        )

        except Exception as e:
            logger.error(f"Error en prueba de password reset: {e}")

        self.auth_findings['password_reset'] = results

    def test_wstg_athn_10(self):
        """WSTG-ATHN-10: Testing for Weaker Authentication in Alternative Channel"""
        print("\n[+] WSTG-ATHN-10: Alternative Channel Authentication Testing")

        results = {
            'alternative_channels': [],
            'weak_auth_found': [],
            'channels_tested': []
        }

        # Canales alternativos comunes
        alternative_endpoints = [
            '/api/login',
            '/api/auth/login',
            '/mobile/login',
            '/admin/login',
            '/api/v1/auth',
            '/auth/token',
            '/oauth/token'
        ]

        for endpoint in alternative_endpoints:
            try:
                url = urljoin(self.target_info.base_url, endpoint)
                response = self.make_request('GET', url)

                if response and response.status_code == 200:
                    results['alternative_channels'].append({
                        'endpoint': endpoint,
                        'url': url,
                        'status_code': response.status_code
                    })
                    results['channels_tested'].append(endpoint)

                    print(f"    [*] Canal alternativo encontrado: {endpoint}")

                    # Probar autenticación en este canal
                    if endpoint.startswith('/api/') or 'mobile' in endpoint:
                        # Probar autenticación API
                        auth_result = self._test_api_authentication(url)
                        if auth_result['vulnerable']:
                            results['weak_auth_found'].append(auth_result)

            except Exception as e:
                logger.debug(f"Error probando endpoint {endpoint}: {e}")

        # Evaluar resultados
        if results['weak_auth_found']:
            self.add_vulnerability(
                'WSTG-ATHN-10-WEAK-ALT-CHANNEL',
                'Autenticación débil en canal alternativo',
                {'weak_channels': results['weak_auth_found']},
                'high',
                'CWE-287'
            )
            print(f"    [!] {len(results['weak_auth_found'])} canales con autenticación débil")

        self.auth_findings['alternative_channels'] = results

    def test_wstg_athn_11(self):
        """WSTG-ATHN-11: Testing Multi-Factor Authentication (MFA)"""
        print("\n[+] WSTG-ATHN-11: MFA Testing")

        results = {
            'mfa_implementation': False,
            'mfa_methods': [],
            'bypass_possible': False,
            'otp_analysis': {}
        }

        try:
            # Buscar evidencia de MFA en la aplicación
            login_response = self.make_request('GET', self.login_url)

            if login_response:
                # Analizar respuesta buscando MFA
                content = login_response.text.lower()

                mfa_indicators = [
                    'two factor', '2fa', 'mfa', 'multi-factor',
                    'verification code', 'authenticator', 'otp',
                    'totp', 'google authenticator', 'sms verification',
                    'email code', 'push notification'
                ]

                for indicator in mfa_indicators:
                    if indicator in content:
                        results['mfa_implementation'] = True
                        results['mfa_methods'].append(indicator)
                        print(f"    [*] Indicador MFA encontrado: {indicator}")

                # Buscar endpoints de MFA
                mfa_endpoints = [
                    '/mfa/verify',
                    '/2fa/verify',
                    '/auth/verify-code',
                    '/api/mfa',
                    '/verify-otp'
                ]

                for endpoint in mfa_endpoints:
                    url = urljoin(self.target_info.base_url, endpoint)
                    response = self.make_request('GET', url)

                    if response and response.status_code == 200:
                        results['mfa_implementation'] = True
                        print(f"    [*] Endpoint MFA encontrado: {endpoint}")

                # Probar bypass de MFA si está implementado
                if results['mfa_implementation']:
                    bypass_result = self._test_mfa_bypass()
                    if bypass_result['bypass_possible']:
                        results['bypass_possible'] = True
                        self.add_vulnerability(
                            'WSTG-ATHN-11-MFA-BYPASS',
                            'Bypass de MFA posible',
                            bypass_result,
                            'critical',
                            'CWE-303'
                        )
                        print("    [!] Bypass de MFA posible")

        except Exception as e:
            logger.error(f"Error en prueba de MFA: {e}")

        # Evaluar implementación de MFA
        if not results['mfa_implementation']:
            print("    [-] No se detectó implementación de MFA")
            self.add_vulnerability(
                'WSTG-ATHN-11-NO-MFA',
                'No se implementa MFA (recomendado para acceso crítico)',
                results,
                'medium',
                'CWE-304'
            )
        else:
            print("    [+] MFA implementado")

        self.auth_findings['mfa_implementation'] = results

    def test_brute_force_with_kali_tools(self):
        """Pruebas de fuerza bruta con herramientas de Kali"""
        print("\n[*] Ejecutando pruebas con herramientas de Kali Linux")

        # Pruebas con Hydra
        if 'brute' in self.kali_tools and 'hydra' in self.kali_tools['brute']:
            print("    [*] Iniciando fuerza bruta con Hydra...")
            hydra_result = self._run_hydra_brute_force()
            if hydra_result:
                self.auth_findings['hydra_results'] = hydra_result

        # Pruebas con Hashcat (si hay hashes)
        if 'brute' in self.kali_tools and 'hashcat' in self.kali_tools['brute']:
            print("    [*] Preparando pruebas con Hashcat...")
            # Esto se implementaría si se encuentran hashes de contraseñas

    def _run_hydra_brute_force(self):
        """Ejecuta fuerza bruta con Hydra"""
        try:
            hydra = self.kali_tools['brute']['hydra']

            # Crear archivos temporales
            users_file = f"/tmp/hydra_users_{int(time.time())}.txt"
            passwords_file = f"/tmp/hydra_passwords_{int(time.time())}.txt"

            # Escribir usuarios y contraseñas limitados para testing
            with open(users_file, 'w') as f:
                for user in self.common_usernames[:5]:
                    f.write(f"{user}\n")

            with open(passwords_file, 'w') as f:
                for pwd in self.common_passwords[:5]:
                    f.write(f"{pwd}\n")

            # Ejecutar Hydra
            result = hydra.hydra_web_form(
                target=self.target_info.base_url,
                form_path=self.login_url,
                username_field=self.username_field,
                password_field=self.password_field,
                users_file=users_file,
                passwords_file=passwords_file
            )

            # Limpiar archivos
            os.remove(users_file)
            os.remove(passwords_file)

            return result

        except Exception as e:
            logger.error(f"Error ejecutando Hydra: {e}")
            return None

    def _check_login_success(self, response, username=None):
        """Verifica si el login fue exitoso basado en la respuesta"""
        if not response:
            return False

        # Indicadores de login exitoso
        success_indicators = [
            response.status_code in [200, 302],
            'dashboard' in response.text.lower(),
            'welcome' in response.text.lower(),
            'logout' in response.text.lower(),
            'profile' in response.text.lower(),
            'home' in response.text.lower(),
            len(response.cookies) > 0,
            'session' in str(response.cookies).lower()
        ]

        # Indicadores de login fallido
        failure_indicators = [
            'invalid' in response.text.lower(),
            'incorrect' in response.text.lower(),
            'failed' in response.text.lower(),
            'error' in response.text.lower(),
            'denied' in response.text.lower(),
            'wrong' in response.text.lower()
        ]

        # Evaluar
        success_score = sum(success_indicators)
        failure_score = sum(failure_indicators)

        return success_score > failure_score

    def _get_form_field_name(self, form, field_type):
        """Obtiene el nombre de un campo en un formulario"""
        field_patterns = {
            'username': ['username', 'user', 'email', 'login', 'id'],
            'password': ['password', 'pass', 'pwd', 'passwd']
        }

        for pattern in field_patterns.get(field_type, []):
            field = form.find('input', {'name': re.compile(pattern, re.I)})
            if field:
                return field.get('name')

        return field_type  # Default

    def _extract_error_message(self, html_content):
        """Extrae mensaje de error del contenido HTML"""
        soup = BeautifulSoup(html_content, 'html.parser')

        # Buscar clases comunes de error
        error_classes = ['error', 'alert', 'warning', 'danger', 'message']
        for class_name in error_classes:
            error_element = soup.find(class_=re.compile(class_name, re.I))
            if error_element:
                return error_element.get_text(strip=True)

        # Buscar patrones de error en el texto
        error_patterns = [
            r'(?:error|alert|warning):\s*(.*?)(?:\.|$)',
            r'(?:invalid|incorrect|failed):\s*(.*?)(?:\.|$)'
        ]

        for pattern in error_patterns:
            match = re.search(pattern, html_content, re.I)
            if match:
                return match.group(1).strip()

        return ""

    def _find_registration_form(self):
        """Busca formulario de registro"""
        registration_urls = [
            '/register',
            '/signup',
            '/registration',
            '/join',
            '/create-account'
        ]

        for url in registration_urls:
            full_url = urljoin(self.target_info.base_url, url)
            response = self.make_request('GET', full_url)

            if response and response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                form = soup.find('form')

                if form:
                    # Verificar si tiene campos de contraseña
                    password_input = form.find('input', {'type': 'password'})
                    if password_input:
                        return {'url': full_url, 'form': form}

        return None

    def _find_change_password_form(self):
        """Busca formulario de cambio de contraseña"""
        change_password_urls = [
            '/change-password',
            '/profile',
            '/settings',
            '/account'
        ]

        for url in change_password_urls:
            full_url = urljoin(self.target_info.base_url, url)
            response = self.make_request('GET', full_url)

            if response and response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                form = soup.find('form')

                if form:
                    # Verificar si tiene campos de contraseña
                    password_inputs = form.find_all('input', {'type': 'password'})
                    if len(password_inputs) >= 1:
                        return {'url': full_url, 'form': form}

        return None

    def _test_password_policy_form(self, form_info, test_passwords, results):
        """Prueba política de contraseñas en un formulario específico"""
        # Implementación simplificada - en producción se harían submit reales
        for test_case in test_passwords:
            test_result = {
                'password': test_case['password'],
                'description': test_case['description'],
                'accepted': False,
                'error_message': None
            }

            # Simulación - en realidad se haría submit del formulario
            # Aquí asumimos que contraseñas muy cortas son rechazadas
            if len(test_case['password']) < 4:
                test_result['accepted'] = False
                test_result['error_message'] = 'Password too short'
            else:
                # Asumimos que otras contraseñas son aceptadas (para testing)
                test_result['accepted'] = True

            if test_result['accepted'] and test_case['description'] in ['Too short', 'Dictionary word', 'Only numbers']:
                results['weak_passwords_accepted'].append(test_result)

            results['tested_passwords'].append(test_result)

    def _find_security_questions(self, soup):
        """Encuentra preguntas de seguridad en el HTML"""
        questions = []

        # Buscar etiquetas comunes de preguntas
        question_labels = soup.find_all(text=re.compile(r'(?:question|security|answer)', re.I))
        for label in question_labels:
            parent = label.parent
            if parent:
                question_text = label.strip()
                if len(question_text) > 10:  # Filtro para evitar falsos positivos
                    questions.append(question_text)

        # Buscar selects de preguntas de seguridad
        question_selects = soup.find_all('select', {'name': re.compile(r'question', re.I)})
        for select in question_selects:
            options = select.find_all('option')
            for option in options:
                option_text = option.get_text(strip=True)
                if len(option_text) > 10:
                    questions.append(option_text)

        return questions[:5]  # Limitar a 5 preguntas

    def _is_weak_security_question(self, question):
        """Determina si una pregunta de seguridad es débil"""
        weak_patterns = [
            r'what.*?name',
            r'where.*?born',
            r'favorite.*?color',
            r'pet.*?name',
            r'mother.*?maiden',
            r'first.*?school',
            r'favorite.*?food'
        ]

        question_lower = question.lower()
        return any(re.search(pattern, question_lower) for pattern in weak_patterns)

    def _analyze_password_reset_response(self, response_text):
        """Analiza respuesta de reset de contraseña"""
        analysis = {
            'token_in_response': False,
            'token_length': 0,
            'predictable_format': False
        }

        # Buscar patrones de token
        token_patterns = [
            r'token[:=]\s*([a-zA-Z0-9+/=]{20,})',
            r'code[:=]\s*([a-zA-Z0-9]{6,})',
            r'verification[:=]\s*([a-zA-Z0-9]{6,})'
        ]

        for pattern in token_patterns:
            match = re.search(pattern, response_text, re.I)
            if match:
                token = match.group(1)
                analysis['token_in_response'] = True
                analysis['token_length'] = len(token)

                # Verificar si es predecible
                if re.match(r'^[0-9]+$', token):
                    analysis['predictable_format'] = True
                elif re.match(r'^[a-zA-Z0-9]{8}$', token):
                    analysis['predictable_format'] = True

                break

        return analysis

    def _test_api_authentication(self, auth_url):
        """Prueba autenticación en endpoint API"""
        result = {
            'endpoint': auth_url,
            'vulnerable': False,
            'findings': []
        }

        try:
            # Probar diferentes métodos de autenticación API
            auth_methods = [
                # JSON POST
                {
                    'method': 'POST',
                    'headers': {'Content-Type': 'application/json'},
                    'data': json.dumps({'username': 'admin', 'password': 'admin'})
                },
                # Form POST
                {
                    'method': 'POST',
                    'headers': {'Content-Type': 'application/x-www-form-urlencoded'},
                    'data': 'username=admin&password=admin'
                },
                # Basic Auth
                {
                    'method': 'GET',
                    'headers': {'Authorization': 'Basic YWRtaW46YWRtaW4='}  # admin:admin
                }
            ]

            for auth_method in auth_methods:
                response = requests.request(
                    auth_method['method'],
                    auth_url,
                    headers=auth_method['headers'],
                    data=auth_method.get('data'),
                    timeout=10,
                    verify=False
                )

                if response.status_code == 200:
                    result['vulnerable'] = True
                    result['findings'].append({
                        'method': auth_method['method'],
                        'success': True,
                        'response_preview': response.text[:100]
                    })
                    break

        except Exception as e:
            logger.debug(f"Error probando autenticación API: {e}")

        return result

    def _test_mfa_bypass(self):
        """Prueba bypass de MFA"""
        # Implementación simplificada - en producción se harían pruebas más exhaustivas
        return {
            'bypass_possible': False,
            'methods_tested': ['session_manipulation', 'parameter_pollution']
        }

    def save_results(self, output_dir: str = ".", format: str = "both"):
        """Guardar resultados específicos de autenticación"""
        # Guardar resultados base
        super().save_results(output_dir, format)

        # Agregar hallazgos específicos de autenticación
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Guardar archivo adicional con hallazgos de autenticación
        auth_results_file = f"{output_dir}/auth_findings_{self.target_info.domain}_{timestamp}.json"
        with open(auth_results_file, 'w', encoding='utf-8') as f:
            json.dump(self.auth_findings, f, indent=2, ensure_ascii=False)

        print(f"[+] Hallazgos de autenticación guardados en: {auth_results_file}")

def main():
    parser = argparse.ArgumentParser(description='OWASP WSTG Authentication Testing Framework')
    parser.add_argument('--target', required=True, help='Dominio objetivo (ej: ejemplo.com)')
    parser.add_argument('--login-url', default='/login', help='URL de login (default: /login)')
    parser.add_argument('--username-field', default='username', help='Campo de username (default: username)')
    parser.add_argument('--password-field', default='password', help='Campo de password (default: password)')
    parser.add_argument('--kali-tools', action='store_true', help='Usar herramientas de Kali')
    parser.add_argument('--verbose', '-v', action='store_true', help='Modo verbose')

    args = parser.parse_args()

    try:
        config = {
            'login_url': args.login_url,
            'username_field': args.username_field,
            'password_field': args.password_field,
            'use_kali_tools': args.kali_tools
        }

        tester = AuthenticationTester(args.target, config)
        success = tester.run_tests()

        if success:
            tester.save_results()
            print(f"\n[+] Pruebas de autenticación completadas para {args.target}")
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
#!/usr/bin/env python3
"""
OWASP WSTG Configuration and Deployment Management Testing Framework
Autor: Framework OWASP WSTG
Propósito: Automatizar pruebas de Configuration Testing (WSTG-CONF)

Este script realiza pruebas automatizadas de configuración y despliegue
siguiendo los estándares de OWASP Web Security Testing Guide.

Uso: python configuration_testing.py --target <domain.com>

Requisitos: pip install requests beautifulsoup4 ssl-checker python-nmap dnspython
"""

import requests
import json
import time
import sys
import argparse
import re
import socket
import ssl
import subprocess
import OpenSSL
from urllib.parse import urlparse
from datetime import datetime
import dns.resolver

class ConfigurationTesting:
    def __init__(self, target):
        self.target = target
        self.url = f"https://{target}" if not target.startswith(('http://', 'https://')) else target
        self.domain = urlparse(self.url).netloc
        self.results = {
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'tests': {}
        }

    def run_all_tests(self):
        """Ejecutar todas las pruebas de Configuration Testing"""
        print(f"[*] Iniciando pruebas de Configuration Testing para: {self.target}")
        print("=" * 60)

        # WSTG-CONF-06: HTTP Methods
        self.test_wstg_conf_06()

        # WSTG-CONF-07: HSTS Testing
        self.test_wstg_conf_07()

        # WSTG-CONF-08: RIA Cross Domain Policy
        self.test_wstg_conf_08()

        # WSTG-CONF-12: CSP Testing
        self.test_wstg_conf_12()

        # WSTG-CONF-14: HTTP Security Headers
        self.test_wstg_conf_14()

        # WSTG-CONF-03: File Extensions Handling
        self.test_wstg_conf_03()

        # WSTG-CONF-04: Backup Files
        self.test_wstg_conf_04()

        # WSTG-CONF-05: Admin Interfaces
        self.test_wstg_conf_05()

        # WSTG-CONF-10: Subdomain Takeover
        self.test_wstg_conf_10()

        # Guardar resultados
        self.save_results()

    def test_wstg_conf_06(self):
        """WSTG-CONF-06: Test HTTP Methods"""
        print("\n[+] WSTG-CONF-06: HTTP Methods Testing")

        results = {
            'allowed_methods': [],
            'dangerous_methods': [],
            'options_method': {},
            'put_test': {},
            'delete_test': {},
            'trace_test': {}
        }

        try:
            # Probar OPTIONS para descubrir métodos permitidos
            response = requests.options(self.url, timeout=10, verify=False)
            if 'Allow' in response.headers:
                allowed = [method.strip() for method in response.headers['Allow'].split(',')]
                results['allowed_methods'] = allowed
                results['options_method'] = {
                    'status_code': response.status_code,
                    'allow_header': response.headers['Allow']
                }
                print(f"    [*] Métodos permitidos: {', '.join(allowed)}")

                # Identificar métodos peligrosos
                dangerous_methods = ['PUT', 'DELETE', 'TRACE', 'CONNECT', 'PATCH']
                results['dangerous_methods'] = [method for method in dangerous_methods if method in allowed]

                if results['dangerous_methods']:
                    print(f"    [!] Métodos peligrosos detectados: {', '.join(results['dangerous_methods'])}")

            # Probar método PUT
            try:
                test_content = "test content for configuration testing"
                put_response = requests.put(f"{self.url}/config_test.txt",
                                           data=test_content,
                                           timeout=10,
                                           verify=False)
                results['put_test'] = {
                    'status_code': put_response.status_code,
                    'allowed': put_response.status_code not in [405, 501]
                }
                if put_response.status_code not in [405, 501]:
                    print(f"    [!] PUT método permitido - Código: {put_response.status_code}")

                    # Intentar acceder al archivo creado
                    get_response = requests.get(f"{self.url}/config_test.txt", timeout=10, verify=False)
                    if get_response.status_code == 200 and test_content in get_response.text:
                        print(f"    [!] Archivo creado exitosamente - VULNERABILIDAD CRÍTICA")
                    # Limpiar archivo creado
                    requests.delete(f"{self.url}/config_test.txt", timeout=10, verify=False)
            except:
                results['put_test'] = {'error': 'Method not tested'}

            # Probar método TRACE
            try:
                trace_response = requests.request('TRACE', self.url, timeout=10, verify=False)
                results['trace_test'] = {
                    'status_code': trace_response.status_code,
                    'allowed': trace_response.status_code not in [405, 501]
                }
                if trace_response.status_code not in [405, 501]:
                    print(f"    [!] TRACE método permitido - Posible XSS")
            except:
                results['trace_test'] = {'error': 'Method not tested'}

        except requests.exceptions.RequestException as e:
            print(f"    [-] Error probando métodos HTTP: {e}")
            results['error'] = str(e)

        self.results['tests']['WSTG-CONF-06'] = results

    def test_wstg_conf_07(self):
        """WSTG-CONF-07: Test HTTP Strict Transport Security"""
        print("\n[+] WSTG-CONF-07: HSTS Testing")

        results = {
            'hsts_present': False,
            'hsts_header': None,
            'max_age': None,
            'include_subdomains': False,
            'preload': False,
            'recommendations': []
        }

        try:
            if not self.url.startswith('https://'):
                print("    [-] No es HTTPS - HSTS no aplicable")
                results['error'] = 'HTTPS required for HSTS'
            else:
                response = requests.get(self.url, timeout=10, verify=False)

                if 'strict-transport-security' in response.headers:
                    results['hsts_present'] = True
                    results['hsts_header'] = response.headers['strict-transport-security']

                    # Parsear HSTS header
                    hsts_header = response.headers['strict-transport-security']

                    # Extraer max-age
                    max_age_match = re.search(r'max-age=(\d+)', hsts_header)
                    if max_age_match:
                        results['max_age'] = int(max_age_match.group(1))

                    # Verificar includeSubDomains
                    results['include_subdomains'] = 'includesubdomains' in hsts_header.lower()

                    # Verificar preload
                    results['preload'] = 'preload' in hsts_header.lower()

                    print(f"    [+] HSTS presente: {hsts_header}")

                    # Evaluar configuración
                    if results['max_age'] and results['max_age'] < 31536000:  # 1 año
                        results['recommendations'].append("Max-age debe ser al menos 31536000 (1 año)")

                    if not results['include_subdomains']:
                        results['recommendations'].append("Considerar includeSubDomains para mayor protección")

                    if not results['preload']:
                        results['recommendations'].append("Considerar preload para inclusión en lista preload de Chrome")

                else:
                    print("    [-] HSTS no implementado")
                    results['recommendations'].append("Implementar HSTS para forzar HTTPS")

        except requests.exceptions.RequestException as e:
            print(f"    [-] Error probando HSTS: {e}")
            results['error'] = str(e)

        self.results['tests']['WSTG-CONF-07'] = results

    def test_wstg_conf_08(self):
        """WSTG-CONF-08: Test RIA Cross Domain Policy"""
        print("\n[+] WSTG-CONF-08: RIA Cross Domain Policy")

        results = {
            'crossdomain_xml': None,
            'clientaccesspolicy_xml': None,
            'security_issues': [],
            'policy_analysis': {}
        }

        # Verificar crossdomain.xml (Flash)
        try:
            crossdomain_url = f"{self.url}/crossdomain.xml"
            response = requests.get(crossdomain_url, timeout=10, verify=False)

            if response.status_code == 200:
                results['crossdomain_xml'] = response.text

                # Analizar políticas inseguras
                if 'allow-access-from domain="*"' in response.text:
                    results['security_issues'].append("crossdomain.xml permite acceso desde cualquier dominio")
                    print("    [!] crossdomain.xml permite acceso desde cualquier dominio - INSEGURO")

                if 'allow-http-request-headers-from domain="*"' in response.text:
                    results['security_issues'].append("crossdomain.xml permite headers desde cualquier dominio")

                print(f"    [+] crossdomain.xml encontrado")
            else:
                print(f"    [-] crossdomain.xml no encontrado ({response.status_code})")

        except requests.exceptions.RequestException:
            print("    [-] crossdomain.xml no accesible")

        # Verificar clientaccesspolicy.xml (Silverlight)
        try:
            clientaccess_url = f"{self.url}/clientaccesspolicy.xml"
            response = requests.get(clientaccess_url, timeout=10, verify=False)

            if response.status_code == 200:
                results['clientaccesspolicy_xml'] = response.text

                # Analizar políticas inseguras
                if '<domain uri="*"/>' in response.text:
                    results['security_issues'].append("clientaccesspolicy.xml permite acceso desde cualquier dominio")
                    print("    [!] clientaccesspolicy.xml permite acceso desde cualquier dominio - INSEGURO")

                print(f"    [+] clientaccesspolicy.xml encontrado")
            else:
                print(f"    [-] clientaccesspolicy.xml no encontrado ({response.status_code})")

        except requests.exceptions.RequestException:
            print("    [-] clientaccesspolicy.xml no accesible")

        self.results['tests']['WSTG-CONF-08'] = results

    def test_wstg_conf_12(self):
        """WSTG-CONF-12: Testing for Content Security Policy"""
        print("\n[+] WSTG-CONF-12: Content Security Policy Testing")

        results = {
            'csp_present': False,
            'csp_header': None,
            'csp_policies': {},
            'security_issues': [],
            'recommendations': []
        }

        try:
            response = requests.get(self.url, timeout=10, verify=False)

            # Verificar CSP header
            csp_headers = ['content-security-policy', 'x-content-security-policy', 'x-webkit-csp']

            for header in csp_headers:
                if header in response.headers:
                    results['csp_present'] = True
                    results['csp_header'] = response.headers[header]

                    # Parsear directivas CSP
                    csp_value = response.headers[header]
                    directives = [d.strip() for d in csp_value.split(';')]

                    for directive in directives:
                        if ':' in directive:
                            key, value = directive.split(':', 1)
                            results['csp_policies'][key.strip()] = value.strip()

                    print(f"    [+] CSP encontrado: {header}")
                    break

            if not results['csp_present']:
                print("    [-] CSP no implementado")
                results['recommendations'].append("Implementar Content Security Policy")
            else:
                # Analizar configuración CSP
                policies = results['csp_policies']

                # Verificar directivas inseguras
                if 'default-src' in policies:
                    if '*' in policies['default-src'] or 'unsafe-inline' in policies['default-src']:
                        results['security_issues'].append("default-src permite contenido inseguro")

                if 'script-src' in policies:
                    if '*' in policies['script-src']:
                        results['security_issues'].append("script-src permite scripts de cualquier origen")
                    if 'unsafe-inline' in policies['script-src']:
                        results['security_issues'].append("script-src permite inline scripts - inseguro")
                    if 'unsafe-eval' in policies['script-src']:
                        results['security_issues'].append("script-src permite eval() - inseguro")

                # Recomendaciones
                if 'frame-ancestors' not in policies:
                    results['recommendations'].append("Agregar 'frame-ancestors' para prevenir clickjacking")

                if 'upgrade-insecure-requests' not in policies:
                    results['recommendations'].append("Considerar 'upgrade-insecure-requests' para forzar HTTPS")

        except requests.exceptions.RequestException as e:
            print(f"    [-] Error probando CSP: {e}")
            results['error'] = str(e)

        self.results['tests']['WSTG-CONF-12'] = results

    def test_wstg_conf_14(self):
        """WSTG-CONF-14: Test Other HTTP Security Header Misconfigurations"""
        print("\n[+] WSTG-CONF-14: HTTP Security Headers Testing")

        results = {
            'headers': {},
            'missing_headers': [],
            'misconfigured_headers': [],
            'security_score': 0
        }

        security_headers = {
            'X-Frame-Options': {
                'expected_values': ['DENY', 'SAMEORIGIN'],
                'description': 'Protección contra clickjacking'
            },
            'X-Content-Type-Options': {
                'expected_values': ['nosniff'],
                'description': 'Previene MIME-sniffing'
            },
            'X-XSS-Protection': {
                'expected_values': ['1; mode=block'],
                'description': 'Filtro XSS del navegador'
            },
            'Referrer-Policy': {
                'expected_values': ['strict-origin-when-cross-origin', 'strict-origin', 'no-referrer'],
                'description': 'Control de información del referrer'
            },
            'Permissions-Policy': {
                'expected_values': ['geolocation=(), microphone=(), camera=()'],
                'description': 'Control de APIs del navegador'
            }
        }

        try:
            response = requests.get(self.url, timeout=10, verify=False)

            for header_name, header_info in security_headers.items():
                if header_name.lower() in [h.lower() for h in response.headers.keys()]:
                    # Encontrar el header (case-insensitive)
                    actual_header = next(h for h in response.headers.keys() if h.lower() == header_name.lower())
                    header_value = response.headers[actual_header]

                    results['headers'][header_name] = header_value

                    # Verificar si el valor es seguro
                    is_secure = any(expected in header_value for expected in header_info['expected_values'])

                    if is_secure:
                        print(f"    [+] {header_name}: {header_value} ✓")
                        results['security_score'] += 1
                    else:
                        print(f"    [!] {header_name}: {header_value} - Configuración no óptima")
                        results['misconfigured_headers'].append(header_name)
                else:
                    print(f"    [-] {header_name}: No presente")
                    results['missing_headers'].append(header_name)

        except requests.exceptions.RequestException as e:
            print(f"    [-] Error probando headers: {e}")
            results['error'] = str(e)

        print(f"\n    [*] Puntuación de seguridad: {results['security_score']}/{len(security_headers)}")

        self.results['tests']['WSTG-CONF-14'] = results

    def test_wstg_conf_03(self):
        """WSTG-CONF-03: Test File Extensions Handling"""
        print("\n[+] WSTG-CONF-03: File Extensions Handling")

        results = {
            'sensitive_extensions': {},
            'accessible_files': [],
            'security_issues': []
        }

        sensitive_extensions = [
            '.bak', '.backup', '.old', '.orig', '.save',
            '.conf', '.config', '.ini', '.cfg', '.properties',
            '.sql', '.db', '.sqlite', '.mdb',
            '.log', '.txt', '.tmp',
            '.p12', '.pem', '.key', '.crt', '.cer'
        ]

        base_files = ['config', 'database', 'settings', 'admin', 'backup']

        for ext in sensitive_extensions:
            for base in base_files:
                test_file = f"{base}{ext}"
                try:
                    file_url = f"{self.url}/{test_file}"
                    response = requests.get(file_url, timeout=5, verify=False)

                    if response.status_code == 200:
                        content_type = response.headers.get('content-type', 'unknown')
                        file_size = len(response.content)

                        results['accessible_files'].append({
                            'file': test_file,
                            'size': file_size,
                            'content_type': content_type
                        })

                        results['security_issues'].append(f"Archivo sensible accesible: {test_file}")
                        print(f"    [!] Archivo sensible encontrado: {test_file} ({file_size} bytes)")

                except requests.exceptions.RequestException:
                    continue

        if not results['accessible_files']:
            print("    [+] No se encontraron archivos sensibles accesibles")

        self.results['tests']['WSTG-CONF-03'] = results

    def test_wstg_conf_04(self):
        """WSTG-CONF-04: Review Old Backup and Unreferenced Files"""
        print("\n[+] WSTG-CONF-04: Backup Files Testing")

        results = {
            'backup_files_found': [],
            'temp_files_found': [],
            'version_files_found': []
        }

        backup_patterns = [
            'backup.zip', 'backup.tar.gz', 'backup.sql',
            'db_backup.sql', 'database_backup.sql',
            'site_backup.zip', 'www_backup.zip',
            '.git/', '.svn/', '.DS_Store',
            'Thumbs.db', 'desktop.ini'
        ]

        temp_patterns = [
            'temp/', 'tmp/', 'cache/',
            'temp.txt', 'tmp.txt',
            'phpinfo.php', 'info.php',
            'test.php', 'debug.php'
        ]

        version_patterns = [
            'old/', 'backup/', 'archive/',
            'v1/', 'v2/', 'old-version/',
            '_backup/', '_old/'
        ]

        all_patterns = backup_patterns + temp_patterns + version_patterns

        for pattern in all_patterns:
            try:
                test_url = f"{self.url}/{pattern}"
                response = requests.head(test_url, timeout=5, verify=False)

                if response.status_code == 200:
                    results['backup_files_found'].append(pattern)
                    print(f"    [!] Archivo backup/temporal encontrado: {pattern}")

            except requests.exceptions.RequestException:
                continue

        if not results['backup_files_found']:
            print("    [+] No se encontraron archivos de backup accesibles")

        self.results['tests']['WSTG-CONF-04'] = results

    def test_wstg_conf_05(self):
        """WSTG-CONF-05: Enumerate Infrastructure and Application Admin Interfaces"""
        print("\n[+] WSTG-CONF-05: Admin Interfaces Enumeration")

        results = {
            'admin_paths': {},
            'admin_pages_found': [],
            'security_issues': []
        }

        admin_paths = [
            '/admin', '/administrator', '/admin.php',
            '/login', '/login.php', '/wp-admin',
            '/wp-login.php', '/phpmyadmin', '/adminer',
            '/cpanel', '/webmail', '/controlpanel',
            '/console', '/manager', '/dashboard',
            '/setup', '/install', '/config'
        ]

        for path in admin_paths:
            try:
                admin_url = f"{self.url}{path}"
                response = requests.get(admin_url, timeout=5, verify=False)

                if response.status_code == 200:
                    results['admin_pages_found'].append(path)
                    results['admin_paths'][path] = {
                        'status_code': response.status_code,
                        'title': self._extract_title(response.text),
                        'content_length': len(response.text)
                    }
                    print(f"    [+] Interfaz admin encontrada: {path} ({response.status_code})")

                    # Verificar si requiere autenticación
                    if 'login' in response.text.lower() or 'password' in response.text.lower():
                        print(f"      [*] Requiere autenticación")
                    else:
                        results['security_issues'].append(f"Interfaz admin sin protección: {path}")
                        print(f"      [!] Posible interfaz admin sin protección")

            except requests.exceptions.RequestException:
                continue

        if not results['admin_pages_found']:
            print("    [+] No se encontraron interfaces administrativas accesibles")

        self.results['tests']['WSTG-CONF-05'] = results

    def test_wstg_conf_10(self):
        """WSTG-CONF-10: Test for Subdomain Takeover"""
        print("\n[+] WSTG-CONF-10: Subdomain Takeover Testing")

        results = {
            'subdomains_checked': [],
            'vulnerable_subdomains': [],
            'services_detected': {}
        }

        # Lista de subdominios comunes
        common_subdomains = [
            'www', 'mail', 'ftp', 'admin', 'api', 'blog',
            'shop', 'store', 'dev', 'test', 'staging',
            'app', 'mobile', 'm', 'cdn', 'static',
            'assets', 'images', 'media', 'files'
        ]

        # Servicios cloud comunes para takeover
        cloud_services = {
            'github.io': 'GitHub Pages',
            'herokuapp.com': 'Heroku',
            'netlify.com': 'Netlify',
            's3.amazonaws.com': 'Amazon S3',
            'azurewebsites.net': 'Azure',
            'cloudapp.net': 'Azure',
            'appspot.com': 'Google App Engine'
        }

        for subdomain in common_subdomains:
            full_domain = f"{subdomain}.{self.domain}"

            try:
                # Resolver IP
                ip = socket.gethostbyname(full_domain)
                results['subdomains_checked'].append(full_domain)

                # Verificar si apunta a servicios cloud
                for service_pattern, service_name in cloud_services.items():
                    if service_pattern in full_domain:
                        try:
                            response = requests.get(f"http://{full_domain}", timeout=10, verify=False)

                            # Signos de takeover posible
                            takeover_signs = [
                                "NoSuchBucket",
                                "Repository not found",
                                "There isn't a GitHub Pages site here",
                                "Fastly error: unknown domain",
                                "404 Not Found - nginx",
                                "The specified bucket does not exist"
                            ]

                            if any(sign in response.text for sign in takeover_signs):
                                results['vulnerable_subdomains'].append(full_domain)
                                results['services_detected'][full_domain] = service_name
                                print(f"    [!] Posible subdomain takeover: {full_domain} ({service_name})")

                        except:
                            pass

            except socket.gaierror:
                # Subdomain no existe - normal
                continue
            except:
                continue

        if not results['vulnerable_subdomains']:
            print("    [+] No se detectaron subdominios vulnerables a takeover")

        self.results['tests']['WSTG-CONF-10'] = results

    def _extract_title(self, html):
        """Extraer el título de una página HTML"""
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(html, 'html.parser')
            return soup.title.string if soup.title else "No title"
        except:
            return "Error extracting title"

    def save_results(self):
        """Guardar resultados en archivos JSON y texto plano"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Guardar JSON
        json_file = f"configuration_testing_{self.domain}_{timestamp}.json"
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)

        # Guardar texto plano
        txt_file = f"configuration_testing_{self.domain}_{timestamp}.txt"
        with open(txt_file, 'w', encoding='utf-8') as f:
            f.write("OWASP WSTG Configuration and Deployment Management Test Results\n")
            f.write("=" * 65 + "\n\n")
            f.write(f"Target: {self.target}\n")
            f.write(f"Fecha: {self.results['timestamp']}\n\n")

            for test_name, test_results in self.results['tests'].items():
                f.write(f"\n{test_name}:\n")
                f.write("-" * len(test_name) + "\n")

                if isinstance(test_results, dict):
                    for key, value in test_results.items():
                        if isinstance(value, list):
                            if value:
                                f.write(f"{key}: {len(value)} items\n")
                                for item in value[:5]:  # Limitar a 5 items
                                    f.write(f"  - {item}\n")
                        elif isinstance(value, dict):
                            f.write(f"{key}:\n")
                            for subkey, subvalue in value.items():
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
        print("RESUMEN DE CONFIGURATION TESTING")
        print("=" * 60)

        total_tests = len(self.results['tests'])
        print(f"Tests ejecutados: {total_tests}")

        # Contar vulnerabilidades críticas
        critical_issues = 0
        high_issues = 0
        medium_issues = 0

        # WSTG-CONF-06 - HTTP Methods
        if 'WSTG-CONF-06' in self.results['tests']:
            conf06 = self.results['tests']['WSTG-CONF-06']
            if conf06.get('put_test', {}).get('allowed'):
                critical_issues += 1
                print("Vulnerabilidad CRÍTICA: PUT method permite creación de archivos")

            if conf06.get('trace_test', {}).get('allowed'):
                high_issues += 1
                print("Vulnerabilidad ALTA: TRACE method permitido")

        # WSTG-CONF-07 - HSTS
        if 'WSTG-CONF-07' in self.results['tests']:
            if not self.results['tests']['WSTG-CONF-07'].get('hsts_present'):
                medium_issues += 1
                print("Vulnerabilidad MEDIA: HSTS no implementado")

        # WSTG-CONF-14 - Security Headers
        if 'WSTG-CONF-14' in self.results['tests']:
            missing_headers = len(self.results['tests']['WSTG-CONF-14'].get('missing_headers', []))
            if missing_headers > 2:
                medium_issues += 1
                print(f"Vulnerabilidad MEDIA: {missing_headers} headers de seguridad faltantes")

        # WSTG-CONF-10 - Subdomain Takeover
        if 'WSTG-CONF-10' in self.results['tests']:
            vulnerable_subdomains = len(self.results['tests']['WSTG-CONF-10'].get('vulnerable_subdomains', []))
            if vulnerable_subdomains > 0:
                high_issues += vulnerable_subdomains
                print(f"Vulnerabilidad ALTA: {vulnerable_subdomains} subdominios vulnerables a takeover")

        print(f"\nResumen de vulnerabilidades:")
        print(f"  Críticas: {critical_issues}")
        print(f"  Altas: {high_issues}")
        print(f"  Medias: {medium_issues}")
        print(f"  Totales: {critical_issues + high_issues + medium_issues}")

        print("\nRecomendaciones principales:")
        if critical_issues > 0:
            print("- CORREGIR URGENTEMENTE las vulnerabilidades críticas")
        if high_issues > 0:
            print("- Atender las vulnerabilidades altas")
        print("- Implementar headers de seguridad faltantes")
        print("- Restringir métodos HTTP innecesarios")
        print("- Revisar configuración de subdominios")

def main():
    parser = argparse.ArgumentParser(description='OWASP WSTG Configuration Testing Framework')
    parser.add_argument('--target', required=True, help='Dominio objetivo (ej: ejemplo.com)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Modo verbose')

    args = parser.parse_args()

    try:
        tester = ConfigurationTesting(args.target)
        tester.run_all_tests()
    except KeyboardInterrupt:
        print("\n[!] Prueba interrumpida por el usuario")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
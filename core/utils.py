#!/usr/bin/env python3
"""
Utilities Module for OWASP WSTG Testing Framework
Funciones utilitarias compartidas entre todos los módulos del framework
"""

import re
import socket
import dns.resolver
import subprocess
import ipaddress
from typing import List, Dict, Optional, Tuple, Any
from urllib.parse import urlparse, urljoin, parse_qs
import ssl
import OpenSSL
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

class NetworkUtils:
    """Utilidades para análisis de red"""

    @staticmethod
    def resolve_hostname(hostname: str) -> List[str]:
        """Resuelve un hostname a direcciones IP"""
        try:
            # IPv4
            ipv4_addresses = socket.gethostbyname_ex(hostname)[2]
            # IPv6
            ipv6_addresses = []
            try:
                ipv6_addresses = [addr[4][0] for addr in socket.getaddrinfo(hostname, None, socket.AF_INET6)]
            except:
                pass

            return ipv4_addresses + ipv6_addresses
        except Exception as e:
            logger.warning(f"No se pudo resolver {hostname}: {e}")
            return []

    @staticmethod
    def reverse_dns_lookup(ip: str) -> Optional[str]:
        """Realiza lookup DNS inverso"""
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname
        except:
            return None

    @staticmethod
    def get_dns_records(domain: str) -> Dict[str, List[str]]:
        """Obtiene múltiples registros DNS de un dominio"""
        records = {
            'A': [],
            'AAAA': [],
            'MX': [],
            'TXT': [],
            'NS': [],
            'CNAME': [],
            'SOA': []
        }

        for record_type in records.keys():
            try:
                answers = dns.resolver.resolve(domain, record_type)
                records[record_type] = [str(answer) for answer in answers]
                logger.debug(f"DNS {record_type} records for {domain}: {len(records[record_type])}")
            except Exception as e:
                logger.debug(f"No se pudieron obtener registros {record_type} para {domain}: {e}")

        return records

    @staticmethod
    def is_private_ip(ip: str) -> bool:
        """Verifica si una IP es privada"""
        try:
            return ipaddress.ip_address(ip).is_private
        except:
            return False

    @staticmethod
    def get_ip_info(ip: str) -> Dict[str, Any]:
        """Obtiene información detallada de una IP"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return {
                'ip': ip,
                'version': ip_obj.version,
                'is_private': ip_obj.is_private,
                'is_multicast': ip_obj.is_multicast,
                'is_reserved': ip_obj.is_reserved,
                'is_loopback': ip_obj.is_loopback,
                'packed': str(ip_obj.packed)
            }
        except Exception as e:
            logger.error(f"Error analizando IP {ip}: {e}")
            return {'ip': ip, 'error': str(e)}

class WebUtils:
    """Utilidades para análisis web"""

    @staticmethod
    def extract_domain_from_url(url: str) -> str:
        """Extrae el dominio de una URL"""
        try:
            parsed = urlparse(url)
            return parsed.netloc
        except:
            return url

    @staticmethod
    def normalize_url(url: str) -> str:
        """Normaliza una URL (agrega esquema si es necesario)"""
        if not url.startswith(('http://', 'https://')):
            return f"https://{url}"
        return url

    @staticmethod
    def extract_urls_from_text(text: str, base_url: str = None) -> List[str]:
        """Extrae URLs de texto"""
        # Patrones de URLs
        url_pattern = re.compile(
            r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        )
        urls = url_pattern.findall(text)

        # URLs relativas
        if base_url:
            rel_pattern = re.compile(r'href=["\']([^"\']+)["\']')
            rel_urls = rel_pattern.findall(text)
            for rel_url in rel_urls:
                if rel_url.startswith('/') and not rel_url.startswith('//'):
                    urls.append(urljoin(base_url, rel_url))

        return list(set(urls))  # Eliminar duplicados

    @staticmethod
    def extract_emails_from_text(text: str) -> List[str]:
        """Extrae direcciones de email de texto"""
        email_pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
        return list(set(email_pattern.findall(text)))

    @staticmethod
    def extract_phone_numbers_from_text(text: str) -> List[str]:
        """Extrae números de teléfono de texto"""
        phone_patterns = [
            r'\+?1?\d{9,15}',  # Internacional
            r'\d{3}-\d{3}-\d{4}',  # Formato US
            r'\(\d{3}\)\s*\d{3}-\d{4}',  # Formato US con paréntesis
            r'\d{10}',  # 10 dígitos
        ]

        phones = []
        for pattern in phone_patterns:
            matches = re.findall(pattern, text)
            phones.extend(matches)

        return list(set(phones))

    @staticmethod
    def parse_cookies(cookie_header: str) -> Dict[str, str]:
        """Parsea header de cookies"""
        cookies = {}
        if cookie_header:
            for cookie in cookie_header.split(';'):
                if '=' in cookie:
                    name, value = cookie.strip().split('=', 1)
                    cookies[name] = value
        return cookies

    @staticmethod
    def extract_form_data(html_content: str) -> List[Dict[str, Any]]:
        """Extrae información de formularios de HTML"""
        from bs4 import BeautifulSoup

        soup = BeautifulSoup(html_content, 'html.parser')
        forms = []

        for form in soup.find_all('form'):
            form_data = {
                'action': form.get('action', ''),
                'method': form.get('method', 'GET').upper(),
                'enctype': form.get('enctype', 'application/x-www-form-urlencoded'),
                'fields': []
            }

            for input_field in form.find_all(['input', 'select', 'textarea']):
                field_data = {
                    'name': input_field.get('name', ''),
                    'type': input_field.get('type', 'text'),
                    'value': input_field.get('value', ''),
                    'required': input_field.has_attr('required'),
                    'tag': input_field.name
                }

                if input_field.name == 'select':
                    field_data['options'] = [
                        {'value': opt.get('value', ''), 'text': opt.get_text(strip=True)}
                        for opt in input_field.find_all('option')
                    ]

                form_data['fields'].append(field_data)

            forms.append(form_data)

        return forms

class SecurityUtils:
    """Utilidades para análisis de seguridad"""

    @staticmethod
    def analyze_ssl_certificate(hostname: str, port: int = 443) -> Dict[str, Any]:
        """Analiza certificado SSL/TLS"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert(binary_form=True)
                    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert)

                    # Extraer información del certificado
                    subject = dict(x509.get_subject().get_components())
                    issuer = dict(x509.get_issuer().get_components())

                    return {
                        'version': ssock.version(),
                        'cipher': ssock.cipher(),
                        'subject': {k.decode(): v.decode() for k, v in subject.items()},
                        'issuer': {k.decode(): v.decode() for k, v in issuer.items()},
                        'serial_number': x509.get_serial_number(),
                        'not_before': datetime.strptime(x509.get_notBefore().decode('ascii'), '%Y%m%d%H%M%SZ'),
                        'not_after': datetime.strptime(x509.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ'),
                        'signature_algorithm': x509.get_signature_algorithm().decode('ascii'),
                        'extensions': [
                            {
                                'name': ext.get_short_name().decode(),
                                'critical': ext.get_critical(),
                                'value': str(ext.get_data())
                            }
                            for ext in x509.get_extension_count() and [
                                x509.get_extension(i) for i in range(x509.get_extension_count())
                            ] or []
                        ]
                    }
        except Exception as e:
            logger.error(f"Error analizando certificado SSL para {hostname}: {e}")
            return {'error': str(e)}

    @staticmethod
    def check_password_strength(password: str) -> Dict[str, Any]:
        """Evalúa la fuerza de una contraseña"""
        result = {
            'length': len(password),
            'has_lowercase': bool(re.search(r'[a-z]', password)),
            'has_uppercase': bool(re.search(r'[A-Z]', password)),
            'has_digits': bool(re.search(r'\d', password)),
            'has_special': bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password)),
            'score': 0,
            'strength': 'very_weak'
        }

        # Calcular score
        if result['length'] >= 8:
            result['score'] += 1
        if result['length'] >= 12:
            result['score'] += 1
        if result['has_lowercase']:
            result['score'] += 1
        if result['has_uppercase']:
            result['score'] += 1
        if result['has_digits']:
            result['score'] += 1
        if result['has_special']:
            result['score'] += 1

        # Determinar fuerza
        if result['score'] <= 2:
            result['strength'] = 'very_weak'
        elif result['score'] <= 4:
            result['strength'] = 'weak'
        elif result['score'] == 5:
            result['strength'] = 'medium'
        elif result['score'] == 6:
            result['strength'] = 'strong'
        else:
            result['strength'] = 'very_strong'

        return result

    @staticmethod
    def check_xss_payloads(text: str) -> List[Dict[str, str]]:
        """Busca payloads XSS en texto"""
        xss_patterns = [
            {'pattern': r'<script[^>]*>', 'type': 'script_tag'},
            {'pattern': r'javascript:', 'type': 'javascript_protocol'},
            {'pattern': r'on\w+\s*=', 'type': 'event_handler'},
            {'pattern': r'<iframe[^>]*>', 'type': 'iframe'},
            {'pattern': r'<object[^>]*>', 'type': 'object'},
            {'pattern': r'<embed[^>]*>', 'type': 'embed'},
            {'pattern': r'eval\s*\(', 'type': 'eval_function'},
            {'pattern': r'document\.cookie', 'type': 'cookie_access'},
        ]

        findings = []
        for pattern_info in xss_patterns:
            matches = re.finditer(pattern_info['pattern'], text, re.IGNORECASE)
            for match in matches:
                findings.append({
                    'type': pattern_info['type'],
                    'payload': match.group(),
                    'position': match.span()
                })

        return findings

    @staticmethod
    def check_sql_injection_payloads(text: str) -> List[Dict[str, str]]:
        """Busca payloads de SQL Injection en texto"""
        sqli_patterns = [
            {'pattern': r'(\%27)|(\')|(\-\-)|(\%23)|(#)', 'type': 'basic_injection'},
            {'pattern': r'((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))', 'type': 'union_based'},
            {'pattern': r'\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))', 'type': 'boolean_based'},
            {'pattern': r'((\%27)|(\'))union', 'type': 'union_select'},
            {'pattern': r'exec(\s|\+)+(s|x)p\w+', 'type': 'stored_procedure'},
            {'pattern': r'UNION.*SELECT', 'type': 'union_select_explicit'},
            {'pattern': r'INSERT.*INTO', 'type': 'insert_statement'},
            {'pattern': r'DELETE.*FROM', 'type': 'delete_statement'},
            {'pattern': r'DROP.*TABLE', 'type': 'drop_statement'},
        ]

        findings = []
        for pattern_info in sqli_patterns:
            matches = re.finditer(pattern_info['pattern'], text, re.IGNORECASE)
            for match in matches:
                findings.append({
                    'type': pattern_info['type'],
                    'payload': match.group(),
                    'position': match.span()
                })

        return findings

class FileUtils:
    """Utilidades para manejo de archivos"""

    @staticmethod
    def is_backup_file(filename: str) -> bool:
        """Verifica si un filename parece ser un backup"""
        backup_extensions = [
            '.bak', '.backup', '.old', '.orig', '.save',
            '.tmp', '.temp', '.copy', '.prev'
        ]

        filename_lower = filename.lower()
        return (
            any(filename_lower.endswith(ext) for ext in backup_extensions) or
            any(pattern in filename_lower for pattern in ['backup', 'old', 'temp', 'tmp'])
        )

    @staticmethod
    def is_config_file(filename: str) -> bool:
        """Verifica si un filename parece ser un archivo de configuración"""
        config_extensions = [
            '.conf', '.config', '.ini', '.cfg', '.properties',
            '.yml', '.yaml', '.json', '.xml', '.env'
        ]

        config_names = [
            'config', 'configuration', 'settings', 'options',
            'database', 'db', 'auth', 'security'
        ]

        filename_lower = filename.lower()
        return (
            any(filename_lower.endswith(ext) for ext in config_extensions) or
            any(name in filename_lower for name in config_names)
        )

    @staticmethod
    def get_file_type_info(filename: str) -> Dict[str, Any]:
        """Obtiene información básica sobre un tipo de archivo"""
        extension = filename.lower().split('.')[-1] if '.' in filename else ''

        file_types = {
            # Documentos
            'pdf': {'type': 'document', 'category': 'portable_document'},
            'doc': {'type': 'document', 'category': 'microsoft_word'},
            'docx': {'type': 'document', 'category': 'microsoft_word'},
            'xls': {'type': 'document', 'category': 'microsoft_excel'},
            'xlsx': {'type': 'document', 'category': 'microsoft_excel'},
            'txt': {'type': 'document', 'category': 'text'},

            # Configuración
            'conf': {'type': 'config', 'category': 'configuration'},
            'config': {'type': 'config', 'category': 'configuration'},
            'ini': {'type': 'config', 'category': 'configuration'},
            'cfg': {'type': 'config', 'category': 'configuration'},
            'env': {'type': 'config', 'category': 'environment'},

            # Código/Base de datos
            'sql': {'type': 'database', 'category': 'sql_script'},
            'db': {'type': 'database', 'category': 'database_file'},
            'sqlite': {'type': 'database', 'category': 'sqlite_database'},

            # Backup
            'bak': {'type': 'backup', 'category': 'backup_file'},
            'backup': {'type': 'backup', 'category': 'backup_file'},
            'old': {'type': 'backup', 'category': 'backup_file'},

            # Web
            'html': {'type': 'web', 'category': 'html'},
            'htm': {'type': 'web', 'category': 'html'},
            'js': {'type': 'web', 'category': 'javascript'},
            'css': {'type': 'web', 'category': 'stylesheet'},
            'php': {'type': 'web', 'category': 'php_script'},
        }

        file_info = file_types.get(extension, {'type': 'unknown', 'category': 'unknown'})
        file_info['extension'] = extension
        file_info['is_backup'] = FileUtils.is_backup_file(filename)
        file_info['is_config'] = FileUtils.is_config_file(filename)

        return file_info

class DataUtils:
    """Utilidades para procesamiento de datos"""

    @staticmethod
    def merge_dictionaries(dict1: Dict, dict2: Dict) -> Dict:
        """Fusiona dos diccionarios recursivamente"""
        result = dict1.copy()
        for key, value in dict2.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = DataUtils.merge_dictionaries(result[key], value)
            else:
                result[key] = value
        return result

    @staticmethod
    def filter_dict_by_keys(dictionary: Dict, keys: List[str]) -> Dict:
        """Filtra un diccionario solo con las keys especificadas"""
        return {key: dictionary[key] for key in keys if key in dictionary}

    @staticmethod
    def remove_duplicates_from_list(lst: List) -> List:
        """Elimina duplicados de una lista manteniendo el orden"""
        seen = set()
        result = []
        for item in lst:
            if item not in seen:
                seen.add(item)
                result.append(item)
        return result

    @staticmethod
    def safe_int_conversion(value: Any, default: int = 0) -> int:
        """Conversión segura a entero"""
        try:
            return int(value)
        except (ValueError, TypeError):
            return default

    @staticmethod
    def safe_float_conversion(value: Any, default: float = 0.0) -> float:
        """Conversión segura a float"""
        try:
            return float(value)
        except (ValueError, TypeError):
            return default

class CommandUtils:
    """Utilidades para ejecución de comandos externos"""

    @staticmethod
    def run_command(command: str, timeout: int = 30, capture_output: bool = True) -> Dict[str, Any]:
        """
        Ejecuta un comando externo de forma segura

        Args:
            command: Comando a ejecutar
            timeout: Tiempo máximo de ejecución
            capture_output: Si se debe capturar la salida

        Returns:
            Dict con el resultado
        """
        try:
            result = subprocess.run(
                command,
                shell=True,
                timeout=timeout,
                capture_output=capture_output,
                text=True,
                check=False
            )

            return {
                'success': result.returncode == 0,
                'return_code': result.returncode,
                'stdout': result.stdout if capture_output else '',
                'stderr': result.stderr if capture_output else '',
                'command': command
            }
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'error': 'Command timeout',
                'command': command
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'command': command
            }

# Funciones de conveniencia
def extract_tech_from_headers(headers: Dict[str, str]) -> List[str]:
    """Extrae tecnología de headers HTTP"""
    technologies = []

    tech_indicators = {
        'server': ['apache', 'nginx', 'iis', 'litespeed', 'caddy'],
        'x-powered-by': ['php', 'asp.net', 'express', 'python', 'ruby', 'java'],
        'x-generator': ['wordpress', 'drupal', 'joomla', 'ghost'],
        'x-aspnet-version': ['asp.net'],
        'x-drupal-cache': ['drupal'],
    }

    for header, value in headers.items():
        header_lower = header.lower()
        value_lower = value.lower()

        if header_lower in tech_indicators:
            for tech in tech_indicators[header_lower]:
                if tech in value_lower:
                    technologies.append(tech)

    return list(set(technologies))

def calculate_cvss_score(attack_vector: str = 'N', attack_complexity: str = 'L',
                        privileges_required: str = 'N', user_interaction: str = 'N',
                        scope: str = 'U', confidentiality: str = 'N',
                        integrity: str = 'N', availability: str = 'N') -> float:
    """
    Calcula score CVSS básico (simplificado)

    Args:
        Parámetros del vector CVSS

    Returns:
        Score CVSS base (0-10)
    """
    # Mapeo de valores a scores (simplificado)
    av_scores = {'N': 0.85, 'A': 0.62, 'L': 0.55, 'P': 0.2}
    ac_scores = {'L': 0.77, 'H': 0.44}
    pr_scores = {'N': 0.85, 'L': 0.62, 'H': 0.27}
    ui_scores = {'N': 0.85, 'R': 0.62}

    cia_scores = {'H': 0.56, 'L': 0.22, 'N': 0.0}

    try:
        # Cálculo básico CVSS
        exploitability = 8.22 * av_scores[attack_vector] * ac_scores[attack_complexity] * \
                        pr_scores[privileges_required] * ui_scores[user_interaction]

        impact = 1 - (1 - cia_scores[confidentiality]) * \
                 (1 - cia_scores[integrity]) * (1 - cia_scores[availability])

        if impact <= 0:
            return 0.0

        if scope == 'C':
            impact = 7.52 * (impact - 0.029) - 3.25 * (impact - 0.02)**15
            base_score = min(10, impact + exploitability)
        else:
            impact = 6.42 * impact
            base_score = min(10, impact + exploitability)

        return round(base_score, 1)
    except KeyError:
        return 5.0  # Default medium score
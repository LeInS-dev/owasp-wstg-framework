#!/usr/bin/env python3
"""
Kali Linux Tools Integration Module
Integración con herramientas específicas de Kali Linux para testing de seguridad

Este módulo proporciona wrappers y utilidades para integrar herramientas
de Kali Linux con el framework OWASP WSTG.
"""

import subprocess
import json
import os
import re
import time
import logging
from typing import Dict, List, Any, Optional, Union
from pathlib import Path
import xml.etree.ElementTree as ET

logger = logging.getLogger(__name__)

class KaliToolsIntegration:
    """
    Clase principal para integración con herramientas de Kali Linux
    """

    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.tool_paths = self._detect_tool_paths()
        self.output_dir = self.config.get('output_dir', './kali_outputs')

        # Crear directorio de salida
        Path(self.output_dir).mkdir(parents=True, exist_ok=True)

    def _detect_tool_paths(self) -> Dict[str, str]:
        """Detecta rutas de herramientas de Kali Linux"""
        common_tools = {
            'nmap': '/usr/bin/nmap',
            'nikto': '/usr/bin/nikto',
            'hydra': '/usr/bin/hydra',
            'dirb': '/usr/bin/dirb',
            'gobuster': '/usr/bin/gobuster',
            'sqlmap': '/usr/bin/sqlmap',
            'wpscan': '/usr/bin/wpscan',
            'burpsuite': '/usr/bin/burpsuite',
            'john': '/usr/bin/john',
            'hashcat': '/usr/bin/hashcat',
            'metasploit': '/usr/bin/msfconsole',
            'zap': '/usr/bin/zaproxy',
            'dirsearch': '/usr/bin/dirsearch',
            'feroxbuster': '/usr/bin/feroxbuster',
            'ffuf': '/usr/bin/ffuf',
            'wfuzz': '/usr/bin/wfuzz',
            'curl': '/usr/bin/curl',
            'wget': '/usr/bin/wget',
            'python': '/usr/bin/python3'
        }

        detected_paths = {}
        for tool, default_path in common_tools.items():
            if os.path.exists(default_path):
                detected_paths[tool] = default_path
            else:
                # Buscar en PATH
                result = self._run_command(['which', tool], capture_output=True)
                if result['success']:
                    detected_paths[tool] = result['stdout'].strip()

        logger.info(f"Herramientas detectadas: {list(detected_paths.keys())}")
        return detected_paths

    def _run_command(self, command: List[str], timeout: int = 300,
                    capture_output: bool = True, cwd: str = None) -> Dict[str, Any]:
        """
        Ejecuta un comando de forma segura con manejo de errores

        Args:
            command: Comando a ejecutar como lista
            timeout: Tiempo máximo de ejecución
            capture_output: Si capturar la salida
            cwd: Directorio de trabajo

        Returns:
            Diccionario con resultado
        """
        try:
            result = subprocess.run(
                command,
                timeout=timeout,
                capture_output=capture_output,
                text=True,
                cwd=cwd,
                check=False
            )

            return {
                'success': result.returncode == 0,
                'return_code': result.returncode,
                'stdout': result.stdout if capture_output else '',
                'stderr': result.stderr if capture_output else '',
                'command': ' '.join(command)
            }
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'error': 'Command timeout',
                'command': ' '.join(command)
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'command': ' '.join(command)
            }

class NmapScanner(KaliToolsIntegration):
    """Wrapper para Nmap - escaneo de puertos y detección de servicios"""

    def scan_ports(self, target: str, ports: str = None,
                  scan_type: str = '-sS', output_format: str = 'json') -> Dict[str, Any]:
        """
        Realiza escaneo de puertos con Nmap

        Args:
            target: Target a escanear
            ports: Puertos (ej: "1-1000", "80,443,8080")
            scan_type: Tipo de escaneo (-sS, -sT, -sV, -O, -A)
            output_format: Formato de salida (json, xml, normal)

        Returns:
            Resultados del escaneo
        """
        if 'nmap' not in self.tool_paths:
            logger.error("Nmap no encontrado")
            return {'error': 'Nmap not available'}

        # Construir comando
        command = [self.tool_paths['nmap']]

        # Agregar tipo de escaneo
        command.append(scan_type)

        # Agregar opciones de rendimiento
        command.extend(['-T4', '--max-retries', '2'])

        # Agregar formato de salida
        if output_format == 'json':
            output_file = f"{self.output_dir}/nmap_{target.replace('.', '_')}.json"
            command.extend(['-oX', output_file])
        elif output_format == 'xml':
            output_file = f"{self.output_dir}/nmap_{target.replace('.', '_')}.xml"
            command.extend(['-oX', output_file])

        # Agregar puertos si se especifican
        if ports:
            command.extend(['-p', ports])

        # Agregar target
        command.append(target)

        logger.info(f"Ejecutando Nmap: {' '.join(command)}")
        result = self._run_command(command, timeout=600)

        if result['success'] and output_format in ['json', 'xml'] and os.path.exists(output_file):
            # Parsear resultados
            if output_format == 'xml':
                result['parsed'] = self._parse_nmap_xml(output_file)

        return result

    def _parse_nmap_xml(self, xml_file: str) -> Dict[str, Any]:
        """Parsea archivo XML de Nmap"""
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()

            parsed = {
                'scan_info': {},
                'hosts': [],
                'services': []
            }

            # Información del escaneo
            scan_info = root.find('.//scaninfo')
            if scan_info is not None:
                parsed['scan_info'] = scan_info.attrib

            # Hosts y servicios
            for host in root.findall('.//host'):
                host_info = {
                    'status': None,
                    'address': None,
                    'hostnames': [],
                    'ports': []
                }

                # Estado del host
                status = host.find('.//status')
                if status is not None:
                    host_info['status'] = status.attrib

                # Dirección IP
                address = host.find('.//address[@addrtype="ipv4"]')
                if address is not None:
                    host_info['address'] = address.attrib

                # Hostnames
                for hostname in host.findall('.//hostname'):
                    host_info['hostnames'].append(hostname.attrib)

                # Puertos y servicios
                for port in host.findall('.//port'):
                    port_info = {
                        'port_id': port.get('portid'),
                        'protocol': port.get('protocol'),
                        'state': None,
                        'service': None
                    }

                    state = port.find('.//state')
                    if state is not None:
                        port_info['state'] = state.attrib

                    service = port.find('.//service')
                    if service is not None:
                        port_info['service'] = service.attrib

                    host_info['ports'].append(port_info)

                parsed['hosts'].append(host_info)

            return parsed
        except Exception as e:
            logger.error(f"Error parseando Nmap XML: {e}")
            return {'error': str(e)}

class WebScanner(KaliToolsIntegration):
    """Wrapper para herramientas de web scanning"""

    def nikto_scan(self, target: str, ports: str = '80,443') -> Dict[str, Any]:
        """
        Realiza escaneo con Nikto

        Args:
            target: Target a escanear
            ports: Puertos a escanear

        Returns:
            Resultados del escaneo
        """
        if 'nikto' not in self.tool_paths:
            logger.error("Nikto no encontrado")
            return {'error': 'Nikto not available'}

        output_file = f"{self.output_dir}/nikto_{target.replace('.', '_')}.xml"

        command = [
            self.tool_paths['nikto'],
            '-h', target,
            '-p', ports,
            '-o', output_file,
            '-Format', 'xml',
            '-Tuning', '9'  # Testar todo
        ]

        logger.info(f"Ejecutando Nikto: {' '.join(command)}")
        result = self._run_command(command, timeout=600)

        if result['success'] and os.path.exists(output_file):
            result['parsed'] = self._parse_nikto_xml(output_file)

        return result

    def _parse_nikto_xml(self, xml_file: str) -> Dict[str, Any]:
        """Parsea archivo XML de Nikto"""
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()

            parsed = {
                'scan_info': {},
                'vulnerabilities': []
            }

            # Información del escaneo
            parsed['scan_info'] = root.attrib

            # Vulnerabilidades encontradas
            for item in root.findall('.//item'):
                vuln = {
                    'id': item.get('id', ''),
                    'osvdb': item.get('osvdb', ''),
                    'method': item.text or '',
                    'name': item.get('name', ''),
                    'reference': item.get('reference', '')
                }
                parsed['vulnerabilities'].append(vuln)

            return parsed
        except Exception as e:
            logger.error(f"Error parseando Nikto XML: {e}")
            return {'error': str(e)}

    def gobuster_scan(self, target: str, wordlist: str = None,
                     extensions: str = 'php,asp,aspx,jsp,html,htm') -> Dict[str, Any]:
        """
        Realiza escaneo de directorios con Gobuster

        Args:
            target: Target a escanear (incluyendo protocolo)
            wordlist: Wordlist personalizada
            extensions: Extensiones a probar

        Returns:
            Resultados del escaneo
        """
        if 'gobuster' not in self.tool_paths:
            logger.error("Gobuster no encontrado")
            return {'error': 'Gobuster not available'}

        output_file = f"{self.output_dir}/gobuster_{target.replace('://', '_').replace('.', '_')}.json"

        # Wordlist por defecto
        if not wordlist:
            common_wordlists = [
                '/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt',
                '/usr/share/wordlists/dirb/common.txt',
                '/usr/share/wordlists/wfuzz/general/common.txt'
            ]
            wordlist = next((wl for wl in common_wordlists if os.path.exists(wl)), None)

        if not wordlist:
            return {'error': 'No wordlist found'}

        command = [
            self.tool_paths['gobuster'],
            'dir',
            '-u', target,
            '-w', wordlist,
            '-x', extensions,
            '-o', output_file,
            '-j',  # Concurrent requests
            '-q',  # Quiet mode
            '-k',  # Skip SSL verification
            '-t', '50'  # Threads
        ]

        logger.info(f"Ejecutando Gobuster: {' '.join(command)}")
        result = self._run_command(command, timeout=300)

        if result['success'] and os.path.exists(output_file):
            result['parsed'] = self._parse_gobuster_json(output_file)

        return result

    def _parse_gobuster_json(self, json_file: str) -> Dict[str, Any]:
        """Parsea archivo JSON de Gobuster"""
        try:
            with open(json_file, 'r') as f:
                data = json.load(f)

            return {
                'directories': data.get('result', []),
                'total_found': len(data.get('result', []))
            }
        except Exception as e:
            logger.error(f"Error parseando Gobuster JSON: {e}")
            return {'error': str(e)}

class BruteForceTools(KaliToolsIntegration):
    """Wrapper para herramientas de fuerza bruta"""

    def hydra_ssh(self, target: str, user: str = None, users_file: str = None,
                 password: str = None, passwords_file: str = None,
                 port: int = 22) -> Dict[str, Any]:
        """
        Realiza ataque de fuerza bruta a SSH con Hydra

        Args:
            target: Target a atacar
            user: Usuario específico
            users_file: Archivo de usuarios
            password: Contraseña específica
            passwords_file: Archivo de contraseñas
            port: Puerto SSH

        Returns:
            Resultados del ataque
        """
        if 'hydra' not in self.tool_paths:
            logger.error("Hydra no encontrado")
            return {'error': 'Hydra not available'}

        command = [
            self.tool_paths['hydra'],
            '-V',  # Verbose
            '-f',  # Exit when found
            '-o', f"{self.output_dir}/hydra_ssh_{target}.txt"
        ]

        # Configurar usuarios
        if user:
            command.extend(['-l', user])
        elif users_file:
            command.extend(['-L', users_file])
        else:
            return {'error': 'User or users file required'}

        # Configurar contraseñas
        if password:
            command.extend(['-p', password])
        elif passwords_file:
            command.extend(['-P', passwords_file])
        else:
            return {'error': 'Password or passwords file required'}

        # Configurar servicio y target
        command.extend(['-s', str(port), 'ssh://' + target])

        logger.info(f"Ejecutando Hydra SSH: {' '.join(command)}")
        return self._run_command(command, timeout=3600)

    def hydra_web_form(self, target: str, form_path: str = '/login',
                      username_param: str = 'username', password_param: str = 'password',
                      failure_message: str = 'Invalid', users_file: str = None,
                      passwords_file: str = None) -> Dict[str, Any]:
        """
        Realiza ataque de fuerza bruta a formulario web con Hydra

        Args:
            target: Target a atacar (URL completa)
            form_path: Path del formulario
            username_param: Parámetro de username
            password_param: Parámetro de password
            failure_message: Mensaje de error en login fallido
            users_file: Archivo de usuarios
            passwords_file: Archivo de contraseñas

        Returns:
            Resultados del ataque
        """
        if 'hydra' not in self.tool_paths:
            logger.error("Hydra no encontrado")
            return {'error': 'Hydra not available'}

        if not users_file or not passwords_file:
            return {'error': 'Users file and passwords file required'}

        command = [
            self.tool_paths['hydra'],
            '-V',  # Verbose
            '-f',  # Exit when found
            '-o', f"{self.output_dir}/hydra_form_{target.replace('://', '_')}.txt",
            '-L', users_file,
            '-P', passwords_file,
            '-m', form_path,
            '-p', f'{username_param}=^USER^&{password_param}=^PASS^',
            '-F', failure_message,
            'http-post-form://' + target
        ]

        logger.info(f"Ejecutando Hydra Web Form: {' '.join(command)}")
        return self._run_command(command, timeout=3600)

class SQLInjectionTools(KaliToolsIntegration):
    """Wrapper para herramientas de SQL Injection"""

    def sqlmap_scan(self, target: str, data: str = None,
                   cookies: str = None, level: int = 1,
                   risk: int = 1, dbms: str = None) -> Dict[str, Any]:
        """
        Realiza escaneo con SQLMap

        Args:
            target: URL target
            data: POST data
            cookies: Cookies
            level: Level de testing (1-5)
            risk: Risk level (1-3)
            dbms: DBMS específico (mysql, postgresql, oracle, etc.)

        Returns:
            Resultados del escaneo
        """
        if 'sqlmap' not in self.tool_paths:
            logger.error("SQLMap no encontrado")
            return {'error': 'SQLMap not available'}

        output_dir = f"{self.output_dir}/sqlmap_{int(time.time())}"
        os.makedirs(output_dir, exist_ok=True)

        command = [
            self.tool_paths['sqlmap'],
            '-u', target,
            '--batch',
            '--level', str(level),
            '--risk', str(risk),
            '--output-dir', output_dir
        ]

        if data:
            command.extend(['--data', data])
        if cookies:
            command.extend(['--cookie', cookies])
        if dbms:
            command.extend(['--dbms', dbms])

        logger.info(f"Ejecutando SQLMap: {' '.join(command)}")
        result = self._run_command(command, timeout=1800)

        if result['success'] and os.path.exists(output_dir):
            result['output_dir'] = output_dir
            result['parsed'] = self._parse_sqlmap_output(output_dir)

        return result

    def _parse_sqlmap_output(self, output_dir: str) -> Dict[str, Any]:
        """Parsea salida de SQLMap"""
        try:
            log_file = os.path.join(output_dir, 'log')
            if not os.path.exists(log_file):
                return {'error': 'Log file not found'}

            with open(log_file, 'r') as f:
                log_content = f.read()

            # Buscar inyecciones encontradas
            injections = []
            if 'Parameter' in log_content and 'is vulnerable' in log_content:
                # Parseo simple de vulnerabilidades
                lines = log_content.split('\n')
                for line in lines:
                    if 'is vulnerable' in line:
                        injections.append(line.strip())

            return {
                'vulnerabilities_found': len(injections),
                'vulnerabilities': injections,
                'log_size': len(log_content)
            }
        except Exception as e:
            logger.error(f"Error parseando SQLMap output: {e}")
            return {'error': str(e)}

class WebApplicationScanner(KaliToolsIntegration):
    """Wrapper para escaneo de aplicaciones web específicas"""

    def wpscan_scan(self, target: str, enumerate_all: bool = True,
                    user_list: str = None, password_list: str = None) -> Dict[str, Any]:
        """
        Realiza escaneo con WPScan

        Args:
            target: Target WordPress
            enumerate_all: Enumerar todo
            user_list: Archivo de usuarios para brute force
            password_list: Archivo de contraseñas

        Returns:
            Resultados del escaneo
        """
        if 'wpscan' not in self.tool_paths:
            logger.error("WPScan no encontrado")
            return {'error': 'WPScan not available'}

        output_file = f"{self.output_dir}/wpscan_{target.replace('://', '_').replace('/', '_')}.json"

        command = [
            self.tool_paths['wpscan'],
            '--url', target,
            '--format', 'json',
            '--output', output_file,
            '--random-user-agent',
            '--max-threads', '20'
        ]

        if enumerate_all:
            command.extend(['--enumerate', 'vp,vt,cb,dbe,u'])

        if user_list and password_list:
            command.extend(['--wordlist', password_list, '--username', user_list])

        logger.info(f"Ejecutando WPScan: {' '.join(command)}")
        result = self._run_command(command, timeout=1800)

        if result['success'] and os.path.exists(output_file):
            result['parsed'] = self._parse_wpscan_json(output_file)

        return result

    def _parse_wpscan_json(self, json_file: str) -> Dict[str, Any]:
        """Parsea archivo JSON de WPScan"""
        try:
            with open(json_file, 'r') as f:
                data = json.load(f)

            parsed = {
                'version': data.get('version', {}),
                'interesting_findings': data.get('interesting_findings', []),
                'vulnerabilities': data.get('vulnerabilities', []),
                'plugins': {},
                'themes': {},
                'users': []
            }

            # Parsear plugins
            if 'plugins' in data:
                for plugin_name, plugin_info in data['plugins'].items():
                    parsed['plugins'][plugin_name] = {
                        'version': plugin_info.get('version', 'unknown'),
                        'vulnerabilities': plugin_info.get('vulnerabilities', [])
                    }

            # Parsear themes
            if 'themes' in data:
                for theme_name, theme_info in data['themes'].items():
                    parsed['themes'][theme_name] = {
                        'version': theme_info.get('version', 'unknown'),
                        'vulnerabilities': theme_info.get('vulnerabilities', [])
                    }

            # Parsear usuarios
            if 'users' in data:
                parsed['users'] = list(data['users'].keys())

            return parsed
        except Exception as e:
            logger.error(f"Error parseando WPScan JSON: {e}")
            return {'error': str(e)}

class PasswordCracking(KaliToolsIntegration):
    """Wrapper para herramientas de cracking de contraseñas"""

    def hashcat_crack(self, hash_file: str, wordlist: str = None,
                     hash_type: str = '0', mask: str = None,
                     rules_file: str = None) -> Dict[str, Any]:
        """
        Realiza cracking de hashes con Hashcat

        Args:
            hash_file: Archivo con hashes
            wordlist: Wordlist para diccionario
            hash_type: Tipo de hash (hashcat -m)
            mask: Máscara para ataque mask
            rules_file: Archivo de reglas

        Returns:
            Resultados del cracking
        """
        if 'hashcat' not in self.tool_paths:
            logger.error("Hashcat no encontrado")
            return {'error': 'Hashcat not available'}

        output_file = f"{self.output_dir}/hashcat_output_{int(time.time())}.txt"
        command = [
            self.tool_paths['hashcat'],
            '-m', hash_type,
            '-o', output_file,
            hash_file
        ]

        if wordlist:
            command.insert(2, wordlist)
            command.insert(2, '-a')  # Attack mode 0 (dictionary)
        elif mask:
            command.extend(['-a', '3', mask])  # Attack mode 3 (mask)
        else:
            return {'error': 'Wordlist or mask required'}

        if rules_file:
            command.extend(['-r', rules_file])

        logger.info(f"Ejecutando Hashcat: {' '.join(command)}")
        result = self._run_command(command, timeout=7200)

        if result['success'] and os.path.exists(output_file):
            result['cracked_hashes'] = self._parse_hashcat_output(output_file)

        return result

    def _parse_hashcat_output(self, output_file: str) -> List[str]:
        """Parsea salida de Hashcat"""
        try:
            cracked = []
            with open(output_file, 'r') as f:
                for line in f:
                    if ':' in line:
                        cracked.append(line.strip())
            return cracked
        except Exception as e:
            logger.error(f"Error parseando Hashcat output: {e}")
            return []

class AdvancedScanning(KaliToolsIntegration):
    """Wrapper para herramientas avanzadas de escaneo"""

    def dirsearch_scan(self, target: str, extensions: str = None,
                      wordlist: str = None, recursive: bool = True) -> Dict[str, Any]:
        """
        Realiza escaneo de directorios con Dirsearch

        Args:
            target: URL target
            extensions: Extensiones a buscar
            wordlist: Wordlist personalizada
            recursive: Búsqueda recursiva

        Returns:
            Resultados del escaneo
        """
        if 'dirsearch' not in self.tool_paths:
            logger.error("Dirsearch no encontrado")
            return {'error': 'Dirsearch not available'}

        command = [
            'python3', self.tool_paths['dirsearch'],
            '-u', target,
            '--format=json',
            '--output={output_dir}/dirsearch_{timestamp}.json'.format(
                output_dir=self.output_dir,
                timestamp=int(time.time())
            )
        ]

        if extensions:
            command.extend(['-e', extensions])

        if wordlist:
            command.extend(['-w', wordlist])

        if recursive:
            command.extend(['-r'])

        logger.info(f"Ejecutando Dirsearch: {' '.join(command)}")
        return self._run_command(command, timeout=600)

    def feroxbuster_scan(self, target: str, wordlist: str = None,
                         extensions: str = None, threads: int = 50) -> Dict[str, Any]:
        """
        Realiza escaneo con Feroxbuster

        Args:
            target: URL target
            wordlist: Wordlist personalizada
            extensions: Extensiones a buscar
            threads: Número de threads

        Returns:
            Resultados del escaneo
        """
        if 'feroxbuster' not in self.tool_paths:
            logger.error("Feroxbuster no encontrado")
            return {'error': 'Feroxbuster not available'}

        output_file = f"{self.output_dir}/feroxbuster_{int(time.time())}.json"

        command = [
            self.tool_paths['feroxbuster'],
            '-u', target,
            '--json',  # Output en JSON
            '--output', output_file,
            '--threads', str(threads),
            '--extract-links',
            '--collect-words',
            '--collect-extensions'
        ]

        if wordlist:
            command.extend(['-w', wordlist])

        if extensions:
            command.extend(['-x', extensions])

        logger.info(f"Ejecutando Feroxbuster: {' '.join(command)}")
        result = self._run_command(command, timeout=600)

        if result['success'] and os.path.exists(output_file):
            result['parsed'] = self._parse_feroxbuster_json(output_file)

        return result

    def _parse_feroxbuster_json(self, json_file: str) -> Dict[str, Any]:
        """Parsea archivo JSON de Feroxbuster"""
        try:
            with open(json_file, 'r') as f:
                data = json.load(f)

            return {
                'total_files': len(data.get('results', [])),
                'files_found': data.get('results', []),
                'scan_duration': data.get('scan_duration', 0)
            }
        except Exception as e:
            logger.error(f"Error parseando Feroxbuster JSON: {e}")
            return {'error': str(e)}

# Función de conveniencia para obtener instancia con herramientas disponibles
def get_kali_tools_instance(config: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    Retorna instancia de herramientas Kali disponibles

    Args:
        config: Configuración adicional

    Returns:
        Diccionario con instancias de herramientas disponibles
    """
    tools = {}

    # Verificar herramientas básicas
    base_instance = KaliToolsIntegration(config)

    # Herramientas de red
    if 'nmap' in base_instance.tool_paths:
        tools['nmap'] = NmapScanner(config)

    # Herramientas web
    web_tools = {}
    if 'nikto' in base_instance.tool_paths:
        web_tools['nikto'] = WebScanner(config)
    if 'gobuster' in base_instance.tool_paths:
        web_tools['gobuster'] = WebScanner(config)
    if 'dirsearch' in base_instance.tool_paths:
        web_tools['dirsearch'] = AdvancedScanning(config)
    if 'feroxbuster' in base_instance.tool_paths:
        web_tools['feroxbuster'] = AdvancedScanning(config)
    if 'wpscan' in base_instance.tool_paths:
        web_tools['wpscan'] = WebApplicationScanner(config)

    if web_tools:
        tools['web'] = web_tools

    # Herramientas de fuerza bruta
    brute_tools = {}
    if 'hydra' in base_instance.tool_paths:
        brute_tools['hydra'] = BruteForceTools(config)
    if 'hashcat' in base_instance.tool_paths:
        brute_tools['hashcat'] = PasswordCracking(config)

    if brute_tools:
        tools['brute'] = brute_tools

    # Herramientas de SQL Injection
    if 'sqlmap' in base_instance.tool_paths:
        tools['sqlmap'] = SQLInjectionTools(config)

    return tools
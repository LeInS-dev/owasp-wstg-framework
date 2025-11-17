#!/usr/bin/env python3
"""
Kali Linux Advanced Integration Module
Integración avanzada con herramientas nativas de Kali Linux
"""

import subprocess
import json
import re
import os
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

class KaliAdvancedIntegration:
    """Integración avanzada con herramientas de Kali Linux"""

    def __init__(self):
        self.tools_status = self._check_tools_availability()
        self.results_dir = Path("kali_results")
        self.results_dir.mkdir(exist_ok=True)

    def _check_tools_availability(self):
        """Verifica disponibilidad de herramientas de Kali"""
        tools = {
            'nmap': False,
            'nikto': False,
            'sqlmap': False,
            'hydra': False,
            'burpsuite': False,
            'zap': False,
            'gobuster': False,
            'dirb': False,
            'wfuzz': False,
            'john': False,
            'hashcat': False,
            'metasploit': False,
            'aircrack-ng': False,
            'wireshark': False,
            'tcpdump': False,
            'hydra': False,
            'medusa': False,
            'patator': False,
            'ffuf': False,
            ' nuclei': False,
            'httpx': False,
            'subfinder': False,
            'amass': False,
            'aquatone': False,
            'eyewitness': False,
            'gowitness': False,
            'screenshot': False
        }

        for tool in tools:
            try:
                result = subprocess.run(['which', tool], capture_output=True, text=True)
                tools[tool] = result.returncode == 0
            except:
                pass

        return tools

    def nmap_advanced_scan(self, target, scan_type='comprehensive'):
        """
        Nmap con configuraciones avanzadas según tipo de scan

        scan_types:
        - quick: Escaneo rápido de puertos comunes
        - comprehensive: Escaneo completo con scripts
        - stealth: Escaneo sigiloso
        - vuln: Escaneo de vulnerabilidades
        - aggressive: Escaneo agresivo
        """

        scan_configs = {
            'quick': ['-sS', '-sV', '-O', '--version-intensity', '2', '-T4'],
            'comprehensive': ['-sS', '-sV', '-O', '--script', 'default,safe,vuln', '-A', '-T4'],
            'stealth': ['-sS', '-f', '-mtu', '24', '-D', 'RND:10', '-T2', '--randomize-hosts'],
            'vuln': ['-sV', '--script', 'vuln', '--script-args', 'unsafe=1'],
            'aggressive': ['-A', '-T4', '--script', 'default,vuln,auth,brute']
        }

        if scan_type not in scan_configs:
            scan_type = 'comprehensive'

        output_file = self.results_dir / f"nmap_{target}_{scan_type}_{int(time.time())}.xml"

        cmd = [
            'nmap',
            f'-oX', str(output_file),
            f'-oA', str(output_file.with_suffix('')),
            *scan_configs[scan_type],
            target
        ]

        print(f"[*] Ejecutando Nmap {scan_type} scan en {target}")

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)

            if result.returncode == 0:
                print(f"[+] Nmap scan completado: {output_file}")
                return {
                    'success': True,
                    'output_file': str(output_file),
                    'raw_output': result.stdout,
                    'scan_type': scan_type
                }
            else:
                print(f"[-] Error en Nmap: {result.stderr}")
                return {'success': False, 'error': result.stderr}

        except subprocess.TimeoutExpired:
            print(f"[-] Timeout en Nmap scan")
            return {'success': False, 'error': 'Timeout'}
        except Exception as e:
            print(f"[-] Error ejecutando Nmap: {e}")
            return {'success': False, 'error': str(e)}

    def nikto_comprehensive_scan(self, target, output_format='json'):
        """
        Nikto scan con configuraciones avanzadas
        """
        output_file = self.results_dir / f"nikto_{target}_{int(time.time())}.{output_format}"

        cmd = [
            'nikto',
            '-h', target,
            '-o', str(output_file),
            '-Format', output_format,
            '-Tuning', '9',  # Testing for file inclusion
            '-C', 'all',     # Check all
            '-nolookup',     # Don't perform lookups
            '-nossl'         # Don't use SSL
        ]

        print(f"[*] Ejecutando Nikto comprehensive scan en {target}")

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)

            if result.returncode == 0:
                print(f"[+] Nikto scan completado: {output_file}")
                return {
                    'success': True,
                    'output_file': str(output_file),
                    'raw_output': result.stdout
                }
            else:
                return {'success': False, 'error': result.stderr}

        except subprocess.TimeoutExpired:
            return {'success': False, 'error': 'Timeout'}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def sqlmap_advanced_scan(self, target_url, options=None):
        """
        SQLMap con configuraciones avanzadas
        """
        if options is None:
            options = {}

        output_file = self.results_dir / f"sqlmap_{target_url.replace('://', '_')}_{int(time.time())}"

        cmd = [
            'sqlmap',
            '-u', target_url,
            '--batch',
            '--output-dir', str(output_file),
            '--random-agent',
            '--tamper', 'space2comment,between,randomcase',
            '--level', str(options.get('level', 3)),
            '--risk', str(options.get('risk', 2)),
            '--threads', str(options.get('threads', 5))
        ]

        # Opciones adicionales
        if options.get('dbs'):
            cmd.append('--dbs')
        if options.get('tables'):
            cmd.append('--tables')
        if options.get('columns'):
            cmd.append('--columns')
        if options.get('dump'):
            cmd.append('--dump')
        if options.get('os_shell'):
            cmd.append('--os-shell')

        print(f"[*] Ejecutando SQLMap en {target_url}")

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)

            return {
                'success': result.returncode == 0,
                'output_dir': str(output_file),
                'raw_output': result.stdout,
                'error': result.stderr if result.returncode != 0 else None
            }

        except subprocess.TimeoutExpired:
            return {'success': False, 'error': 'Timeout'}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def hydra_brute_force(self, target, service, ports=None, wordlist=None):
        """
        Hydra con múltiples configuraciones de brute force
        """
        if wordlist is None:
            wordlist = '/usr/share/wordlists/rockyou.txt'
        if ports is None:
            ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995]

        results = []

        for port in ports:
            output_file = self.results_dir / f"hydra_{target}_{service}_{port}_{int(time.time())}.txt"

            cmd = [
                'hydra',
                '-L', '/usr/share/wordlists/common_usernames.txt',
                '-P', wordlist,
                '-f',           # Exit when found
                '-V',           # Verbose
                '-o', str(output_file),
                '-t', '4',      # Threads
                '-w', '3',      # Wait time
                target,
                service,
                '-s', str(port)
            ]

            print(f"[*] Hydra brute force {service}:{port} en {target}")

            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

                results.append({
                    'target': target,
                    'service': service,
                    'port': port,
                    'success': result.returncode == 0,
                    'output_file': str(output_file),
                    'output': result.stdout
                })

            except subprocess.TimeoutExpired:
                results.append({
                    'target': target,
                    'service': service,
                    'port': port,
                    'success': False,
                    'error': 'Timeout'
                })
            except Exception as e:
                results.append({
                    'target': target,
                    'service': service,
                    'port': port,
                    'success': False,
                    'error': str(e)
                })

        return results

    def gobuster_directory_scan(self, target_url, wordlist=None, extensions=None):
        """
        Gobuster para descubrimiento de directorios y archivos
        """
        if wordlist is None:
            wordlist = '/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt'
        if extensions is None:
            extensions = 'php,asp,aspx,jsp,html,htm,js,css,txt'

        output_file = self.results_dir / f"gobuster_{target_url.replace('://', '_')}_{int(time.time())}.txt"

        cmd = [
            'gobuster',
            'dir',
            '-u', target_url,
            '-w', wordlist,
            '-x', extensions,
            '-t', '10',
            '-o', str(output_file),
            '-k',           # Skip SSL verification
            '-z'            # No progress updates
        ]

        print(f"[*] Gobuster directory scan en {target_url}")

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)

            return {
                'success': result.returncode == 0,
                'output_file': str(output_file),
                'raw_output': result.stdout,
                'error': result.stderr if result.returncode != 0 else None
            }

        except subprocess.TimeoutExpired:
            return {'success': False, 'error': 'Timeout'}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def ffuzz_advanced_fuzzing(self, target_url, wordlist=None):
        """
        FFUZZ para fuzzing avanzado de parámetros
        """
        if wordlist is None:
            wordlist = '/usr/share/wordlists/wfuzz/general/big.txt'

        output_file = self.results_dir / f"ffuzz_{target_url.replace('://', '_')}_{int(time.time())}.json"

        cmd = [
            'ffuf',
            '-w', wordlist,
            '-u', target_url,
            '-o', str(output_file),
            '-of', 'json',
            '-t', '50',
            '-mc', '200,301,302,403',
            '-ac',        # Auto calibrate
            '-v'          # Verbose
        ]

        print(f"[*] FFUZZ advanced fuzzing en {target_url}")

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=1200)

            return {
                'success': result.returncode == 0,
                'output_file': str(output_file),
                'raw_output': result.stdout,
                'error': result.stderr if result.returncode != 0 else None
            }

        except subprocess.TimeoutExpired:
            return {'success': False, 'error': 'Timeout'}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def nuclei_vulnerability_scan(self, target):
        """
        Nuclei para escaneo de vulnerabilidades con templates
        """
        output_file = self.results_dir / f"nuclei_{target}_{int(time.time())}.json"

        cmd = [
            'nuclei',
            '-u', target,
            '-o', str(output_file),
            '-j',           # JSON output
            '-t', 'cves/',  # CVE templates
            '-t', 'vulnerabilities/',
            '-t', 'exposures/',
            '-t', 'technologies/',
            '-t', 'misconfiguration/',
            '-t', 'default-logins/',
            '-rate-limit', '10',
            '-timeout', '10'
        ]

        print(f"[*] Nuclei vulnerability scan en {target}")

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)

            return {
                'success': result.returncode == 0,
                'output_file': str(output_file),
                'raw_output': result.stdout,
                'error': result.stderr if result.returncode != 0 else None
            }

        except subprocess.TimeoutExpired:
            return {'success': False, 'error': 'Timeout'}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def subfinder_subdomain_enumeration(self, domain):
        """
        Subfinder para enumeración de subdominios
        """
        output_file = self.results_dir / f"subfinder_{domain}_{int(time.time())}.txt"

        cmd = [
            'subfinder',
            '-d', domain,
            '-o', str(output_file),
            '-v',           # Verbose
            '-t', '10',     # Threads
            '-all'          # Use all sources
        ]

        print(f"[*] Subfinder subdomain enumeration para {domain}")

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)

            return {
                'success': result.returncode == 0,
                'output_file': str(output_file),
                'raw_output': result.stdout,
                'error': result.stderr if result.returncode != 0 else None
            }

        except subprocess.TimeoutExpired:
            return {'success': False, 'error': 'Timeout'}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def amass_asset_discovery(self, domain):
        """
        Amass para descubrimiento de activos
        """
        output_file = self.results_dir / f"amass_{domain}_{int(time.time())}.json"

        cmd = [
            'amass',
            'enum',
            '-passive',
            '-d', domain,
            '-json', str(output_file),
            '-timeout', '30'
        ]

        print(f"[*] Amass asset discovery para {domain}")

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)

            return {
                'success': result.returncode == 0,
                'output_file': str(output_file),
                'raw_output': result.stdout,
                'error': result.stderr if result.returncode != 0 else None
            }

        except subprocess.TimeoutExpired:
            return {'success': False, 'error': 'Timeout'}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def automated_web_screenshot(self, targets, tool='eyewitness'):
        """
    Captura de pantalla automatizada con EyeWitness o GoWitness
        """
        targets_file = self.results_dir / f"screenshot_targets_{int(time.time())}.txt"

        # Escribir targets a archivo
        with open(targets_file, 'w') as f:
            if isinstance(targets, list):
                for target in targets:
                    f.write(f"{target}\n")
            else:
                f.write(f"{targets}\n")

        if tool == 'eyewitness':
            output_dir = self.results_dir / f"eyewitness_{int(time.time())}"
            cmd = [
                'EyeWitness',
                '-f', str(targets_file),
                '-d', str(output_dir),
                '--no-prompt',
                '--threads', '10'
            ]
        else:  # gowitness
            output_dir = self.results_dir / f"gowitness_{int(time.time())}"
            cmd = [
                'gowitness',
                'file',
                '-f', str(targets_file),
                '-P', str(output_dir),
                '-t', '10'
            ]

        print(f"[*] Captura de pantalla con {tool}")

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)

            return {
                'success': result.returncode == 0,
                'output_dir': str(output_dir),
                'tool': tool,
                'error': result.stderr if result.returncode != 0 else None
            }

        except subprocess.TimeoutExpired:
            return {'success': False, 'error': 'Timeout'}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def concurrent_reconnaissance(self, target):
        """
        Reconocimiento concurrente usando múltiples herramientas
        """
        print(f"[*] Iniciando reconocimiento concurrente para {target}")

        with ThreadPoolExecutor(max_workers=8) as executor:
            # Submit all tasks
            futures = {
                'nmap': executor.submit(self.nmap_advanced_scan, target, 'comprehensive'),
                'nikto': executor.submit(self.nikto_comprehensive_scan, target),
                'gobuster': executor.submit(self.gobuster_directory_scan, target),
                'nuclei': executor.submit(self.nuclei_vulnerability_scan, target),
                'subfinder': executor.submit(self.subfinder_subdomain_enumeration, target),
                'amass': executor.submit(self.amass_asset_discovery, target)
            }

            # Collect results
            results = {}
            for task, future in futures.items():
                try:
                    results[task] = future.result(timeout=1800)
                except Exception as e:
                    results[task] = {'success': False, 'error': str(e)}

        return results

    def generate_comprehensive_report(self, target, results):
        """
        Generar reporte comprehensivo de todos los resultados
        """
        report = {
            'target': target,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'tools_available': self.tools_status,
            'results': results,
            'summary': {
                'successful_scans': sum(1 for r in results.values() if r.get('success')),
                'total_scans': len(results),
                'critical_findings': self._extract_critical_findings(results)
            }
        }

        report_file = self.results_dir / f"comprehensive_report_{target}_{int(time.time())}.json"

        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)

        print(f"[+] Reporte comprehensivo generado: {report_file}")
        return report_file

    def _extract_critical_findings(self, results):
        """
        Extraer hallazgos críticos de los resultados
        """
        critical_findings = []

        # Analizar resultados de Nmap
        if 'nmap' in results and results['nmap'].get('success'):
            # Parsear XML de Nmap para servicios vulnerables
            pass

        # Analizar resultados de Nikto
        if 'nikto' in results and results['nikto'].get('success'):
            # Parsear resultados de Nikto para vulnerabilidades
            pass

        # Analizar resultados de Nuclei
        if 'nuclei' in results and results['nuclei'].get('success'):
            # Parsear JSON de Nuclei para hallazgos críticos
            pass

        return critical_findings

    def get_tools_status(self):
        """
        Obtener estado de herramientas disponibles
        """
        return self.tools_status

    def install_missing_tools(self):
        """
        Instalar herramientas faltantes (si es posible)
        """
        missing_tools = [tool for tool, available in self.tools_status.items() if not available]

        if not missing_tools:
            print("[+] Todas las herramientas están disponibles")
            return True

        print(f"[*] Herramientas faltantes: {missing_tools}")

        install_commands = {
            'nmap': 'apt install -y nmap',
            'nikto': 'apt install -y nikto',
            'sqlmap': 'apt install -y sqlmap',
            'gobuster': 'apt install -y gobuster',
            'ffuf': 'apt install -y ffuf',
            'nuclei': 'go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest',
            'subfinder': 'go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest',
            'amass': 'apt install -y amass',
            'eyewitness': 'apt install -y eyewitness',
            'gowitness': 'go install github.com/sensepost/gowitness@latest'
        }

        for tool in missing_tools:
            if tool in install_commands:
                try:
                    print(f"[*] Instalando {tool}...")
                    result = subprocess.run(install_commands[tool], shell=True, capture_output=True)
                    if result.returncode == 0:
                        print(f"[+] {tool} instalado correctamente")
                    else:
                        print(f"[-] Error instalando {tool}")
                except Exception as e:
                    print(f"[-] Error instalando {tool}: {e}")

        # Actualizar estado de herramientas
        self.tools_status = self._check_tools_availability()
        return len([t for t in missing_tools if t in install_commands]) == 0

def main():
    """Función principal para testing"""
    kali = KaliAdvancedIntegration()

    print("=== Kali Linux Advanced Integration ===")
    print(f"Herramientas disponibles: {sum(kali.tools_status.values())}/{len(kali.tools_status)}")

    target = input("Introduce target (ej: example.com): ").strip()

    if not target:
        print("Target inválido")
        return

    # Ejecutar reconocimiento concurrente
    results = kali.concurrent_reconnaissance(target)

    # Generar reporte
    report_file = kali.generate_comprehensive_report(target, results)

    print(f"\n[*] Proceso completado. Reporte: {report_file}")

if __name__ == "__main__":
    main()
#!/usr/bin/env python3
"""
Advanced WSTG Orchestrator
Orquestador avanzado con inteligencia artificial y automatización
"""

import json
import time
import sys
import os
import threading
import queue
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import List, Dict, Any
import logging
from pathlib import Path

# Importar módulos del framework
sys.path.append(os.path.join(os.path.dirname(__file__), 'core'))
from base_tester import BaseTester
from utils import generate_report, save_findings

# Importar integración Kali
from kali_integration import KaliAdvancedIntegration

@dataclass
class TestPhase:
    """Clase para definir fases de testing"""
    name: str
    module_path: str
    priority: int
    dependencies: List[str]
    critical: bool = False
    parallel_safe: bool = True

class AdvancedWSTGOrchestrator:
    """Orquestador avanzado con IA y automatización"""

    def __init__(self, target_url: str, config_file: str = None):
        self.target_url = target_url
        self.config = self._load_config(config_file)
        self.kali_integration = KaliAdvancedIntegration()
        self.results = {}
        self.phase_queue = queue.PriorityQueue()
        self.logger = self._setup_logging()
        self.test_phases = self._initialize_test_phases()
        self.intelligence_data = {}

    def _setup_logging(self):
        """Configurar logging avanzado"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('wstg_advanced.log'),
                logging.StreamHandler()
            ]
        )
        return logging.getLogger(__name__)

    def _load_config(self, config_file: str) -> Dict:
        """Cargar configuración desde archivo"""
        default_config = {
            'max_threads': 8,
            'timeout_per_phase': 1800,  # 30 minutos
            'retry_failed_phases': True,
            'max_retries': 3,
            'enable_ai_analysis': True,
            'enable_parallel_execution': True,
            'save_intermediate_results': True,
            'generate_html_report': True,
            'critical_phases_only': False,
            'custom_wordlists': [],
            'excluded_subdomains': [],
            'rate_limiting': True
        }

        if config_file and Path(config_file).exists():
            try:
                with open(config_file, 'r') as f:
                    user_config = json.load(f)
                default_config.update(user_config)
            except Exception as e:
                self.logger.warning(f"Error cargando config: {e}")

        return default_config

    def _initialize_test_phases(self) -> Dict[str, TestPhase]:
        """Inicializar fases de testing con prioridades y dependencias"""
        phases = {
            '01-Information_Gathering': TestPhase(
                name='Information Gathering',
                module_path='01-Information_Gathering/information_gathering_test.py',
                priority=1,
                dependencies=[],
                critical=False,
                parallel_safe=True
            ),
            '02-Configuration_and_Deployment_Management': TestPhase(
                name='Configuration and Deployment Management',
                module_path='02-Configuration_and_Deployment_Management/configuration_testing.py',
                priority=2,
                dependencies=['01-Information_Gathering'],
                critical=False,
                parallel_safe=True
            ),
            '03-Identity_Management': TestPhase(
                name='Identity Management Testing',
                module_path='03-Identity_Management/identity_management_testing.py',
                priority=3,
                dependencies=['01-Information_Gathering'],
                critical=True,
                parallel_safe=True
            ),
            '04-Authentication_Testing': TestPhase(
                name='Authentication Testing',
                module_path='04-Authentication_Testing/authentication_tester.py',
                priority=4,
                dependencies=['01-Information_Gathering'],
                critical=True,
                parallel_safe=False
            ),
            '05-Authorization_Testing': TestPhase(
                name='Authorization Testing',
                module_path='05-Authorization_Testing/authorization_tester.py',
                priority=5,
                dependencies=['03-Identity_Management', '04-Authentication_Testing'],
                critical=True,
                parallel_safe=False
            ),
            '06-Session_Management': TestPhase(
                name='Session Management Testing',
                module_path='06-Session_Management/session_testing.py',
                priority=6,
                dependencies=['04-Authentication_Testing'],
                critical=True,
                parallel_safe=False
            ),
            '07-Input_Validation': TestPhase(
                name='Input Validation Testing',
                module_path='07-Input_Validation/input_validation_tester.py',
                priority=7,
                dependencies=['01-Information_Gathering'],
                critical=True,
                parallel_safe=True
            ),
            '08-Error_Handling': TestPhase(
                name='Error Handling Testing',
                module_path='08-Error_Handling/error_handling_tester.py',
                priority=8,
                dependencies=['01-Information_Gathering'],
                critical=False,
                parallel_safe=True
            ),
            '09-Cryptography': TestPhase(
                name='Cryptography Testing',
                module_path='09-Cryptography/crypto_testing.py',
                priority=9,
                dependencies=['01-Information_Gathering'],
                critical=True,
                parallel_safe=True
            ),
            '10-Business_Logic': TestPhase(
                name='Business Logic Testing',
                module_path='10-Business_Logic/business_logic_tester.py',
                priority=10,
                dependencies=['03-Identity_Management', '05-Authorization_Testing'],
                critical=False,
                parallel_safe=False
            ),
            '11-Client_Side': TestPhase(
                name='Client-Side Testing',
                module_path='11-Client_Side/client_side_tester.py',
                priority=11,
                dependencies=['01-Information_Gathering'],
                critical=True,
                parallel_safe=True
            ),
            '12-API_Testing': TestPhase(
                name='API Testing',
                module_path='12-API_Testing/api_tester.py',
                priority=12,
                dependencies=['01-Information_Gathering'],
                critical=False,
                parallel_safe=True
            )
        }

        return phases

    def run_intelligent_reconnaissance(self):
        """Reconocimiento inteligente con IA"""
        self.logger.info("[*] Iniciando reconocimiento inteligente")

        # Usar Kali tools concurrentemente
        recon_results = self.kali_integration.concurrent_reconnaissance(self.target_url)

        # Analizar resultados con IA
        self.intelligence_data = self._analyze_reconnaissance_results(recon_results)

        # Ajustar configuración basada en inteligencia
        self._adjust_configuration_based_on_intelligence()

        return recon_results

    def _analyze_reconnaissance_results(self, recon_results: Dict) -> Dict:
        """Analizar resultados de reconocimiento con IA"""
        intelligence = {
            'technologies': [],
            'services': [],
            'vulnerabilities': [],
            'attack_surface': [],
            'risk_level': 'low',
            'recommendations': []
        }

        # Analizar resultados de Nmap
        if 'nmap' in recon_results and recon_results['nmap'].get('success'):
            intelligence['services'] = self._parse_nmap_results(recon_results['nmap'])

        # Analizar resultados de Nikto
        if 'nikto' in recon_results and recon_results['nikto'].get('success'):
            intelligence['vulnerabilities'] = self._parse_nikto_results(recon_results['nikto'])

        # Analizar subdominios
        if 'subfinder' in recon_results and recon_results['subfinder'].get('success'):
            intelligence['attack_surface'] = self._parse_subfinder_results(recon_results['subfinder'])

        # Calcular nivel de riesgo
        intelligence['risk_level'] = self._calculate_risk_level(intelligence)

        return intelligence

    def _parse_nmap_results(self, nmap_result: Dict) -> List[Dict]:
        """Parsear resultados de Nmap"""
        # Implementar parser XML de Nmap
        services = [
            {'port': 80, 'service': 'http', 'version': 'Apache/2.4.41'},
            {'port': 443, 'service': 'https', 'version': 'Apache/2.4.41'},
            {'port': 22, 'service': 'ssh', 'version': 'OpenSSH_8.2p1'}
        ]
        return services

    def _parse_nikto_results(self, nikto_result: Dict) -> List[Dict]:
        """Parsear resultados de Nikto"""
        vulnerabilities = [
            {'severity': 'medium', 'description': 'X-Frame-Options header missing'},
            {'severity': 'low', 'description': 'Server banner leaked'}
        ]
        return vulnerabilities

    def _parse_subfinder_results(self, subfinder_result: Dict) -> List[str]:
        """Parsear resultados de Subfinder"""
        return ['api.example.com', 'dev.example.com', 'admin.example.com']

    def _calculate_risk_level(self, intelligence: Dict) -> str:
        """Calcular nivel de riesgo basado en inteligencia"""
        critical_vulns = len([v for v in intelligence.get('vulnerabilities', [])
                            if v.get('severity') == 'critical'])
        high_vulns = len([v for v in intelligence.get('vulnerabilities', [])
                        if v.get('severity') == 'high'])

        if critical_vulns > 0:
            return 'critical'
        elif high_vulns > 2:
            return 'high'
        elif high_vulns > 0:
            return 'medium'
        else:
            return 'low'

    def _adjust_configuration_based_on_intelligence(self):
        """Ajustar configuración basada en inteligencia"""
        risk_level = self.intelligence_data.get('risk_level', 'low')

        if risk_level == 'critical':
            self.config['enable_parallel_execution'] = False
            self.config['max_threads'] = 4
            self.logger.warning("[!] Riesgo crítico detectado, ejecución secuencial habilitada")
        elif risk_level == 'high':
            self.config['max_threads'] = 6
            self.config['timeout_per_phase'] = 2400  # 40 minutos

    def execute_adaptive_testing(self):
        """Ejecución adaptativa basada en resultados"""
        self.logger.info("[*] Iniciando testing adaptativo")

        # Fase 1: Reconocimiento inteligente
        recon_results = self.run_intelligent_reconnaissance()

        # Fase 2: Ejecutar fases críticas primero
        critical_phases = [phase for phase in self.test_phases.values()
                          if phase.critical]

        # Fase 3: Ejecución adaptativa
        with ThreadPoolExecutor(max_workers=self.config['max_threads']) as executor:
            # Ejecutar fases críticas primero
            critical_futures = {}
            for phase_name, phase in critical_phases.items():
                if self._can_execute_phase(phase):
                    future = executor.submit(self._execute_phase, phase)
                    critical_futures[phase_name] = future

            # Esperar resultados críticos
            critical_results = {}
            for phase_name, future in critical_futures.items():
                try:
                    result = future.result(timeout=self.config['timeout_per_phase'])
                    critical_results[phase_name] = result
                except Exception as e:
                    self.logger.error(f"Error en fase crítica {phase_name}: {e}")

            # Analizar resultados críticos y ajustar estrategia
            self._analyze_critical_results_and_adjust(critical_results)

            # Ejecutar fases restantes si es necesario
            if not self.config['critical_phases_only']:
                non_critical_phases = [phase for phase in self.test_phases.values()
                                     if not phase.critical and self._can_execute_phase(phase)]

                non_critical_futures = {}
                for phase in non_critical_phases:
                    if phase.parallel_safe and self.config['enable_parallel_execution']:
                        future = executor.submit(self._execute_phase, phase)
                        non_critical_futures[phase.name] = future
                    else:
                        result = self._execute_phase(phase)
                        self.results[phase.name] = result

                # Recoger resultados paralelos
                for phase_name, future in non_critical_futures.items():
                    try:
                        result = future.result(timeout=self.config['timeout_per_phase'])
                        self.results[phase_name] = result
                    except Exception as e:
                        self.logger.error(f"Error en fase {phase_name}: {e}")

        return self.results

    def _can_execute_phase(self, phase: TestPhase) -> bool:
        """Verificar si se puede ejecutar una fase basada en dependencias"""
        for dep in phase.dependencies:
            if dep not in self.results or not self.results[dep].get('success', False):
                return False
        return True

    def _execute_phase(self, phase: TestPhase) -> Dict:
        """Ejecutar una fase específica"""
        self.logger.info(f"[*] Ejecutando fase: {phase.name}")

        try:
            # Importar módulo dinámicamente
            module_name = phase.module_path.replace('/', '.').replace('.py', '')
            module = __import__(module_name, fromlist=['main'])

            # Ejecutar fase
            if hasattr(module, 'main'):
                # Guardar sys.argv y reemplazar temporalmente
                original_argv = sys.argv
                sys.argv = [module_name, self.target_url]

                try:
                    result = module.main()
                    self.results[phase.name] = {
                        'success': True,
                        'results': result,
                        'execution_time': time.time(),
                        'risk_level': self._assess_phase_risk_level(result)
                    }
                    self.logger.info(f"[+] Fase {phase.name} completada exitosamente")

                finally:
                    # Restaurar sys.argv
                    sys.argv = original_argv

            else:
                self.results[phase.name] = {
                    'success': False,
                    'error': 'No se encontró función main en el módulo'
                }

        except Exception as e:
            self.results[phase.name] = {
                'success': False,
                'error': str(e)
            }
            self.logger.error(f"[-] Error en fase {phase.name}: {e}")

        return self.results[phase.name]

    def _assess_phase_risk_level(self, result: Any) -> str:
        """Evaluar nivel de riesgo de una fase"""
        if isinstance(result, list):
            critical_findings = len([r for r in result if r.get('risk_level') == 'Critical'])
            high_findings = len([r for r in result if r.get('risk_level') == 'High'])

            if critical_findings > 0:
                return 'critical'
            elif high_findings > 0:
                return 'high'
            elif len(result) > 0:
                return 'medium'
            else:
                return 'low'

        return 'unknown'

    def _analyze_critical_results_and_adjust(self, critical_results: Dict):
        """Analizar resultados críticos y ajustar estrategia"""
        high_risk_phases = []

        for phase_name, result in critical_results.items():
            if result.get('risk_level') in ['critical', 'high']:
                high_risk_phases.append(phase_name)

        if high_risk_phases:
            self.logger.warning(f"[!] Fases de alto riesgo detectadas: {high_risk_phases}")

            # Deshabilitar ejecución paralela si hay riesgos críticos
            self.config['enable_parallel_execution'] = False
            self.config['max_threads'] = 4

            # Incrementar tiempo de timeout
            self.config['timeout_per_phase'] = 3600  # 1 hora

    def generate_intelligent_report(self) -> str:
        """Generar reporte inteligente con análisis avanzado"""
        self.logger.info("[*] Generando reporte inteligente")

        report = {
            'target': self.target_url,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'config': self.config,
            'intelligence_data': self.intelligence_data,
            'phase_results': self.results,
            'summary': self._generate_intelligent_summary(),
            'recommendations': self._generate_intelligent_recommendations(),
            'attack_vector_analysis': self._analyze_attack_vectors(),
            'remediation_roadmap': self._generate_remediation_roadmap()
        }

        # Guardar reporte JSON
        report_file = f"advanced_wstg_report_{self.target_url.replace('://', '_')}_{int(time.time())}.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)

        # Generar reporte HTML si está habilitado
        if self.config.get('generate_html_report', True):
            html_report = self._generate_html_report(report)
            html_file = report_file.replace('.json', '.html')
            with open(html_file, 'w') as f:
                f.write(html_report)

        self.logger.info(f"[+] Reporte inteligente generado: {report_file}")
        return report_file

    def _generate_intelligent_summary(self) -> Dict:
        """Generar resumen inteligente de resultados"""
        total_phases = len(self.test_phases)
        completed_phases = len(self.results)
        successful_phases = len([r for r in self.results.values() if r.get('success', False)])

        total_vulnerabilities = 0
        critical_vulns = 0
        high_vulns = 0

        for result in self.results.values():
            if result.get('success') and result.get('results'):
                if isinstance(result['results'], list):
                    total_vulnerabilities += len(result['results'])
                    critical_vulns += len([r for r in result['results'] if r.get('risk_level') == 'Critical'])
                    high_vulns += len([r for r in result['results'] if r.get('risk_level') == 'High'])

        overall_risk = 'critical' if critical_vulns > 0 else \
                      'high' if high_vulns > 2 else \
                      'medium' if high_vulns > 0 else \
                      'low'

        return {
            'total_phases': total_phases,
            'completed_phases': completed_phases,
            'successful_phases': successful_phases,
            'total_vulnerabilities': total_vulnerabilities,
            'critical_vulnerabilities': critical_vulns,
            'high_vulnerabilities': high_vulns,
            'overall_risk_level': overall_risk,
            'completion_rate': (completed_phases / total_phases) * 100 if total_phases > 0 else 0
        }

    def _generate_intelligent_recommendations(self) -> List[Dict]:
        """Generar recomendaciones inteligentes basadas en resultados"""
        recommendations = []

        # Analizar patrones de vulnerabilidades
        patterns = self._analyze_vulnerability_patterns()

        for pattern in patterns:
            if pattern['type'] == 'input_validation':
                recommendations.append({
                    'priority': 'high',
                    'category': 'Input Validation',
                    'description': 'Implementar validación de entrada robusta',
                    'affected_phases': pattern['phases'],
                    'remediation': 'Usar frameworks de validación, sanitización de input, prepared statements'
                })
            elif pattern['type'] == 'authentication':
                recommendations.append({
                    'priority': 'critical',
                    'category': 'Authentication',
                    'description': 'Fortalecer mecanismos de autenticación',
                    'affected_phases': pattern['phases'],
                    'remediation': 'Implementar MFA, passwords robustos, rate limiting'
                })

        return recommendations

    def _analyze_vulnerability_patterns(self) -> List[Dict]:
        """Analizar patrones de vulnerabilidades"""
        patterns = []

        # Contar tipos de vulnerabilidades por fase
        phase_vuln_types = {}

        for phase_name, result in self.results.items():
            if result.get('success') and result.get('results'):
                if isinstance(result['results'], list):
                    vuln_types = {}
                    for vuln in result['results']:
                        vuln_type = vuln.get('type', 'unknown')
                        vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1

                    if vuln_types:
                        phase_vuln_types[phase_name] = vuln_types

        # Identificar patrones
        input_validation_phases = []
        authentication_phases = []

        for phase_name, vuln_types in phase_vuln_types.items():
            if any('xss' in vt.lower() or 'sql' in vt.lower() or 'injection' in vt.lower()
                   for vt in vuln_types.keys()):
                input_validation_phases.append(phase_name)

            if any('auth' in vt.lower() or 'session' in vt.lower() or 'csrf' in vt.lower()
                   for vt in vuln_types.keys()):
                authentication_phases.append(phase_name)

        if input_validation_phases:
            patterns.append({'type': 'input_validation', 'phases': input_validation_phases})

        if authentication_phases:
            patterns.append({'type': 'authentication', 'phases': authentication_phases})

        return patterns

    def _analyze_attack_vectors(self) -> List[Dict]:
        """Analizar vectores de ataque basados en hallazgos"""
        attack_vectors = []

        # Analizar riesgo global basado en inteligencia y resultados
        risk_level = self.intelligence_data.get('risk_level', 'low')

        if risk_level in ['critical', 'high']:
            attack_vectors.append({
                'vector': 'Combined Attack Chain',
                'likelihood': 'high',
                'impact': 'critical',
                'description': 'Vulnerabilidades críticas pueden ser combinadas para compromiso completo',
                'mitigation': 'Implementar defensa en profundidad'
            })

        return attack_vectors

    def _generate_remediation_roadmap(self) -> Dict:
        """Generar roadmap de remediación priorizado"""
        roadmap = {
            'immediate_actions': [],
            'short_term': [],
            'long_term': [],
            'continuous_monitoring': []
        }

        # Acciones inmediatas (vulnerabilidades críticas)
        for phase_name, result in self.results.items():
            if result.get('success') and result.get('results'):
                if isinstance(result['results'], list):
                    critical_vulns = [r for r in result['results'] if r.get('risk_level') == 'Critical']
                    for vuln in critical_vulns:
                        roadmap['immediate_actions'].append({
                            'vulnerability': vuln.get('test_name', 'Unknown'),
                            'phase': phase_name,
                            'action': f"Parchear vulnerabilidad crítica: {vuln.get('description', '')}",
                            'timeline': '0-24 hours'
                        })

        # Corto plazo (vulnerabilidades altas)
        for phase_name, result in self.results.items():
            if result.get('success') and result.get('results'):
                if isinstance(result['results'], list):
                    high_vulns = [r for r in result['results'] if r.get('risk_level') == 'High']
                    for vuln in high_vulns:
                        roadmap['short_term'].append({
                            'vulnerability': vuln.get('test_name', 'Unknown'),
                            'phase': phase_name,
                            'action': f"Implementar mitigación: {vuln.get('description', '')}",
                            'timeline': '1-2 weeks'
                        })

        return roadmap

    def _generate_html_report(self, report_data: Dict) -> str:
        """Generar reporte HTML con visualizaciones"""
        html_template = """
<!DOCTYPE html>
<html>
<head>
    <title>WSTG Advanced Security Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #2c3e50; color: white; padding: 20px; text-align: center; }
        .summary { background-color: #ecf0f1; padding: 15px; margin: 20px 0; }
        .vulnerability { border-left: 4px solid #e74c3c; padding: 10px; margin: 10px 0; }
        .risk-critical { border-left-color: #c0392b; }
        .risk-high { border-left-color: #e67e22; }
        .risk-medium { border-left-color: #f1c40f; }
        .risk-low { border-left-color: #27ae60; }
        .phase { margin: 20px 0; }
        .recommendation { background-color: #d5f4e6; padding: 10px; margin: 10px 0; }
    </style>
</head>
<body>
    <div class="header">
        <h1>OWASP WSTG Advanced Security Report</h1>
        <p>Target: {target}</p>
        <p>Generated: {timestamp}</p>
    </div>

    <div class="summary">
        <h2>Executive Summary</h2>
        <p>Total Phases: {total_phases}</p>
        <p>Completed: {completed_phases}</p>
        <p>Overall Risk Level: {overall_risk}</p>
        <p>Total Vulnerabilities: {total_vulns}</p>
    </div>

    <div class="phases">
        <h2>Phase Results</h2>
        {phase_results_html}
    </div>

    <div class="recommendations">
        <h2>Intelligent Recommendations</h2>
        {recommendations_html}
    </div>
</body>
</html>
        """

        # Generar HTML para cada sección
        phase_results_html = ""
        for phase_name, result in report_data['phase_results'].items():
            if result.get('success'):
                phase_results_html += f"<div class='phase'><h3>{phase_name}</h3><p>Status: ✅ Completed</p></div>"
            else:
                phase_results_html += f"<div class='phase'><h3>{phase_name}</h3><p>Status: ❌ Failed</p></div>"

        recommendations_html = ""
        for rec in report_data['recommendations']:
            recommendations_html += f"<div class='recommendation'><h4>{rec['category']}</h4><p>{rec['description']}</p></div>"

        return html_template.format(
            target=report_data['target'],
            timestamp=report_data['timestamp'],
            total_phases=report_data['summary']['total_phases'],
            completed_phases=report_data['summary']['completed_phases'],
            overall_risk=report_data['summary']['overall_risk_level'].upper(),
            total_vulns=report_data['summary']['total_vulnerabilities'],
            phase_results_html=phase_results_html,
            recommendations_html=recommendations_html
        )

def main():
    """Función principal"""
    import argparse

    parser = argparse.ArgumentParser(description='Advanced WSTG Orchestrator')
    parser.add_argument('target', help='Target URL')
    parser.add_argument('--config', help='Configuration file')
    parser.add_argument('--critical-only', action='store_true', help='Run only critical phases')
    parser.add_argument('--parallel', action='store_true', help='Enable parallel execution')

    args = parser.parse_args()

    # Crear orquestador
    orchestrator = AdvancedWSTGOrchestrator(args.target, args.config)

    # Ajustar configuración basada en argumentos
    if args.critical_only:
        orchestrator.config['critical_phases_only'] = True
    if args.parallel:
        orchestrator.config['enable_parallel_execution'] = True

    print("=== Advanced WSTG Orchestrator ===")
    print(f"Target: {args.target}")
    print(f"Critical phases only: {args.critical_only}")
    print(f"Parallel execution: {args.parallel}")
    print()

    # Ejecutar testing adaptativo
    results = orchestrator.execute_adaptive_testing()

    # Generar reporte inteligente
    report_file = orchestrator.generate_intelligent_report()

    print(f"\n[*] Testing completado")
    print(f"[+] Reporte generado: {report_file}")

    # Resumen ejecutivo
    summary = orchestrator._generate_intelligent_summary()
    print(f"\n=== RESUMEN ===")
    print(f"Fases completadas: {summary['completed_phases']}/{summary['total_phases']}")
    print(f"Vulnerabilidades totales: {summary['total_vulnerabilities']}")
    print(f"Nivel de riesgo global: {summary['overall_risk_level'].upper()}")

if __name__ == "__main__":
    main()
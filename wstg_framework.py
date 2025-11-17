#!/usr/bin/env python3
"""
OWASP WSTG Framework - Main Orchestration Script
Autor: Framework OWASP WSTG
Propósito: Script principal unificado para orquestar todas las fases del testing

Este es el script principal que permite ejecutar el framework completo
o fases específicas del OWASP Web Security Testing Guide.

Uso:
  # Ejecutar todas las fases
  python wstg_framework.py --target example.com --phase all

  # Ejecutar fases específicas
  python wstg_framework.py --target example.com --phase info,conf,auth

  # Ejecutar fase individual
  python wstg_framework.py --target example.com --phase info

  # Análisis rápido
  python wstg_framework.py --target example.com --recon

  # Planificación basada en descubrimientos
  python wstg_framework.py --target example.com --plan
"""

import sys
import os
import json
import time
import argparse
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
import importlib

# Agregar el directorio actual al path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.base_tester import BaseTester, TestResult
from core.utils import NetworkUtils, DataUtils

# Configuración de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('wstg_framework.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class WSTGFramework:
    """
    Clase principal del framework WSTG

    Orquesta todas las fases del testing framework, gestiona dependencias
    entre fases, y genera reportes integrados.
    """

    def __init__(self, target: str, config: Dict[str, Any] = None):
        self.target = target
        self.config = config or {}

        # Fases disponibles del framework
        self.phases = {
            'info': {
                'id': 'WSTG-INFO',
                'name': 'Information Gathering',
                'class': 'info_tester.InformationGatheringTester',
                'module_path': '01-Information_Gathering.info_tester',
                'priority': 1,
                'dependencies': [],
                'quick_mode': True
            },
            'conf': {
                'id': 'WSTG-CONF',
                'name': 'Configuration and Deployment Management',
                'class': 'ConfigurationTester',
                'module_path': '02-Configuration_and_Deployment_Management.configuration_tester',
                'priority': 2,
                'dependencies': ['info'],
                'quick_mode': True
            },
            'idnt': {
                'id': 'WSTG-IDNT',
                'name': 'Identity Management',
                'class': 'IdentityManagementTester',
                'module_path': '03-Identity_Management.identity_management_testing',
                'priority': 3,
                'dependencies': ['info'],
                'quick_mode': False
            },
            'athn': {
                'id': 'WSTG-ATHN',
                'name': 'Authentication Testing',
                'class': 'AuthenticationTester',
                'module_path': '04-Authentication_Testing.authentication_tester',
                'priority': 4,
                'dependencies': ['info', 'idnt'],
                'quick_mode': False
            },
            'athz': {
                'id': 'WSTG-ATHZ',
                'name': 'Authorization Testing',
                'class': 'AuthorizationTester',
                'module_path': '05-Authorization_Testing.authorization_tester',
                'priority': 5,
                'dependencies': ['info', 'athn'],
                'quick_mode': False
            },
            'sess': {
                'id': 'WSTG-SESS',
                'name': 'Session Management Testing',
                'class': 'SessionTester',
                'module_path': '06-Session_Management.session_tester',
                'priority': 6,
                'dependencies': ['info', 'athn'],
                'quick_mode': False
            },
            'inpv': {
                'id': 'WSTG-INPV',
                'name': 'Input Validation Testing',
                'class': 'InputValidationTester',
                'module_path': '07-Input_Validation.input_validation_tester',
                'priority': 7,
                'dependencies': ['info'],
                'quick_mode': False
            },
            'errh': {
                'id': 'WSTG-ERRH',
                'name': 'Error Handling',
                'class': 'ErrorHandlingTester',
                'module_path': '08-Error_Handling.error_tester',
                'priority': 8,
                'dependencies': ['info'],
                'quick_mode': True
            },
            'cryp': {
                'id': 'WSTG-CRYP',
                'name': 'Cryptography',
                'class': 'CryptographyTester',
                'module_path': '09-Cryptography.cryptography_tester',
                'priority': 9,
                'dependencies': ['info'],
                'quick_mode': True
            },
            'busl': {
                'id': 'WSTG-BUSL',
                'name': 'Business Logic',
                'class': 'BusinessLogicTester',
                'module_path': '10-Business_Logic.business_logic_tester',
                'priority': 10,
                'dependencies': ['info', 'athn', 'athz'],
                'quick_mode': False
            },
            'clnt': {
                'id': 'WSTG-CLNT',
                'name': 'Client-side Testing',
                'class': 'ClientSideTester',
                'module_path': '11-Client_Side.client_side_tester',
                'priority': 11,
                'dependencies': ['info'],
                'quick_mode': True
            },
            'apit': {
                'id': 'WSTG-APIT',
                'name': 'API Testing',
                'class': 'APITester',
                'module_path': '12-API_Testing.api_tester',
                'priority': 12,
                'dependencies': ['info'],
                'quick_mode': False
            }
        }

        # Estado global de la ejecución
        self.global_state = {
            'target': target,
            'start_time': datetime.now(),
            'session_id': f"wstg_session_{int(time.time())}",
            'phases_completed': [],
            'findings': {
                'technologies': [],
                'subdomains': [],
                'endpoints': [],
                'vulnerabilities': []
            },
            'configuration': config
        }

        logger.info(f"Framework WSTG inicializado para target: {target}")

    def run_phase(self, phase_key: str, shared_data: Dict[str, Any] = None) -> Optional[Dict[str, Any]]:
        """
        Ejecuta una fase específica del framework

        Args:
            phase_key: Key de la fase (ej: 'info', 'conf')
            shared_data: Datos compartidos entre fases

        Returns:
            Resultados de la fase o None si hay error
        """
        if phase_key not in self.phases:
            logger.error(f"Fase no reconocida: {phase_key}")
            return None

        phase_info = self.phases[phase_key]
        logger.info(f"Ejecutando fase {phase_info['id']} - {phase_info['name']}")

        try:
            # Importar el tester de la fase
            module = importlib.import_module(phase_info['module_path'])
            tester_class = getattr(module, phase_info['class'])

            # Crear instancia del tester con datos compartidos
            config = self.config.copy()
            if shared_data:
                config['shared_data'] = shared_data

            with tester_class(self.target, config) as tester:
                # Ejecutar pruebas
                success = tester.run_tests()

                if success:
                    results = tester.results

                    # Agregar información global
                    results['framework_session_id'] = self.global_state['session_id']
                    results['phase_priority'] = phase_info['priority']

                    # Actualizar estado global
                    self.global_state['phases_completed'].append(phase_key)

                    # Extraer hallazgos relevantes para compartir con otras fases
                    if 'global_findings' in results:
                        self._update_global_findings(results['global_findings'])

                    logger.info(f"Fase {phase_info['id']} completada exitosamente")
                    return results
                else:
                    logger.error(f"Error ejecutando fase {phase_info['id']}")
                    return None

        except ImportError as e:
            logger.error(f"No se pudo importar el módulo para fase {phase_key}: {e}")
            logger.info(f"Creando tester genérico para fase {phase_key}")
            return self._create_generic_phase_result(phase_key)

        except Exception as e:
            logger.error(f"Error inesperado en fase {phase_key}: {e}")
            return None

    def run_phases(self, phase_keys: List[str], parallel: bool = False,
                  shared_data: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Ejecuta múltiples fases

        Args:
            phase_keys: Lista de keys de fases a ejecutar
            parallel: Si se ejecutan en paralelo (cuando no hay dependencias)
            shared_data: Datos compartidos entre fases

        Returns:
            Resultados consolidados
        """
        logger.info(f"Ejecutando {len(phase_keys)} fases: {', '.join(phase_keys)}")

        # Ordenar fases por prioridad
        sorted_phases = sorted(phase_keys,
                             key=lambda p: self.phases[p]['priority'] if p in self.phases else 999)

        if parallel and self._can_run_parallel(sorted_phases):
            return self._run_phases_parallel(sorted_phases, shared_data)
        else:
            return self._run_phases_sequential(sorted_phases, shared_data)

    def _can_run_parallel(self, phase_keys: List[str]) -> bool:
        """Verifica si las fases pueden ejecutarse en paralelo"""
        for phase_key in phase_keys:
            if phase_key in self.phases:
                dependencies = self.phases[phase_key]['dependencies']
                # Si una fase tiene dependencias que están en la lista actual, no puede ser paralelo
                if any(dep in phase_keys for dep in dependencies):
                    return False
        return True

    def _run_phases_sequential(self, phase_keys: List[str],
                             shared_data: Dict[str, Any] = None) -> Dict[str, Any]:
        """Ejecuta fases en modo secuencial"""
        all_results = {}
        cumulative_data = shared_data or {}

        for phase_key in phase_keys:
            logger.info(f"Executando fase secuencial: {phase_key}")

            # Verificar dependencias
            if phase_key in self.phases:
                dependencies = self.phases[phase_key]['dependencies']
                missing_deps = [dep for dep in dependencies if dep not in self.global_state['phases_completed']]

                if missing_deps:
                    logger.warning(f"Fase {phase_key} depende de: {missing_deps}. Ejecutando dependencias primero.")
                    for dep in missing_deps:
                        if dep in self.phases:
                            dep_result = self.run_phase(dep, cumulative_data)
                            if dep_result:
                                all_results[dep] = dep_result

            # Ejecutar la fase
            result = self.run_phase(phase_key, cumulative_data)
            if result:
                all_results[phase_key] = result

                # Actualizar datos compartidos con hallazgos de esta fase
                if 'findings' in result:
                    cumulative_data.update(result['findings'])

        return all_results

    def _run_phases_parallel(self, phase_keys: List[str],
                           shared_data: Dict[str, Any] = None) -> Dict[str, Any]:
        """Ejecuta fases en modo paralelo"""
        all_results = {}

        with ThreadPoolExecutor(max_workers=4) as executor:
            # Enviar todas las fases para ejecución en paralelo
            future_to_phase = {
                executor.submit(self.run_phase, phase_key, shared_data): phase_key
                for phase_key in phase_keys
            }

            # Recoger resultados
            for future in as_completed(future_to_phase):
                phase_key = future_to_phase[future]
                try:
                    result = future.result()
                    if result:
                        all_results[phase_key] = result
                        logger.info(f"Fase paralela completada: {phase_key}")
                except Exception as e:
                    logger.error(f"Error en fase paralela {phase_key}: {e}")

        return all_results

    def run_recon(self) -> Dict[str, Any]:
        """
        Ejecuta reconocimiento rápido (solo Information Gathering)
        """
        logger.info("Ejecutando reconocimiento rápido")

        # Solo Information Gathering en modo rápido
        config = self.config.copy()
        config['quick_mode'] = True

        recon_result = self.run_phase('info', config)
        if recon_result:
            return {
                'reconnaissance': recon_result,
                'recommendations': self._generate_recon_recommendations(recon_result)
            }
        return {}

    def run_planning(self) -> Dict[str, Any]:
        """
        Ejecuta planificación basada en reconocimiento previo
        """
        logger.info("Ejecutando planificación")

        # Primero hacer reconocimiento
        recon_result = self.run_recon()
        if not recon_result:
            return {'error': 'No se pudo completar el reconocimiento'}

        # Analizar resultados para planificar fases recomendadas
        recommendations = self._analyze_recon_for_planning(recon_result)

        return {
            'reconnaissance': recon_result,
            'planning': recommendations,
            'recommended_phases': recommendations['phases'],
            'estimated_time': recommendations['estimated_time']
        }

    def _update_global_findings(self, findings: Dict[str, Any]):
        """Actualiza los hallazgos globales del framework"""
        for category, items in findings.items():
            if category in self.global_state['findings']:
                if isinstance(items, list):
                    self.global_state['findings'][category].extend(items)
                    # Eliminar duplicados
                    self.global_state['findings'][category] = list(set(self.global_state['findings'][category]))

    def _generate_recon_recommendations(self, recon_result: Dict[str, Any]) -> List[str]:
        """Genera recomendaciones basadas en resultados de reconocimiento"""
        recommendations = []

        # Analizar tecnologías encontradas
        if 'technologies' in recon_result:
            tech = recon_result['technologies']
            if 'WordPress' in tech:
                recommendations.append("Considerar testing específico para WordPress")
            if 'Apache' in tech:
                recommendations.append("Revisar configuración de Apache")

        # Analizar puertos y servicios
        if 'open_ports' in recon_result:
            if 443 in recon_result['open_ports']:
                recommendations.append("HTTPS detectado - priorizar testing de criptografía")

        return recommendations

    def _analyze_recon_for_planning(self, recon_result: Dict[str, Any]) -> Dict[str, Any]:
        """Analiza resultados de reconocimiento para planificar fases"""
        recommended_phases = ['info', 'conf']  # Siempre recomendadas

        # Basado en tecnologías encontradas
        if 'technologies' in recon_result:
            tech = recon_result['technologies']
            if any(t in tech for t in ['WordPress', 'Drupal', 'Joomla']):
                recommended_phases.extend(['idnt', 'athn', 'athz'])

        # Basado en servicios encontrados
        if 'admin_interfaces' in recon_result and recon_result['admin_interfaces']:
            recommended_phases.extend(['idnt', 'athn', 'athz'])

        # Basado en endpoints encontrados
        if 'api_endpoints' in recon_result and recon_result['api_endpoints']:
            recommended_phases.append('apit')

        # Estimar tiempo (simplificado)
        estimated_time = len(recommended_phases) * 15  # 15 minutos por fase en promedio

        return {
            'phases': recommended_phases,
            'estimated_time': estimated_time,
            'priority': 'high' if 'admin_interfaces' in recon_result else 'medium',
            'complexity': 'medium'
        }

    def _create_generic_phase_result(self, phase_key: str) -> Dict[str, Any]:
        """Crea un resultado genérico cuando el módulo no está disponible"""
        phase_info = self.phases[phase_key]

        return {
            'target': self.target,
            'timestamp': datetime.now().isoformat(),
            'session_id': self.global_state['session_id'],
            'phase': phase_info['id'],
            'phase_name': phase_info['name'],
            'test_results': [
                TestResult(
                    test_id=f"{phase_info['id']}-GENERIC",
                    test_name=f"Generic {phase_info['name']} Test",
                    status='warning',
                    severity='info',
                    description=f"El módulo específico para {phase_info['name']} no está disponible",
                    evidence={'message': 'Module not implemented'},
                    recommendation='Implementar el módulo específico para esta fase'
                ).__dict__
            ],
            'summary': {
                'total_tests': 1,
                'by_status': {'warning': 1},
                'by_severity': {'info': 1},
                'total_vulnerabilities': 0
            },
            'metadata': {
                'module_missing': True,
                'phase_priority': phase_info['priority']
            }
        }

    def generate_integrated_report(self, all_results: Dict[str, Any],
                                 output_dir: str = ".", formats: List[str] = None) -> List[str]:
        """
        Genera un reporte integrado de todas las fases ejecutadas

        Args:
            all_results: Resultados de todas las fases
            output_dir: Directorio de salida
            formats: Formatos de reporte ('json', 'html', 'pdf', 'csv')

        Returns:
            Lista de archivos generados
        """
        if formats is None:
            formats = ['json', 'html']

        generated_files = []
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_filename = f"wstg_integrated_report_{self.target}_{timestamp}"

        # Consolidar todos los resultados
        integrated_report = {
            'metadata': {
                'framework_version': '1.0.0',
                'target': self.target,
                'session_id': self.global_state['session_id'],
                'start_time': self.global_state['start_time'].isoformat(),
                'end_time': datetime.now().isoformat(),
                'total_duration': (datetime.now() - self.global_state['start_time']).total_seconds(),
                'phases_executed': list(all_results.keys())
            },
            'global_findings': self.global_state['findings'],
            'phases': all_results,
            'executive_summary': self._generate_executive_summary(all_results),
            'recommendations': self._generate_integrated_recommendations(all_results)
        }

        # Generar reporte JSON
        if 'json' in formats:
            json_file = f"{output_dir}/{base_filename}.json"
            with open(json_file, 'w', encoding='utf-8') as f:
                json.dump(integrated_report, f, indent=2, ensure_ascii=False)
            generated_files.append(json_file)

        # Generar reporte HTML
        if 'html' in formats:
            html_file = f"{output_dir}/{base_filename}.html"
            self._generate_html_report(integrated_report, html_file)
            generated_files.append(html_file)

        # Generar reporte CSV (para vulnerabilidades)
        if 'csv' in formats:
            csv_file = f"{output_dir}/{base_filename}_vulnerabilities.csv"
            self._generate_csv_report(integrated_report, csv_file)
            generated_files.append(csv_file)

        logger.info(f"Reportes generados: {generated_files}")
        return generated_files

    def _generate_executive_summary(self, all_results: Dict[str, Any]) -> Dict[str, Any]:
        """Genera un resumen ejecutivo de todos los resultados"""
        total_vulnerabilities = 0
        critical_vulns = 0
        high_vulns = 0
        medium_vulns = 0
        low_vulns = 0

        phase_summaries = {}

        for phase_key, phase_result in all_results.items():
            if 'summary' in phase_result:
                summary = phase_result['summary']
                phase_summaries[phase_key] = summary

                total_vulnerabilities += summary.get('total_vulnerabilities', 0)
                critical_vulns += summary.get('critical_vulnerabilities', 0)
                high_vulns += summary.get('high_vulnerabilities', 0)
                medium_vulns += summary.get('medium_vulnerabilities', 0)
                low_vulns += summary.get('low_vulnerabilities', 0)

        # Calcular risk score
        risk_score = (critical_vulns * 9 + high_vulns * 6 + medium_vulns * 3 + low_vulns * 1) / max(total_vulnerabilities, 1)

        risk_level = 'Low'
        if risk_score >= 7:
            risk_level = 'Critical'
        elif risk_score >= 5:
            risk_level = 'High'
        elif risk_score >= 3:
            risk_level = 'Medium'

        return {
            'total_phases': len(all_results),
            'total_vulnerabilities': total_vulnerabilities,
            'vulnerabilities_by_severity': {
                'critical': critical_vulns,
                'high': high_vulns,
                'medium': medium_vulns,
                'low': low_vulns
            },
            'risk_score': round(risk_score, 1),
            'risk_level': risk_level,
            'phase_summaries': phase_summaries
        }

    def _generate_integrated_recommendations(self, all_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Genera recomendaciones integradas basadas en todos los resultados"""
        recommendations = []

        # Recolectar todas las recomendaciones de las fases
        for phase_key, phase_result in all_results.items():
            if 'test_results' in phase_result:
                for test_result in phase_result['test_results']:
                    if test_result.get('recommendation'):
                        recommendations.append({
                            'phase': phase_key,
                            'test_id': test_result.get('test_id'),
                            'severity': test_result.get('severity', 'medium'),
                            'recommendation': test_result['recommendation'],
                            'priority': self._calculate_recommendation_priority(test_result.get('severity', 'medium'))
                        })

        # Ordenar por prioridad
        recommendations.sort(key=lambda x: x['priority'], reverse=True)

        # Agregar recomendaciones generales
        if self.global_state['findings']['technologies']:
            recommendations.append({
                'phase': 'general',
                'test_id': 'TECH_UPDATES',
                'severity': 'medium',
                'recommendation': 'Mantener todas las tecnologías actualizadas y parcheadas',
                'priority': 5
            })

        return recommendations

    def _calculate_recommendation_priority(self, severity: str) -> int:
        """Calcula prioridad numérica basada en severidad"""
        priority_map = {
            'critical': 9,
            'high': 7,
            'medium': 5,
            'low': 3,
            'info': 1
        }
        return priority_map.get(severity.lower(), 3)

    def _generate_html_report(self, integrated_report: Dict[str, Any], output_file: str):
        """Genera reporte en formato HTML"""
        html_template = """
<!DOCTYPE html>
<html>
<head>
    <title>WSTG Security Report - {target}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background-color: #f0f0f0; padding: 20px; border-radius: 5px; }}
        .summary {{ margin: 20px 0; }}
        .vulnerability {{ border: 1px solid #ddd; margin: 10px 0; padding: 10px; }}
        .critical {{ border-left: 5px solid #d32f2f; }}
        .high {{ border-left: 5px solid #f57c00; }}
        .medium {{ border-left: 5px solid #fbc02d; }}
        .low {{ border-left: 5px solid #388e3c; }}
        .phase {{ margin: 20px 0; }}
        .phase-header {{ background-color: #e3f2fd; padding: 10px; font-weight: bold; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>OWASP WSTG Security Report</h1>
        <p><strong>Target:</strong> {target}</p>
        <p><strong>Date:</strong> {date}</p>
        <p><strong>Risk Level:</strong> {risk_level}</p>
    </div>

    <div class="summary">
        <h2>Executive Summary</h2>
        <p><strong>Total Vulnerabilities:</strong> {total_vulns}</p>
        <p><strong>Critical:</strong> {critical} | <strong>High:</strong> {high} | <strong>Medium:</strong> {medium} | <strong>Low:</strong> {low}</p>
    </div>

    <div>
        <h2>Phase Results</h2>
        {phase_results}
    </div>

    <div>
        <h2>Recommendations</h2>
        {recommendations}
    </div>
</body>
</html>
        """

        # Preparar contenido dinámico
        exec_summary = integrated_report['executive_summary']
        phase_results_html = ""
        recommendations_html = ""

        # Generar HTML para cada fase
        for phase_key, phase_result in integrated_report['phases'].items():
            phase_name = self.phases.get(phase_key, {}).get('name', phase_key)
            phase_results_html += f"""
            <div class="phase">
                <div class="phase-header">{phase_name}</div>
                <p>Tests executed: {phase_result.get('summary', {}).get('total_tests', 0)}</p>
                <p>Vulnerabilities found: {phase_result.get('summary', {}).get('total_vulnerabilities', 0)}</p>
            </div>
            """

        # Generar HTML para recomendaciones
        for rec in integrated_report['recommendations'][:10]:  # Top 10
            recommendations_html += f"<p><strong>{rec['severity'].upper()}:</strong> {rec['recommendation']}</p>"

        # Formatear template
        html_content = html_template.format(
            target=integrated_report['metadata']['target'],
            date=integrated_report['metadata']['end_time'],
            risk_level=exec_summary['risk_level'],
            total_vulns=exec_summary['total_vulnerabilities'],
            critical=exec_summary['vulnerabilities_by_severity']['critical'],
            high=exec_summary['vulnerabilities_by_severity']['high'],
            medium=exec_summary['vulnerabilities_by_severity']['medium'],
            low=exec_summary['vulnerabilities_by_severity']['low'],
            phase_results=phase_results_html,
            recommendations=recommendations_html
        )

        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)

    def _generate_csv_report(self, integrated_report: Dict[str, Any], output_file: str):
        """Genera reporte CSV de vulnerabilidades"""
        import csv

        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['phase', 'test_id', 'severity', 'description', 'recommendation', 'cwe_id']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

            writer.writeheader()

            for phase_key, phase_result in integrated_report['phases'].items():
                if 'test_results' in phase_result:
                    for test_result in phase_result['test_results']:
                        if test_result.get('status') == 'fail':
                            writer.writerow({
                                'phase': phase_key,
                                'test_id': test_result.get('test_id', ''),
                                'severity': test_result.get('severity', ''),
                                'description': test_result.get('description', ''),
                                'recommendation': test_result.get('recommendation', ''),
                                'cwe_id': test_result.get('cwe_id', '')
                            })

def main():
    """Función principal del framework"""
    parser = argparse.ArgumentParser(
        description='OWASP WSTG Testing Framework - Security Testing Orchestration',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run complete assessment
  python wstg_framework.py --target example.com --phase all

  # Run specific phases
  python wstg_framework.py --target example.com --phase info,conf,auth

  # Quick reconnaissance
  python wstg_framework.py --target example.com --recon

  # Plan assessment based on reconnaissance
  python wstg_framework.py --target example.com --plan

  # Run with custom configuration
  python wstg_framework.py --target example.com --phase info --config timeout=30,delay=2
        """
    )

    parser.add_argument('--target', required=True,
                       help='Target domain or IP (ej: example.com)')
    parser.add_argument('--phase', default='all',
                       help='Phases to run (comma-separated): info,conf,idnt,athn,athz,sess,inpv,errh,cryp,busl,clnt,apit,all')
    parser.add_argument('--recon', action='store_true',
                       help='Run quick reconnaissance only')
    parser.add_argument('--plan', action='store_true',
                       help='Run planning based on reconnaissance')
    parser.add_argument('--parallel', action='store_true',
                       help='Run phases in parallel when possible')
    parser.add_argument('--config', default='',
                       help='Configuration options (key=value,key=value)')
    parser.add_argument('--output-dir', default='.',
                       help='Output directory for reports (default: current directory)')
    parser.add_argument('--format', default='html,json',
                       help='Report formats (comma-separated): json,html,csv,pdf')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Verbose output')

    args = parser.parse_args()

    # Parse configuration
    config = {}
    if args.config:
        for pair in args.config.split(','):
            if '=' in pair:
                key, value = pair.split('=', 1)
                # Intentar convertir a tipo apropiado
                if value.isdigit():
                    config[key] = int(value)
                elif value.replace('.', '').isdigit():
                    config[key] = float(value)
                else:
                    config[key] = value

    # Configurar logging
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    try:
        # Crear instancia del framework
        framework = WSTGFramework(args.target, config)

        print(f"\n{'='*60}")
        print(f"OWASP WSTG Testing Framework")
        print(f"Target: {args.target}")
        print(f"Session ID: {framework.global_state['session_id']}")
        print(f"{'='*60}")

        start_time = time.time()

        # Determinar modo de ejecución
        if args.recon:
            print("\n[*] Modo: Reconocimiento Rápido")
            results = {'recon': framework.run_recon()}

        elif args.plan:
            print("\n[*] Modo: Planificación")
            results = framework.run_planning()

        else:
            # Modo normal de testing
            if args.phase == 'all':
                phase_keys = list(framework.phases.keys())
                print("\n[*] Modo: Testing Completo (Todas las fases)")
            else:
                phase_keys = [p.strip().lower() for p in args.phase.split(',')]
                print(f"\n[*] Modo: Testing Específico - Fases: {', '.join(phase_keys)}")

            # Validar fases
            valid_phases = []
            invalid_phases = []
            for phase_key in phase_keys:
                if phase_key in framework.phases:
                    valid_phases.append(phase_key)
                else:
                    invalid_phases.append(phase_key)

            if invalid_phases:
                print(f"\n[!] Fases no reconocidas: {', '.join(invalid_phases)}")
                print(f"[*] Fases disponibles: {', '.join(framework.phases.keys())}")

            if not valid_phases:
                print("\n[!] No hay fases válidas para ejecutar")
                sys.exit(1)

            # Ejecutar fases
            results = framework.run_phases(valid_phases, parallel=args.parallel)

        # Calcular tiempo total
        end_time = time.time()
        duration = end_time - start_time
        print(f"\n[*] Ejecución completada en {duration:.2f} segundos")

        # Generar reporte integrado
        if results:
            print("\n[*] Generando reportes...")
            formats = [f.strip().lower() for f in args.format.split(',')]
            generated_files = framework.generate_integrated_report(
                results, args.output_dir, formats
            )

            print("\n[+] Reportes generados:")
            for file_path in generated_files:
                print(f"    - {file_path}")

            # Mostrar resumen rápido
            if 'executive_summary' in results.get('reconnaissance', {}) or any('summary' in result for result in results.values()):
                print("\n" + "="*60)
                print("RESUMEN EJECUTIVO")
                print("="*60)

                total_vulns = 0
                critical = 0
                high = 0

                for phase_result in results.values():
                    if 'summary' in phase_result:
                        summary = phase_result['summary']
                        total_vulns += summary.get('total_vulnerabilities', 0)
                        critical += summary.get('critical_vulnerabilities', 0)
                        high += summary.get('high_vulnerabilities', 0)

                print(f"Total de vulnerabilidades: {total_vulns}")
                print(f"Críticas: {critical}")
                print(f"Altas: {high}")

                if critical > 0:
                    print("\n⚠️  SE DETECTARON VULNERABILIDADES CRÍTICAS - REQUIEREN ATENCIÓN INMEDIATA")
                elif high > 0:
                    print("\n⚠️  Se detectaron vulnerabilidades altas - Se recomienda atención prioritaria")
                else:
                    print("\n✅ No se detectaron vulnerabilidades críticas o altas")

        else:
            print("\n[!] No se generaron resultados")

        print(f"\n[*] Session ID: {framework.global_state['session_id']}")
        print("[*] Framework WSTG completado")

    except KeyboardInterrupt:
        print("\n[!] Prueba interrumpida por el usuario")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Error en ejecución del framework: {e}", exc_info=args.verbose)
        print(f"\n[!] Error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
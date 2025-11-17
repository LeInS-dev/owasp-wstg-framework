#!/usr/bin/env python3
"""
Base Testing Framework for OWASP WSTG
Clase base que proporciona funcionalidades comunes para todos los testers

Este módulo implementa la funcionalidad core compartida entre todas las fases
del testing framework OWASP WSTG.
"""

import abc
import json
import time
import sys
import requests
import random
from datetime import datetime
from urllib.parse import urljoin, urlparse
from typing import Dict, List, Any, Optional
import logging
from dataclasses import dataclass, asdict

# Configuración de logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

@dataclass
class TestResult:
    """Estructura estándar para resultados de pruebas"""
    test_id: str
    test_name: str
    status: str  # 'pass', 'fail', 'warning', 'error'
    severity: str  # 'critical', 'high', 'medium', 'low', 'info'
    description: str
    evidence: Dict[str, Any]
    recommendation: Optional[str] = None
    references: List[str] = None
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None

@dataclass
class TargetInfo:
    """Información sobre el objetivo"""
    target: str
    base_url: str
    domain: str
    ip_addresses: List[str] = None
    technologies: List[str] = None
    subdomains: List[str] = None
    session_id: str = None

class BaseTester(abc.ABC):
    """
    Clase base abstracta para todos los testers de fases OWASP WSTG

    Proporciona funcionalidad común:
    - Gestión de sesiones HTTP
    - Sistema de reportes
    - Manejo de errores
    - Cache de resultados
    - User Agents rotativos
    - Rate limiting
    """

    def __init__(self, target: str, config: Dict[str, Any] = None):
        self.target = target
        self.config = config or {}

        # Configuración por defecto
        self.default_timeout = self.config.get('timeout', 10)
        self.max_retries = self.config.get('max_retries', 3)
        self.delay_between_requests = self.config.get('delay', 1)

        # Inicializar información del target
        self.target_info = TargetInfo(
            target=target,
            base_url=self._normalize_url(target),
            domain=self._extract_domain(target),
            session_id=self._generate_session_id()
        )

        # Configurar sesión HTTP
        self.session = self._setup_session()

        # Resultados
        self.results = {
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'session_id': self.target_info.session_id,
            'phase': self.get_phase_id(),
            'test_results': [],
            'summary': {},
            'metadata': {
                'tester_version': '1.0.0',
                'start_time': datetime.now().isoformat()
            }
        }

        # Cache para evitar escaneos duplicados
        self.cache = {}

        logger.info(f"Inicializado tester para fase {self.get_phase_id()} - Target: {target}")

    def _normalize_url(self, target: str) -> str:
        """Normaliza la URL del objetivo"""
        if target.startswith(('http://', 'https://')):
            return target
        return f"https://{target}"

    def _extract_domain(self, target: str) -> str:
        """Extrae el dominio del objetivo"""
        parsed = urlparse(self._normalize_url(target))
        return parsed.netloc

    def _generate_session_id(self) -> str:
        """Genera un ID único para la sesión de testing"""
        return f"wstg_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{random.randint(1000, 9999)}"

    def _setup_session(self) -> requests.Session:
        """Configura la sesión HTTP con parámetros seguros"""
        session = requests.Session()

        # Headers por defecto
        session.headers.update({
            'User-Agent': self._get_random_user_agent(),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        })

        # Configuración de seguridad
        session.verify = False  # Para testing, en producción应该是True

        # Configuración de timeouts y retries
        session.timeout = self.default_timeout

        return session

    def _get_random_user_agent(self) -> str:
        """Retorna un User Agent aleatorio para evitar detección"""
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0',
        ]
        return random.choice(user_agents)

    @abc.abstractmethod
    def get_phase_id(self) -> str:
        """Retorna el ID de la fase (ej: WSTG-INFO)"""
        pass

    @abc.abstractmethod
    def get_phase_name(self) -> str:
        """Retorna el nombre de la fase (ej: Information Gathering)"""
        pass

    def make_request(self, method: str, url: str, **kwargs) -> Optional[requests.Response]:
        """
        Realiza una petición HTTP con reintentos y rate limiting
        """
        url = urljoin(self.target_info.base_url, url)

        # Rate limiting
        if self.delay_between_requests > 0:
            time.sleep(self.delay_between_requests)

        # Rotar User Agent
        if random.random() < 0.3:  # 30% de probabilidad de cambiar
            self.session.headers['User-Agent'] = self._get_random_user_agent()

        for attempt in range(self.max_retries):
            try:
                logger.debug(f"Petición {method.upper()} {url} (intentó {attempt + 1})")
                response = self.session.request(method, url, timeout=self.default_timeout, **kwargs)

                # Verificar si no somos bloqueados
                if self._is_blocked(response):
                    logger.warning(f"Posible bloqueo detectado en {url}")
                    self._handle_block()
                    continue

                return response

            except requests.exceptions.Timeout:
                logger.warning(f"Timeout en petición a {url} (intentó {attempt + 1})")
                if attempt == self.max_retries - 1:
                    return None
                time.sleep(2 ** attempt)  # Exponential backoff

            except requests.exceptions.ConnectionError:
                logger.warning(f"Error de conexión a {url} (intentó {attempt + 1})")
                if attempt == self.max_retries - 1:
                    return None
                time.sleep(2 ** attempt)

            except Exception as e:
                logger.error(f"Error inesperado en petición a {url}: {e}")
                return None

        return None

    def _is_blocked(self, response: requests.Response) -> bool:
        """Verifica si hemos sido bloqueados"""
        block_indicators = [
            response.status_code == 403,
            response.status_code == 429,
            'captcha' in response.text.lower(),
            'blocked' in response.text.lower(),
            'rate limit' in response.text.lower(),
            'too many requests' in response.text.lower(),
            len(response.content) < 100 and response.status_code == 200,  # Posible CAPTCHA page
        ]
        return any(block_indicators)

    def _handle_block(self):
        """Maneja situaciones de bloqueo"""
        # Aumentar delay
        self.delay_between_requests = min(self.delay_between_requests * 2, 10)

        # Cambiar User Agent
        self.session.headers['User-Agent'] = self._get_random_user_agent()

        # Rotar headers si es necesario
        if 'Referer' in self.session.headers:
            del self.session.headers['Referer']

    def add_test_result(self, test_result: TestResult):
        """Agrega un resultado de prueba al reporte"""
        self.results['test_results'].append(asdict(test_result))

        # Logging del resultado
        status_icon = {
            'pass': '✓',
            'fail': '✗',
            'warning': '⚠',
            'error': '❌'
        }.get(test_result.status, '?')

        logger.info(f"{status_icon} {test_result.test_id}: {test_result.description}")

    def add_vulnerability(self, test_id: str, description: str, evidence: Dict,
                         severity: str = 'medium', cwe_id: str = None, cvss_score: float = None):
        """Método de conveniencia para agregar vulnerabilidades"""
        test_result = TestResult(
            test_id=test_id,
            test_name=f"Vulnerability - {test_id}",
            status='fail',
            severity=severity,
            description=description,
            evidence=evidence,
            cwe_id=cwe_id,
            cvss_score=cvss_score
        )
        self.add_test_result(test_result)

    def add_info(self, test_id: str, description: str, evidence: Dict):
        """Método de conveniencia para agregar información"""
        test_result = TestResult(
            test_id=test_id,
            test_name=f"Info - {test_id}",
            status='pass',
            severity='info',
            description=description,
            evidence=evidence
        )
        self.add_test_result(test_result)

    def generate_summary(self) -> Dict[str, Any]:
        """Genera un resumen de los resultados"""
        total_tests = len(self.results['test_results'])

        summary = {
            'total_tests': total_tests,
            'by_status': {},
            'by_severity': {},
            'critical_vulnerabilities': 0,
            'high_vulnerabilities': 0,
            'medium_vulnerabilities': 0,
            'low_vulnerabilities': 0,
            'total_vulnerabilities': 0
        }

        # Contar por estado y severidad
        for result in self.results['test_results']:
            status = result.get('status', 'unknown')
            severity = result.get('severity', 'info')

            summary['by_status'][status] = summary['by_status'].get(status, 0) + 1
            summary['by_severity'][severity] = summary['by_severity'].get(severity, 0) + 1

            # Contar vulnerabilidades
            if status == 'fail':
                summary['total_vulnerabilities'] += 1
                if severity == 'critical':
                    summary['critical_vulnerabilities'] += 1
                elif severity == 'high':
                    summary['high_vulnerabilities'] += 1
                elif severity == 'medium':
                    summary['medium_vulnerabilities'] += 1
                elif severity == 'low':
                    summary['low_vulnerabilities'] += 1

        self.results['summary'] = summary
        return summary

    def save_results(self, output_dir: str = ".", format: str = "both"):
        """
        Guarda los resultados en múltiples formatos

        Args:
            output_dir: Directorio donde guardar los resultados
            format: Formato de salida ('json', 'text', 'both')
        """
        # Generar resumen
        self.generate_summary()

        # Agregar metadata final
        self.results['metadata']['end_time'] = datetime.now().isoformat()
        self.results['metadata']['duration'] = (
            datetime.fromisoformat(self.results['metadata']['end_time']) -
            datetime.fromisoformat(self.results['metadata']['start_time'])
        ).total_seconds()

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_filename = f"{self.get_phase_id().lower()}_{self.target_info.domain}_{timestamp}"

        # Guardar JSON
        if format in ['json', 'both']:
            json_file = f"{output_dir}/{base_filename}.json"
            with open(json_file, 'w', encoding='utf-8') as f:
                json.dump(self.results, f, indent=2, ensure_ascii=False)
            logger.info(f"Resultados JSON guardados en: {json_file}")

        # Guardar texto plano
        if format in ['text', 'both']:
            txt_file = f"{output_dir}/{base_filename}.txt"
            with open(txt_file, 'w', encoding='utf-8') as f:
                self._write_text_report(f)
            logger.info(f"Reporte de texto guardado en: {txt_file}")

    def _write_text_report(self, file_handle):
        """Escribe el reporte en formato texto plano"""
        file_handle.write(f"{'='*60}\n")
        file_handle.write(f"OWASP WSTG - {self.get_phase_name()} Testing Report\n")
        file_handle.write(f"{'='*60}\n\n")

        # Información del objetivo
        file_handle.write(f"Target: {self.results['target']}\n")
        file_handle.write(f"Phase: {self.get_phase_id()} - {self.get_phase_name()}\n")
        file_handle.write(f"Session ID: {self.results['session_id']}\n")
        file_handle.write(f"Timestamp: {self.results['timestamp']}\n\n")

        # Resumen
        if 'summary' in self.results:
            summary = self.results['summary']
            file_handle.write("SUMMARY\n")
            file_handle.write("-" * 7 + "\n")
            file_handle.write(f"Total Tests: {summary['total_tests']}\n")
            file_handle.write(f"Total Vulnerabilities: {summary['total_vulnerabilities']}\n")
            file_handle.write(f"Critical: {summary['critical_vulnerabilities']}\n")
            file_handle.write(f"High: {summary['high_vulnerabilities']}\n")
            file_handle.write(f"Medium: {summary['medium_vulnerabilities']}\n")
            file_handle.write(f"Low: {summary['low_vulnerabilities']}\n\n")

        # Resultados detallados
        file_handle.write("DETAILED RESULTS\n")
        file_handle.write("-" * 16 + "\n")

        for i, result in enumerate(self.results['test_results'], 1):
            file_handle.write(f"\n{i}. {result['test_id']}\n")
            file_handle.write(f"   Status: {result['status'].upper()}\n")
            file_handle.write(f"   Severity: {result['severity'].upper()}\n")
            file_handle.write(f"   Description: {result['description']}\n")

            if result['evidence']:
                file_handle.write("   Evidence:\n")
                for key, value in result['evidence'].items():
                    file_handle.write(f"     - {key}: {value}\n")

            if result.get('recommendation'):
                file_handle.write(f"   Recommendation: {result['recommendation']}\n")

            if result.get('cwe_id'):
                file_handle.write(f"   CWE: {result['cwe_id']}\n")

            file_handle.write("-" * 40 + "\n")

    @abc.abstractmethod
    def run_tests(self) -> bool:
        """
        Ejecuta todas las pruebas de la fase

        Returns:
            bool: True si las pruebas se completaron exitosamente
        """
        pass

    def cleanup(self):
        """Limpia recursos utilizados"""
        if hasattr(self, 'session'):
            self.session.close()
        logger.info(f"Limpieza completada para fase {self.get_phase_id()}")

    def __enter__(self):
        """Context manager entry"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.cleanup()
#!/usr/bin/env python3
"""
Professional Report Generator
Generador de reportes HTML/CSS profesionales con visualizaciones
"""

import json
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any
import base64

class ProfessionalReportGenerator:
    """Generador de reportes profesionales con estilo enterprise"""

    def __init__(self):
        self.template_css = self._get_professional_css()
        self.template_js = self._get_interactive_js()

    def _get_professional_css(self) -> str:
        """CSS profesional para reportes enterprise"""
        return """
        <style>
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }

            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                line-height: 1.6;
                color: #333;
                background-color: #f8f9fa;
            }

            .container {
                max-width: 1200px;
                margin: 0 auto;
                padding: 20px;
            }

            .header {
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                padding: 40px 20px;
                text-align: center;
                border-radius: 10px;
                margin-bottom: 30px;
                box-shadow: 0 10px 30px rgba(0,0,0,0.1);
            }

            .header h1 {
                font-size: 2.5em;
                margin-bottom: 10px;
                font-weight: 300;
            }

            .header .subtitle {
                font-size: 1.2em;
                opacity: 0.9;
            }

            .executive-summary {
                background: white;
                padding: 30px;
                border-radius: 10px;
                margin-bottom: 30px;
                box-shadow: 0 5px 20px rgba(0,0,0,0.1);
            }

            .metrics-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                gap: 20px;
                margin-bottom: 30px;
            }

            .metric-card {
                background: white;
                padding: 25px;
                border-radius: 10px;
                text-align: center;
                box-shadow: 0 5px 20px rgba(0,0,0,0.1);
                transition: transform 0.3s ease;
            }

            .metric-card:hover {
                transform: translateY(-5px);
            }

            .metric-number {
                font-size: 2.5em;
                font-weight: bold;
                margin-bottom: 10px;
            }

            .metric-label {
                font-size: 1.1em;
                color: #666;
            }

            .risk-critical { color: #e74c3c; }
            .risk-high { color: #f39c12; }
            .risk-medium { color: #3498db; }
            .risk-low { color: #27ae60; }

            .section {
                background: white;
                margin-bottom: 30px;
                border-radius: 10px;
                box-shadow: 0 5px 20px rgba(0,0,0,0.1);
                overflow: hidden;
            }

            .section-header {
                background: linear-gradient(135deg, #74b9ff 0%, #0984e3 100%);
                color: white;
                padding: 20px 30px;
                font-size: 1.5em;
                font-weight: 500;
            }

            .section-content {
                padding: 30px;
            }

            .phase-card {
                border: 1px solid #e0e0e0;
                border-radius: 8px;
                margin-bottom: 20px;
                overflow: hidden;
            }

            .phase-header {
                background: #f8f9fa;
                padding: 15px 20px;
                border-bottom: 1px solid #e0e0e0;
                display: flex;
                justify-content: space-between;
                align-items: center;
            }

            .phase-name {
                font-weight: 600;
                font-size: 1.1em;
            }

            .phase-status {
                padding: 5px 12px;
                border-radius: 20px;
                font-size: 0.9em;
                font-weight: 500;
            }

            .status-completed {
                background: #d4edda;
                color: #155724;
            }

            .status-failed {
                background: #f8d7da;
                color: #721c24;
            }

            .status-skipped {
                background: #fff3cd;
                color: #856404;
            }

            .phase-details {
                padding: 20px;
            }

            .vulnerability-list {
                margin-top: 15px;
            }

            .vulnerability-item {
                border-left: 4px solid;
                padding: 15px 20px;
                margin-bottom: 15px;
                background: #f8f9fa;
                border-radius: 0 5px 5px 0;
            }

            .vulnerability-critical { border-left-color: #e74c3c; }
            .vulnerability-high { border-left-color: #f39c12; }
            .vulnerability-medium { border-left-color: #3498db; }
            .vulnerability-low { border-left-color: #27ae60; }

            .vulnerability-title {
                font-weight: 600;
                font-size: 1.1em;
                margin-bottom: 5px;
            }

            .vulnerability-description {
                color: #666;
                margin-bottom: 10px;
            }

            .recommendation-box {
                background: #e8f5e8;
                border-left: 4px solid #27ae60;
                padding: 15px 20px;
                margin-top: 10px;
                border-radius: 0 5px 5px 0;
            }

            .timeline {
                position: relative;
                padding: 20px 0;
            }

            .timeline-item {
                padding: 20px;
                margin-bottom: 20px;
                background: #f8f9fa;
                border-radius: 8px;
                position: relative;
            }

            .timeline-date {
                font-weight: bold;
                color: #3498db;
                margin-bottom: 5px;
            }

            .charts-container {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
                gap: 20px;
                margin: 20px 0;
            }

            .chart-card {
                background: white;
                padding: 20px;
                border-radius: 8px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            }

            .progress-bar {
                width: 100%;
                height: 20px;
                background: #ecf0f1;
                border-radius: 10px;
                overflow: hidden;
                margin: 10px 0;
            }

            .progress-fill {
                height: 100%;
                background: linear-gradient(90deg, #3498db, #2ecc71);
                transition: width 0.3s ease;
            }

            .tag {
                display: inline-block;
                padding: 3px 8px;
                background: #ecf0f1;
                border-radius: 3px;
                font-size: 0.85em;
                margin: 2px;
            }

            .severity-critical { background: #e74c3c; color: white; }
            .severity-high { background: #f39c12; color: white; }
            .severity-medium { background: #3498db; color: white; }
            .severity-low { background: #27ae60; color: white; }

            .collapsible {
                cursor: pointer;
                user-select: none;
            }

            .collapsible:hover {
                background: #f1f2f6;
            }

            .content {
                display: none;
                overflow: hidden;
            }

            .show {
                display: block;
            }

            .footer {
                text-align: center;
                padding: 40px 20px;
                color: #666;
                border-top: 1px solid #e0e0e0;
                margin-top: 50px;
            }

            .risk-indicator {
                display: inline-block;
                width: 12px;
                height: 12px;
                border-radius: 50%;
                margin-right: 8px;
            }

            .risk-indicator-critical { background: #e74c3c; }
            .risk-indicator-high { background: #f39c12; }
            .risk-indicator-medium { background: #3498db; }
            .risk-indicator-low { background: #27ae60; }

            @media (max-width: 768px) {
                .container {
                    padding: 10px;
                }

                .header h1 {
                    font-size: 2em;
                }

                .metrics-grid {
                    grid-template-columns: 1fr;
                }

                .charts-container {
                    grid-template-columns: 1fr;
                }
            }

            @print {
                body {
                    background: white;
                }

                .section {
                    box-shadow: none;
                    border: 1px solid #ddd;
                    page-break-inside: avoid;
                }

                .metric-card {
                    page-break-inside: avoid;
                }
            }
        </style>
        """

    def _get_interactive_js(self) -> str:
        """JavaScript para interactividad"""
        return """
        <script>
            function toggleContent(id) {
                var content = document.getElementById(id);
                var icon = document.getElementById('icon-' + id);

                if (content.classList.contains('show')) {
                    content.classList.remove('show');
                    icon.textContent = '+';
                } else {
                    content.classList.add('show');
                    icon.textContent = '-';
                }
            }

            function showTab(tabName) {
                // Hide all tab contents
                var tabContents = document.querySelectorAll('.tab-content');
                tabContents.forEach(function(content) {
                    content.style.display = 'none';
                });

                // Remove active class from all tab buttons
                var tabButtons = document.querySelectorAll('.tab-button');
                tabButtons.forEach(function(button) {
                    button.classList.remove('active');
                });

                // Show selected tab content
                document.getElementById(tabName + '-content').style.display = 'block';

                // Add active class to clicked tab button
                event.target.classList.add('active');
            }

            // Initialize when DOM is loaded
            document.addEventListener('DOMContentLoaded', function() {
                // Add click handlers to collapsible elements
                var collapsibles = document.querySelectorAll('.collapsible');
                collapsibles.forEach(function(collapsible) {
                    collapsible.addEventListener('click', function() {
                        var content = this.nextElementSibling;
                        content.classList.toggle('show');
                    });
                });

                // Animate progress bars
                var progressBars = document.querySelectorAll('.progress-fill');
                progressBars.forEach(function(bar) {
                    var width = bar.style.width || bar.getAttribute('data-width');
                    bar.style.width = '0%';
                    setTimeout(function() {
                        bar.style.width = width;
                    }, 100);
                });
            });
        </script>
        """

    def generate_professional_report(self, report_data: Dict) -> str:
        """Generar reporte profesional completo"""
        html_content = self._generate_html_structure(report_data)
        return html_content

    def _generate_html_structure(self, data: Dict) -> str:
        """Genera la estructura HTML completa"""
        summary = data.get('summary', {})
        results = data.get('results', {})
        target = data.get('target', 'Unknown')

        html = f"""
        <!DOCTYPE html>
        <html lang="es">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>WSTG Security Report - {target}</title>
            {self.template_css}
            {self.template_js}
        </head>
        <body>
            <div class="container">
                <!-- Header -->
                <div class="header">
                    <h1>OWASP WSTG Security Assessment</h1>
                    <div class="subtitle">Professional Security Testing Report</div>
                    <p style="margin-top: 20px; font-size: 1.1em;">
                        <strong>Target:</strong> {target}<br>
                        <strong>Date:</strong> {datetime.now().strftime('%B %d, %Y %H:%M')}<br>
                        <strong>Assessment ID:</strong> WSTG-{int(time.time())}
                    </p>
                </div>

                <!-- Executive Summary -->
                <div class="executive-summary">
                    <h2 style="margin-bottom: 20px; color: #2c3e50;">Executive Summary</h2>
                    <div class="metrics-grid">
                        {self._generate_metric_cards(summary)}
                    </div>
                    <div style="margin-top: 30px;">
                        <h3 style="color: #2c3e50; margin-bottom: 15px;">Risk Assessment Overview</h3>
                        {self._generate_risk_overview(summary)}
                    </div>
                </div>

                <!-- Phase Results -->
                <div class="section">
                    <div class="section-header">Phase-by-Phase Analysis</div>
                    <div class="section-content">
                        {self._generate_phase_results(results)}
                    </div>
                </div>

                <!-- Critical Findings -->
                <div class="section">
                    <div class="section-header">Critical Findings & Recommendations</div>
                    <div class="section-content">
                        {self._generate_critical_findings(results)}
                    </div>
                </div>

                <!-- Remediation Roadmap -->
                <div class="section">
                    <div class="section-header">Remediation Roadmap</div>
                    <div class="section-content">
                        {self._generate_remediation_roadmap(results)}
                    </div>
                </div>

                <!-- Technical Details -->
                <div class="section">
                    <div class="section-header">Technical Analysis</div>
                    <div class="section-content">
                        {self._generate_technical_details(data)}
                    </div>
                </div>

                <!-- Footer -->
                <div class="footer">
                    <p>This report was generated using OWASP WSTG Framework</p>
                    <p style="margin-top: 10px; font-size: 0.9em; color: #999;">
                        Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} |
                        Assessment Duration: N/A |
                        Compliance: OWASP WSTG v4.2
                    </p>
                </div>
            </div>
        </body>
        </html>
        """
        return html

    def _generate_metric_cards(self, summary: Dict) -> str:
        """Genera las tarjetas de métricas"""
        total_phases = summary.get('total_phases', 12)
        completed_phases = summary.get('completed_phases', 0)
        total_vulns = summary.get('total_vulnerabilities', 0)
        critical_vulns = summary.get('critical_vulnerabilities', 0)
        completion_rate = summary.get('completion_rate', 0)

        overall_risk = summary.get('overall_risk_level', 'low')

        risk_class = f"risk-{overall_risk}"
        risk_color = {
            'critical': '#e74c3c',
            'high': '#f39c12',
            'medium': '#3498db',
            'low': '#27ae60'
        }.get(overall_risk, '#95a5a6')

        return f"""
        <div class="metric-card">
            <div class="metric-number">{total_phases}</div>
            <div class="metric-label">Total WSTG Phases</div>
        </div>
        <div class="metric-card">
            <div class="metric-number">{completed_phases}</div>
            <div class="metric-label">Phases Completed</div>
        </div>
        <div class="metric-card">
            <div class="metric-number">{completion_rate:.1f}%</div>
            <div class="metric-label">Completion Rate</div>
            <div class="progress-bar">
                <div class="progress-fill" style="width: {completion_rate}%; background: linear-gradient(90deg, #3498db, #2ecc71);"></div>
            </div>
        </div>
        <div class="metric-card">
            <div class="metric-number {risk_class}">{total_vulns}</div>
            <div class="metric-label">Total Vulnerabilities</div>
        </div>
        <div class="metric-card risk-critical">
            <div class="metric-number">{critical_vulns}</div>
            <div class="metric-label">Critical Issues</div>
        </div>
        <div class="metric-card">
            <div class="metric-number" style="color: {risk_color}; font-size: 1.5em;">{overall_risk.upper()}</div>
            <div class="metric-label">Overall Risk Level</div>
        </div>
        """

    def _generate_risk_overview(self, summary: Dict) -> str:
        """Genera el overview de riesgo"""
        overall_risk = summary.get('overall_risk_level', 'low')
        total_vulns = summary.get('total_vulnerabilities', 0)
        critical_vulns = summary.get('critical_vulnerabilities', 0)
        high_vulns = summary.get('high_vulnerabilities', 0)

        risk_descriptions = {
            'critical': {
                'description': 'CRITICAL - Immediate action required. System contains severe vulnerabilities that could lead to complete compromise.',
                'color': '#e74c3c',
                'actions': ['Shut down affected systems', 'Apply emergency patches', 'Incident response activation']
            },
            'high': {
                'description': 'HIGH - Significant security risks present. Urgent remediation required to prevent potential breaches.',
                'color': '#f39c12',
                'actions': ['Prioritize remediation', 'Temporary mitigations', 'Enhanced monitoring']
            },
            'medium': {
                'description': 'MEDIUM - Security issues present that should be addressed. Moderate risk to organization.',
                'color': '#3498db',
                'actions': ['Schedule remediation', 'Update security policies', 'User training']
            },
            'low': {
                'description': 'LOW - Minor security issues found. Good security posture with room for improvement.',
                'color': '#27ae60',
                'actions': ['Continue monitoring', 'Security hardening', 'Regular assessments']
            }
        }

        risk_info = risk_descriptions.get(overall_risk, risk_descriptions['low'])

        return f"""
        <div style="border-left: 5px solid {risk_info['color']}; padding: 20px; background: #f8f9fa; border-radius: 5px;">
            <div style="display: flex; align-items: center; margin-bottom: 15px;">
                <div class="risk-indicator risk-indicator-{overall_risk}"></div>
                <h3 style="margin: 0; color: {risk_info['color']};">Risk Level: {overall_risk.upper()}</h3>
            </div>
            <p style="margin-bottom: 15px; font-size: 1.1em;">{risk_info['description']}</p>

            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-top: 20px;">
                <div style="background: white; padding: 15px; border-radius: 5px; text-align: center;">
                    <div style="font-size: 1.8em; font-weight: bold; color: #e74c3c;">{critical_vulns}</div>
                    <div style="color: #666;">Critical</div>
                </div>
                <div style="background: white; padding: 15px; border-radius: 5px; text-align: center;">
                    <div style="font-size: 1.8em; font-weight: bold; color: #f39c12;">{high_vulns}</div>
                    <div style="color: #666;">High</div>
                </div>
                <div style="background: white; padding: 15px; border-radius: 5px; text-align: center;">
                    <div style="font-size: 1.8em; font-weight: bold; color: #3498db;">{total_vulns - critical_vulns - high_vulns}</div>
                    <div style="color: #666;">Medium/Low</div>
                </div>
            </div>

            <div style="margin-top: 20px;">
                <h4 style="margin-bottom: 10px;">Recommended Actions:</h4>
                <ul style="margin: 0; padding-left: 20px;">
                    {''.join([f'<li>{action}</li>' for action in risk_info['actions']])}
                </ul>
            </div>
        </div>
        """

    def _generate_phase_results(self, results: Dict) -> str:
        """Genera los resultados por fase"""
        html = ""

        phase_order = [
            '01-Information_Gathering',
            '02-Configuration_and_Deployment_Management',
            '03-Identity_Management',
            '04-Authentication_Testing',
            '05-Authorization_Testing',
            '06-Session_Management',
            '07-Input_Validation',
            '08-Error_Handling',
            '09-Cryptography',
            '10-Business_Logic',
            '11-Client_Side',
            '12-API_Testing'
        ]

        for phase_name in phase_order:
            if phase_name in results:
                result = results[phase_name]
                html += self._generate_phase_card(phase_name, result)

        return html

    def _generate_phase_card(self, phase_name: str, result: Dict) -> str:
        """Genera una tarjeta de fase"""
        phase_display_name = phase_name.replace('-', ' - ').replace('_', ' ').title()

        status_class = 'status-completed' if result.get('success') else 'status-failed'
        status_text = 'Completed' if result.get('success') else 'Failed'

        vulnerabilities = result.get('vulnerabilities', [])
        critical_count = len([v for v in vulnerabilities if v.get('risk_level') == 'Critical'])
        high_count = len([v for v in vulnerabilities if v.get('risk_level') == 'High'])

        return f"""
        <div class="phase-card">
            <div class="phase-header">
                <div class="phase-name">{phase_display_name}</div>
                <div>
                    <span class="phase-status {status_class}">{status_text}</span>
                    {f'<span class="tag severity-critical">{critical_count} Critical</span>' if critical_count > 0 else ''}
                    {f'<span class="tag severity-high">{high_count} High</span>' if high_count > 0 else ''}
                </div>
            </div>
            <div class="phase-details">
                {self._generate_vulnerability_list(vulnerabilities)}
                {self._generate_phase_summary(result)}
            </div>
        </div>
        """

    def _generate_vulnerability_list(self, vulnerabilities: List) -> str:
        """Genera la lista de vulnerabilidades"""
        if not vulnerabilities:
            return '<p style="color: #27ae60; font-weight: 500;">✅ No security issues found in this phase.</p>'

        html = '<div class="vulnerability-list">'

        # Priorizar vulnerabilidades críticas primero
        critical_vulns = [v for v in vulnerabilities if v.get('risk_level') == 'Critical']
        high_vulns = [v for v in vulnerabilities if v.get('risk_level') == 'High']
        medium_vulns = [v for v in vulnerabilities if v.get('risk_level') == 'Medium']
        low_vulns = [v for v in vulnerabilities if v.get('risk_level') == 'Low']

        for vuln in critical_vulns + high_vulns + medium_vulns + low_vulns[:3]:  # Limitar a 3 de baja severidad
            risk_class = f"vulnerability-{vuln.get('risk_level', 'low').lower()}"

            html += f"""
            <div class="vulnerability-item {risk_class}">
                <div class="vulnerability-title">
                    {vuln.get('test_name', 'Unknown Test')}
                    <span style="float: right; font-size: 0.9em; color: #666;">
                        Risk: {vuln.get('risk_level', 'Unknown').upper()}
                    </span>
                </div>
                <div class="vulnerability-description">
                    {vuln.get('description', 'No description available')}
                </div>
                {self._generate_recommendation_box(vuln.get('recommendations', []))}
            </div>
            """

        if len(vulnerabilities) > len(critical_vulns + high_vulns + medium_vulns + 3):
            html += f'<p style="text-align: center; color: #666; margin-top: 15px;">... and {len(vulnerabilities) - len(critical_vulns + high_vulns + medium_vulns + 3)} more findings</p>'

        html += '</div>'
        return html

    def _generate_recommendation_box(self, recommendations: List) -> str:
        """Genera caja de recomendaciones"""
        if not recommendations:
            return ""

        return f"""
        <div class="recommendation-box">
            <strong>🔧 Recommendations:</strong>
            <ul style="margin: 10px 0 0 20px;">
                {''.join([f'<li>{rec}</li>' for rec in recommendations[:3]])}
                {f'<li>... and {len(recommendations) - 3} more recommendations</li>' if len(recommendations) > 3 else ''}
            </ul>
        </div>
        """

    def _generate_phase_summary(self, result: Dict) -> str:
        """Genera resumen de la fase"""
        if not result.get('success'):
            return f'<p style="color: #e74c3c; margin-top: 15px;">❌ <strong>Execution Failed:</strong> {result.get("error", "Unknown error")}</p>'

        test_count = result.get('test_count', 0)
        if test_count > 0:
            return f'<p style="color: #666; margin-top: 15px;"><strong>Tests Executed:</strong> {test_count} | <strong>Status:</strong> ✅ All tests completed successfully</p>'

        return '<p style="color: #666; margin-top: 15px;"><strong>Status:</strong> ✅ Phase completed successfully</p>'

    def _generate_critical_findings(self, results: Dict) -> str:
        """Genera hallazgos críticos consolidados"""
        all_vulnerabilities = []

        for phase_name, result in results.items():
            if result.get('success') and result.get('vulnerabilities'):
                for vuln in result['vulnerabilities']:
                    vuln['phase'] = phase_name
                    all_vulnerabilities.append(vuln)

        # Filtrar vulnerabilidades críticas y altas
        critical_vulns = [v for v in all_vulnerabilities if v.get('risk_level') == 'Critical']
        high_vulns = [v for v in all_vulnerabilities if v.get('risk_level') == 'High']

        if not critical_vulns and not high_vulns:
            return '<div style="text-align: center; padding: 40px; color: #27ae60;"><h3>✅ No Critical or High Severity Issues Found</h3><p>Great security posture! Continue regular monitoring and maintenance.</p></div>'

        html = '<div style="margin-bottom: 30px;">'

        if critical_vulns:
            html += f'<h3 style="color: #e74c3c; margin-bottom: 20px;">🚨 Critical Issues ({len(critical_vulns)})</h3>'
            for vuln in critical_vulns:
                html += self._generate_critical_finding_card(vuln)

        if high_vulns:
            html += f'<h3 style="color: #f39c12; margin-bottom: 20px; margin-top: 30px;">⚠️ High Priority Issues ({len(high_vulns)})</h3>'
            for vuln in high_vulns[:5]:  # Limitar a 5 vulnerabilidades altas
                html += self._generate_critical_finding_card(vuln)
            if len(high_vulns) > 5:
                html += f'<p style="text-align: center; color: #666;">... and {len(high_vulns) - 5} more high-priority findings</p>'

        html += '</div>'
        return html

    def _generate_critical_finding_card(self, vulnerability: Dict) -> str:
        """Genera tarjeta de hallazgo crítico"""
        return f"""
        <div style="background: white; border: 1px solid #e0e0e0; border-left: 5px solid #e74c3c; border-radius: 5px; padding: 20px; margin-bottom: 20px;">
            <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 10px;">
                <h4 style="margin: 0; color: #2c3e50;">{vulnerability.get('test_name', 'Unknown Issue')}</h4>
                <span class="tag severity-critical">CRITICAL</span>
            </div>
            <p style="color: #666; margin-bottom: 15px;">{vulnerability.get('description', 'No description available')}</p>
            <div style="background: #fff5f5; padding: 15px; border-radius: 5px; border-left: 3px solid #e74c3c;">
                <strong>🛡️ Immediate Action Required:</strong>
                <ul style="margin: 10px 0 0 20px;">
                    {self._generate_immediate_actions(vulnerability)}
                </ul>
            </div>
        </div>
        """

    def _generate_immediate_actions(self, vulnerability: Dict) -> str:
        """Genera acciones inmediatas"""
        recommendations = vulnerability.get('recommendations', [])
        if not recommendations:
            return '<li>Contact security team for immediate assessment</li><li>Implement temporary mitigation measures</li>'

        return ''.join([f'<li>{rec}</li>' for rec in recommendations[:3]])

    def _generate_remediation_roadmap(self, results: Dict) -> str:
        """Genera roadmap de remediación"""
        return """
        <div class="timeline">
            <div class="timeline-item">
                <div class="timeline-date">🔥 Immediate (0-24 hours)</div>
                <h4>Critical Issue Remediation</h4>
                <ul>
                    <li>Apply emergency patches for critical vulnerabilities</li>
                    <li>Implement network segmentation if needed</li>
                    <li>Activate incident response team</li>
                    <li>Temporary mitigation measures</li>
                </ul>
            </div>

            <div class="timeline-item">
                <div class="timeline-date">⚡ Short Term (1-2 weeks)</div>
                <h4>High Priority Fixes</h4>
                <ul>
                    <li>Address high-severity vulnerabilities</li>
                    <li>Update security configurations</li>
                    <li>Implement additional security controls</li>
                    <li>Security awareness training</li>
                </ul>
            </div>

            <div class="timeline-item">
                <div class="timeline-date">📈 Medium Term (1-3 months)</div>
                <h4>Comprehensive Security Improvements</h4>
                <ul>
                    <li>Address medium-severity issues</li>
                    <li>Implement security monitoring</li>
                    <li>Regular security assessments</li>
                    <li>Security policy updates</li>
                </ul>
            </div>

            <div class="timeline-item">
                <div class="timeline-date">🔄 Long Term (3-6 months)</div>
                <h4>Strategic Security Initiatives</h4>
                <ul>
                    <li>Security architecture review</li>
                    <li>Implement advanced security controls</li>
                    <li>Continuous security monitoring</li>
                    <li>Security maturity improvement</li>
                </ul>
            </div>
        </div>
        """

    def _generate_technical_details(self, data: Dict) -> str:
        """Genera detalles técnicos"""
        return """
        <div style="background: #f8f9fa; padding: 20px; border-radius: 8px;">
            <h4>Assessment Details</h4>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin-top: 20px;">
                <div>
                    <strong>Framework Version:</strong> OWASP WSTG v4.2<br>
                    <strong>Testing Methodology:</strong> Gray Box Testing<br>
                    <strong>Compliance Standards:</strong> OWASP Top 10, NIST 800-115<br>
                    <strong>Assessment Type:</strong> Vulnerability Assessment
                </div>
                <div>
                    <strong>Tools Used:</strong> Custom Framework + Kali Linux Tools<br>
                    <strong>Testing Environment:</strong> Production/Staging<br>
                    <strong>Report Format:</strong> HTML + JSON<br>
                    <strong>Next Assessment:</strong> Recommended within 6 months
                </div>
            </div>
        </div>
        """

def main():
    """Función para testing"""
    # Datos de ejemplo
    sample_data = {
        'target': 'https://example.com',
        'summary': {
            'total_phases': 12,
            'completed_phases': 10,
            'total_vulnerabilities': 15,
            'critical_vulnerabilities': 2,
            'high_vulnerabilities': 5,
            'overall_risk_level': 'high',
            'completion_rate': 83.3
        },
        'results': {
            '04-Authentication_Testing': {
                'success': True,
                'vulnerabilities': [
                    {
                        'test_name': 'Weak Password Policy',
                        'risk_level': 'Critical',
                        'description': 'The application does not enforce strong password requirements',
                        'recommendations': [
                            'Implement minimum 8-character password length',
                            'Require complex passwords with special characters',
                            'Implement password history and rotation policies'
                        ]
                    }
                ]
            }
        }
    }

    generator = ProfessionalReportGenerator()
    html_report = generator.generate_professional_report(sample_data)

    with open('professional_security_report.html', 'w', encoding='utf-8') as f:
        f.write(html_report)

    print("[+] Reporte profesional generado: professional_security_report.html")

if __name__ == "__main__":
    main()
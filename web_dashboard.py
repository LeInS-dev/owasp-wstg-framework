#!/usr/bin/env python3
"""
Web Dashboard para WSTG Framework
Dashboard interactivo para visualización y gestión de resultados
"""

import json
import os
import time
from datetime import datetime, timedelta
from pathlib import Path
from flask import Flask, render_template, jsonify, request, send_file
from flask_cors import CORS
import sqlite3
import threading
from dataclasses import dataclass
from typing import List, Dict, Optional
import plotly.graph_objects as go
import plotly.utils
import base64

@dataclass
class ScanSession:
    """Clase para representar una sesión de scan"""
    id: str
    target: str
    status: str  # 'running', 'completed', 'failed', 'cancelled'
    start_time: datetime
    end_time: Optional[datetime]
    results: Dict
    progress: float

class WSTGWebDashboard:
    """Dashboard web para WSTG Framework"""

    def __init__(self, port=5000, host='127.0.0.1'):
        self.app = Flask(__name__)
        CORS(self.app)
        self.port = port
        self.host = host
        self.db_path = 'wstg_dashboard.db'
        self.active_sessions = {}
        self.templates_dir = Path(__file__).parent / 'dashboard_templates'

        # Crear directorio de templates
        self.templates_dir.mkdir(exist_ok=True)

        # Inicializar base de datos
        self._init_database()

        # Crear templates HTML
        self._create_templates()

        # Configurar rutas Flask
        self._setup_routes()

    def _init_database(self):
        """Inicializar base de datos SQLite"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_sessions (
                id TEXT PRIMARY KEY,
                target TEXT NOT NULL,
                status TEXT NOT NULL,
                start_time TEXT NOT NULL,
                end_time TEXT,
                results TEXT,
                progress REAL DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT,
                phase TEXT,
                vulnerability_type TEXT,
                risk_level TEXT,
                description TEXT,
                recommendations TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (session_id) REFERENCES scan_sessions (id)
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS phase_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT,
                phase_name TEXT,
                status TEXT,
                test_count INTEGER,
                vulnerability_count INTEGER,
                execution_time REAL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (session_id) REFERENCES scan_sessions (id)
            )
        ''')

        conn.commit()
        conn.close()

    def _create_templates(self):
        """Crear templates HTML para el dashboard"""
        # Template principal
        main_template = '''
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WSTG Security Dashboard</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #f5f6fa;
            color: #2c3e50;
        }

        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            text-align: center;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }

        .nav-tabs {
            display: flex;
            background: white;
            border-bottom: 1px solid #e0e0e0;
            padding: 0 20px;
        }

        .tab {
            padding: 15px 25px;
            cursor: pointer;
            border-bottom: 3px solid transparent;
            transition: all 0.3s ease;
        }

        .tab:hover {
            background: #f8f9fa;
        }

        .tab.active {
            border-bottom-color: #667eea;
            color: #667eea;
            font-weight: 600;
        }

        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }

        .dashboard-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }

        .card {
            background: white;
            border-radius: 10px;
            padding: 25px;
            box-shadow: 0 5px 20px rgba(0,0,0,0.1);
            transition: transform 0.3s ease;
        }

        .card:hover {
            transform: translateY(-5px);
        }

        .card h3 {
            margin-bottom: 15px;
            color: #2c3e50;
        }

        .metric-value {
            font-size: 2.5em;
            font-weight: bold;
            margin-bottom: 10px;
        }

        .metric-label {
            color: #7f8c8d;
            font-size: 1.1em;
        }

        .risk-critical { color: #e74c3c; }
        .risk-high { color: #f39c12; }
        .risk-medium { color: #3498db; }
        .risk-low { color: #27ae60; }

        .btn {
            padding: 12px 24px;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-size: 1em;
            transition: all 0.3s ease;
        }

        .btn-primary {
            background: #667eea;
            color: white;
        }

        .btn-primary:hover {
            background: #5a6fd8;
        }

        .btn-success {
            background: #27ae60;
            color: white;
        }

        .btn-danger {
            background: #e74c3c;
            color: white;
        }

        .progress-bar {
            width: 100%;
            height: 8px;
            background: #ecf0f1;
            border-radius: 4px;
            overflow: hidden;
            margin: 10px 0;
        }

        .progress-fill {
            height: 100%;
            background: linear-gradient(90deg, #3498db, #2ecc71);
            transition: width 0.3s ease;
        }

        .session-list {
            background: white;
            border-radius: 10px;
            padding: 25px;
            box-shadow: 0 5px 20px rgba(0,0,0,0.1);
        }

        .session-item {
            border-bottom: 1px solid #ecf0f1;
            padding: 20px 0;
        }

        .session-item:last-child {
            border-bottom: none;
        }

        .session-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }

        .session-target {
            font-weight: 600;
            font-size: 1.2em;
        }

        .session-status {
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 0.9em;
            font-weight: 500;
        }

        .status-running {
            background: #fff3cd;
            color: #856404;
        }

        .status-completed {
            background: #d4edda;
            color: #155724;
        }

        .status-failed {
            background: #f8d7da;
            color: #721c24;
        }

        .modal {
            display: none;
            position: fixed;
            z-index: 1000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.5);
        }

        .modal-content {
            background: white;
            margin: 5% auto;
            padding: 30px;
            border-radius: 10px;
            width: 90%;
            max-width: 600px;
        }

        .form-group {
            margin-bottom: 20px;
        }

        .form-group label {
            display: block;
            margin-bottom: 5px;
            font-weight: 500;
        }

        .form-group input, .form-group select, .form-group textarea {
            width: 100%;
            padding: 12px;
            border: 1px solid #ddd;
            border-radius: 6px;
            font-size: 1em;
        }

        .vulnerability-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }

        .vulnerability-table th,
        .vulnerability-table td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ecf0f1;
        }

        .vulnerability-table th {
            background: #f8f9fa;
            font-weight: 600;
        }

        .severity-badge {
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.85em;
            font-weight: 500;
        }

        .severity-critical { background: #e74c3c; color: white; }
        .severity-high { background: #f39c12; color: white; }
        .severity-medium { background: #3498db; color: white; }
        .severity-low { background: #27ae60; color: white; }

        .chart-container {
            height: 400px;
            margin: 20px 0;
        }

        .footer {
            text-align: center;
            padding: 30px 20px;
            color: #7f8c8d;
            border-top: 1px solid #ecf0f1;
            margin-top: 50px;
        }

        .loading {
            text-align: center;
            padding: 40px;
            color: #7f8c8d;
        }

        .hidden {
            display: none;
        }

        @media (max-width: 768px) {
            .container {
                padding: 10px;
            }

            .dashboard-grid {
                grid-template-columns: 1fr;
            }

            .nav-tabs {
                overflow-x: auto;
            }

            .tab {
                min-width: 120px;
            }
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ WSTG Security Dashboard</h1>
        <p>OWASP Web Security Testing Guide Framework</p>
    </div>

    <div class="nav-tabs">
        <div class="tab active" onclick="showTab('dashboard')">Dashboard</div>
        <div class="tab" onclick="showTab('sessions')">Scan Sessions</div>
        <div class="tab" onclick="showTab('vulnerabilities')">Vulnerabilities</div>
        <div class="tab" onclick="showTab('reports')">Reports</div>
    </div>

    <div class="container">
        <!-- Dashboard Tab -->
        <div id="dashboard-tab" class="tab-content">
            <div class="dashboard-grid">
                <div class="card">
                    <h3>Total Sessions</h3>
                    <div class="metric-value" id="total-sessions">0</div>
                    <div class="metric-label">Completed scans</div>
                </div>

                <div class="card">
                    <h3>Total Vulnerabilities</h3>
                    <div class="metric-value risk-high" id="total-vulnerabilities">0</div>
                    <div class="metric-label">Security issues found</div>
                </div>

                <div class="card">
                    <h3>Critical Issues</h3>
                    <div class="metric-value risk-critical" id="critical-issues">0</div>
                    <div class="metric-label">Require immediate attention</div>
                </div>

                <div class="card">
                    <h3>Active Scans</h3>
                    <div class="metric-value" id="active-scans">0</div>
                    <div class="metric-label">Currently running</div>
                </div>
            </div>

            <div style="display: grid; grid-template-columns: 2fr 1fr; gap: 20px;">
                <div class="card">
                    <h3>Recent Sessions</h3>
                    <div id="recent-sessions" class="loading">Loading...</div>
                </div>

                <div class="card">
                    <h3>Quick Actions</h3>
                    <button class="btn btn-primary" onclick="showNewScanModal()" style="width: 100%; margin-bottom: 10px;">
                        🚀 New Security Scan
                    </button>
                    <button class="btn btn-success" onclick="exportReports()" style="width: 100%; margin-bottom: 10px;">
                        📊 Export Reports
                    </button>
                    <button class="btn btn-danger" onclick="clearData()" style="width: 100%;">
                        🗑️ Clear All Data
                    </button>
                </div>
            </div>
        </div>

        <!-- Sessions Tab -->
        <div id="sessions-tab" class="tab-content hidden">
            <div class="card">
                <h3>Scan Sessions</h3>
                <div id="sessions-list" class="loading">Loading sessions...</div>
            </div>
        </div>

        <!-- Vulnerabilities Tab -->
        <div id="vulnerabilities-tab" class="tab-content hidden">
            <div class="card">
                <h3>Vulnerability Management</h3>
                <div id="vulnerabilities-list" class="loading">Loading vulnerabilities...</div>
            </div>
        </div>

        <!-- Reports Tab -->
        <div id="reports-tab" class="tab-content hidden">
            <div class="card">
                <h3>Security Reports</h3>
                <div id="reports-list" class="loading">Loading reports...</div>
            </div>
        </div>
    </div>

    <!-- New Scan Modal -->
    <div id="new-scan-modal" class="modal">
        <div class="modal-content">
            <h3>🚀 New Security Scan</h3>
            <form id="new-scan-form">
                <div class="form-group">
                    <label for="scan-target">Target URL:</label>
                    <input type="text" id="scan-target" name="target" placeholder="https://example.com" required>
                </div>

                <div class="form-group">
                    <label for="scan-type">Scan Type:</label>
                    <select id="scan-type" name="scan_type">
                        <option value="comprehensive">Comprehensive (All Phases)</option>
                        <option value="critical">Critical Phases Only</option>
                        <option value="quick">Quick Scan</option>
                        <option value="custom">Custom</option>
                    </select>
                </div>

                <div class="form-group">
                    <label for="scan-priority">Priority:</label>
                    <select id="scan-priority" name="priority">
                        <option value="normal">Normal</option>
                        <option value="high">High</option>
                        <option value="urgent">Urgent</option>
                    </select>
                </div>

                <div class="form-group">
                    <label for="scan-description">Description:</label>
                    <textarea id="scan-description" name="description" rows="3" placeholder="Optional scan description..."></textarea>
                </div>

                <div style="display: flex; gap: 10px; margin-top: 20px;">
                    <button type="submit" class="btn btn-primary">Start Scan</button>
                    <button type="button" class="btn" onclick="closeModal('new-scan-modal')" style="background: #95a5a6; color: white;">Cancel</button>
                </div>
            </form>
        </div>
    </div>

    <div class="footer">
        <p>WSTG Dashboard v1.0 | OWASP Web Security Testing Guide Framework</p>
        <p style="margin-top: 10px; font-size: 0.9em;">© 2024 - Built for Security Professionals</p>
    </div>

    <script>
        // Global variables
        let currentTab = 'dashboard';

        // Tab navigation
        function showTab(tabName) {
            // Hide all tabs
            document.querySelectorAll('.tab-content').forEach(tab => {
                tab.classList.add('hidden');
            });

            // Remove active class from all tabs
            document.querySelectorAll('.tab').forEach(tab => {
                tab.classList.remove('active');
            });

            // Show selected tab
            document.getElementById(tabName + '-tab').classList.remove('hidden');
            event.target.classList.add('active');

            currentTab = tabName;

            // Load tab-specific data
            loadTabData(tabName);
        }

        // Load tab-specific data
        function loadTabData(tabName) {
            switch(tabName) {
                case 'dashboard':
                    loadDashboardData();
                    break;
                case 'sessions':
                    loadSessionsData();
                    break;
                case 'vulnerabilities':
                    loadVulnerabilitiesData();
                    break;
                case 'reports':
                    loadReportsData();
                    break;
            }
        }

        // Load dashboard data
        async function loadDashboardData() {
            try {
                const response = await fetch('/api/dashboard/stats');
                const data = await response.json();

                document.getElementById('total-sessions').textContent = data.total_sessions || 0;
                document.getElementById('total-vulnerabilities').textContent = data.total_vulnerabilities || 0;
                document.getElementById('critical-issues').textContent = data.critical_issues || 0;
                document.getElementById('active-scans').textContent = data.active_scans || 0;

                // Load recent sessions
                loadRecentSessions();

            } catch (error) {
                console.error('Error loading dashboard data:', error);
            }
        }

        // Load recent sessions
        async function loadRecentSessions() {
            try {
                const response = await fetch('/api/sessions?limit=5');
                const sessions = await response.json();

                const container = document.getElementById('recent-sessions');
                if (sessions.length === 0) {
                    container.innerHTML = '<p style="text-align: center; color: #7f8c8d;">No sessions found</p>';
                    return;
                }

                container.innerHTML = sessions.map(session => `
                    <div class="session-item">
                        <div class="session-header">
                            <span class="session-target">${session.target}</span>
                            <span class="session-status status-${session.status}">${session.status}</span>
                        </div>
                        <div style="color: #7f8c8d; font-size: 0.9em;">
                            Started: ${new Date(session.start_time).toLocaleString()}
                        </div>
                        ${session.progress < 100 ? `
                            <div class="progress-bar">
                                <div class="progress-fill" style="width: ${session.progress}%"></div>
                            </div>
                        ` : ''}
                    </div>
                `).join('');

            } catch (error) {
                console.error('Error loading recent sessions:', error);
            }
        }

        // Load sessions data
        async function loadSessionsData() {
            try {
                const response = await fetch('/api/sessions');
                const sessions = await response.json();

                const container = document.getElementById('sessions-list');
                if (sessions.length === 0) {
                    container.innerHTML = '<p style="text-align: center; color: #7f8c8d;">No sessions found</p>';
                    return;
                }

                container.innerHTML = sessions.map(session => `
                    <div class="session-item">
                        <div class="session-header">
                            <span class="session-target">${session.target}</span>
                            <span class="session-status status-${session.status}">${session.status}</span>
                        </div>
                        <div style="color: #7f8c8d; font-size: 0.9em;">
                            Started: ${new Date(session.start_time).toLocaleString()}
                            ${session.end_time ? `<br>Ended: ${new Date(session.end_time).toLocaleString()}` : ''}
                        </div>
                        <div style="margin-top: 10px;">
                            <button class="btn btn-primary" onclick="viewSessionDetails('${session.id}')">View Details</button>
                            ${session.status === 'completed' ? `<button class="btn btn-success" onclick="downloadReport('${session.id}')">Download Report</button>` : ''}
                            ${session.status === 'running' ? `<button class="btn btn-danger" onclick="cancelSession('${session.id}')">Cancel</button>` : ''}
                        </div>
                    </div>
                `).join('');

            } catch (error) {
                console.error('Error loading sessions:', error);
            }
        }

        // Load vulnerabilities data
        async function loadVulnerabilitiesData() {
            try {
                const response = await fetch('/api/vulnerabilities');
                const vulnerabilities = await response.json();

                const container = document.getElementById('vulnerabilities-list');
                if (vulnerabilities.length === 0) {
                    container.innerHTML = '<p style="text-align: center; color: #27ae60;">🎉 No vulnerabilities found!</p>';
                    return;
                }

                container.innerHTML = `
                    <table class="vulnerability-table">
                        <thead>
                            <tr>
                                <th>Target</th>
                                <th>Phase</th>
                                <th>Type</th>
                                <th>Severity</th>
                                <th>Description</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${vulnerabilities.map(vuln => `
                                <tr>
                                    <td>${vuln.target}</td>
                                    <td>${vuln.phase}</td>
                                    <td>${vuln.vulnerability_type}</td>
                                    <td><span class="severity-badge severity-${vuln.risk_level.toLowerCase()}">${vuln.risk_level.toUpperCase()}</span></td>
                                    <td>${vuln.description.substring(0, 100)}...</td>
                                    <td>
                                        <button class="btn btn-primary" onclick="viewVulnerability('${vuln.id}')">Details</button>
                                    </td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                `;

            } catch (error) {
                console.error('Error loading vulnerabilities:', error);
            }
        }

        // Modal functions
        function showNewScanModal() {
            document.getElementById('new-scan-modal').style.display = 'block';
        }

        function closeModal(modalId) {
            document.getElementById(modalId).style.display = 'none';
        }

        // New scan form submission
        document.getElementById('new-scan-form').addEventListener('submit', async function(e) {
            e.preventDefault();

            const formData = new FormData(e.target);
            const data = Object.fromEntries(formData);

            try {
                const response = await fetch('/api/scans/start', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify(data)
                });

                if (response.ok) {
                    closeModal('new-scan-modal');
                    alert('Scan started successfully!');
                    loadDashboardData();
                } else {
                    alert('Error starting scan');
                }
            } catch (error) {
                console.error('Error starting scan:', error);
                alert('Error starting scan');
            }
        });

        // Initialize dashboard
        document.addEventListener('DOMContentLoaded', function() {
            loadDashboardData();
        });
    </script>
</body>
</html>
        '''

        with open(self.templates_dir / 'index.html', 'w') as f:
            f.write(main_template)

    def _setup_routes(self):
        """Configurar rutas Flask"""

        @self.app.route('/')
        def index():
            return send_file(self.templates_dir / 'index.html')

        @self.app.route('/api/dashboard/stats')
        def dashboard_stats():
            """API endpoint para estadísticas del dashboard"""
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute('SELECT COUNT(*) FROM scan_sessions')
            total_sessions = cursor.fetchone()[0]

            cursor.execute('SELECT COUNT(*) FROM vulnerabilities')
            total_vulnerabilities = cursor.fetchone()[0]

            cursor.execute('SELECT COUNT(*) FROM vulnerabilities WHERE risk_level = "Critical"')
            critical_issues = cursor.fetchone()[0]

            cursor.execute('SELECT COUNT(*) FROM scan_sessions WHERE status = "running"')
            active_scans = cursor.fetchone()[0]

            conn.close()

            return jsonify({
                'total_sessions': total_sessions,
                'total_vulnerabilities': total_vulnerabilities,
                'critical_issues': critical_issues,
                'active_scans': active_scans
            })

        @self.app.route('/api/sessions')
        def get_sessions():
            """API endpoint para obtener sesiones"""
            limit = request.args.get('limit', 50, type=int)
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute('''
                SELECT id, target, status, start_time, end_time, progress
                FROM scan_sessions
                ORDER BY start_time DESC
                LIMIT ?
            ''', (limit,))

            sessions = []
            for row in cursor.fetchall():
                sessions.append({
                    'id': row[0],
                    'target': row[1],
                    'status': row[2],
                    'start_time': row[3],
                    'end_time': row[4],
                    'progress': row[5] or 0
                })

            conn.close()
            return jsonify(sessions)

        @self.app.route('/api/vulnerabilities')
        def get_vulnerabilities():
            """API endpoint para obtener vulnerabilidades"""
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute('''
                SELECT v.id, s.target, v.phase, v.vulnerability_type, v.risk_level, v.description
                FROM vulnerabilities v
                JOIN scan_sessions s ON v.session_id = s.id
                ORDER BY v.risk_level DESC, v.created_at DESC
            ''')

            vulnerabilities = []
            for row in cursor.fetchall():
                vulnerabilities.append({
                    'id': row[0],
                    'target': row[1],
                    'phase': row[2],
                    'vulnerability_type': row[3],
                    'risk_level': row[4],
                    'description': row[5]
                })

            conn.close()
            return jsonify(vulnerabilities)

        @self.app.route('/api/scans/start', methods=['POST'])
        def start_scan():
            """API endpoint para iniciar nuevo scan"""
            data = request.get_json()

            if not data.get('target'):
                return jsonify({'error': 'Target URL is required'}), 400

            session_id = f"scan_{int(time.time())}"
            session = ScanSession(
                id=session_id,
                target=data['target'],
                status='running',
                start_time=datetime.now(),
                end_time=None,
                results={},
                progress=0
            )

            # Guardar en base de datos
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO scan_sessions (id, target, status, start_time, progress)
                VALUES (?, ?, ?, ?, ?)
            ''', (session.id, session.target, session.status, session.start_time.isoformat(), session.progress))
            conn.commit()
            conn.close()

            # Iniciar scan en background
            self.active_sessions[session_id] = session
            thread = threading.Thread(target=self._run_background_scan, args=(session, data))
            thread.start()

            return jsonify({'session_id': session_id, 'status': 'started'})

    def _run_background_scan(self, session: ScanSession, config: Dict):
        """Ejecutar scan en background"""
        try:
            # Importar el framework
            from advanced_wstg_orchestrator import AdvancedWSTGOrchestrator

            # Crear orquestador
            orchestrator = AdvancedWSTGOrchestrator(session.target)

            # Actualizar progreso
            session.progress = 10
            self._update_session_progress(session.id, session.progress)

            # Ejecutar scanning
            results = orchestrator.execute_adaptive_testing()

            session.status = 'completed'
            session.end_time = datetime.now()
            session.results = results
            session.progress = 100

            # Guardar resultados en base de datos
            self._save_scan_results(session, results)

        except Exception as e:
            session.status = 'failed'
            session.end_time = datetime.now()
            print(f"Scan failed for {session.target}: {e}")

        finally:
            # Actualizar estado final
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE scan_sessions
                SET status = ?, end_time = ?, progress = ?, results = ?
                WHERE id = ?
            ''', (session.status, session.end_time.isoformat() if session.end_time else None,
                  session.progress, json.dumps(session.results, default=str), session.id))
            conn.commit()
            conn.close()

            # Limpiar sesión activa
            if session.id in self.active_sessions:
                del self.active_sessions[session.id]

    def _update_session_progress(self, session_id: str, progress: float):
        """Actualizar progreso de sesión"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('UPDATE scan_sessions SET progress = ? WHERE id = ?', (progress, session_id))
        conn.commit()
        conn.close()

    def _save_scan_results(self, session: ScanSession, results: Dict):
        """Guardar resultados de scan en base de datos"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Guardar resultados por fase
        for phase_name, phase_result in results.items():
            if isinstance(phase_result, dict):
                cursor.execute('''
                    INSERT INTO phase_results (session_id, phase_name, status, test_count, vulnerability_count)
                    VALUES (?, ?, ?, ?, ?)
                ''', (
                    session.id,
                    phase_name,
                    'completed' if phase_result.get('success') else 'failed',
                    phase_result.get('test_count', 0),
                    len(phase_result.get('vulnerabilities', []))
                ))

                # Guardar vulnerabilidades
                if phase_result.get('vulnerabilities'):
                    for vuln in phase_result['vulnerabilities']:
                        cursor.execute('''
                            INSERT INTO vulnerabilities (session_id, phase, vulnerability_type, risk_level, description, recommendations)
                            VALUES (?, ?, ?, ?, ?, ?)
                        ''', (
                            session.id,
                            phase_name,
                            vuln.get('test_name', 'Unknown'),
                            vuln.get('risk_level', 'Unknown'),
                            vuln.get('description', ''),
                            json.dumps(vuln.get('recommendations', []))
                        ))

        conn.commit()
        conn.close()

    def run(self):
        """Iniciar el dashboard web"""
        print(f"[*] Starting WSTG Dashboard on http://{self.host}:{self.port}")
        print("[*] Dashboard is ready to use!")
        self.app.run(host=self.host, port=self.port, debug=False)

def main():
    """Función principal para iniciar el dashboard"""
    import argparse

    parser = argparse.ArgumentParser(description='WSTG Web Dashboard')
    parser.add_argument('--host', default='127.0.0.1', help='Host to bind to')
    parser.add_argument('--port', type=int, default=5000, help='Port to bind to')

    args = parser.parse_args()

    dashboard = WSTGWebDashboard(host=args.host, port=args.port)
    dashboard.run()

if __name__ == "__main__":
    main()
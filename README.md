# 🛡️ OWASP WSTG Framework - Professional Security Testing for Kali Linux

[![OWASP](https://img.shields.io/badge/OWASP-Web_Security_Testing_Guide-red)](https://owasp.org/www-project-web-security-testing-guide/)
[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://python.org)
[![Kali Linux](https://img.shields.io/badge/Kali_Linux-compatible-orange.svg)](https://www.kali.org/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

> 🎯 **Framework completo y profesional** que implementa las **12 fases del OWASP Web Security Testing Guide (WSTG)** optimizado para **Kali Linux** con integración total de herramientas de seguridad.

---

## 🌟 **Características Principales**

### **🏗️ Arquitectura Profesional**
- **12 Fases completas** del OWASP WSTG
- **Modular y extensible** con código compartido
- **Testing concurrente** y optimizado
- **Manejo robusto de errores** y recuperación

### **🔧 Integración Kali Linux**
- **Detección automática** de herramientas (Nmap, Hydra, Nikto, etc.)
- **Wrappers Python** para herramientas nativas
- **Wordlists integradas** (rockyou.txt, seclists)
- **Paralelización** con herramientas nativas

### **📊 Reportes Profesionales**
- **Múltiples formatos**: JSON, HTML, CSV
- **Análisis de riesgo** con CVSS scoring
- **Recomendaciones priorizadas**
- **Executive summaries** para management

---

## 🚀 **Instalación Rápida en Kali Linux**

### **Método 1: Setup Automático (Recomendado)**
```bash
# Clonar repositorio
git clone https://github.com/TU_USERNAME/owasp-wstg-framework.git
cd owasp-wstg-framework

# Ejecutar setup (instala todo automáticamente)
chmod +x setup_kali.sh
./setup_kali.sh

# Activar entorno virtual
source venv/bin/activate

# Listo para usar! 🎉
```

### **Método 2: Manual**
```bash
# Instalar dependencias de Python
pip3 install -r requirements.txt

# Instalar herramientas Kali
sudo apt update
sudo apt install nmap nikto hydra gobuster sqlmap -y

# Ejecutar framework
python3 complete_wstg_framework.py --target example.com
```

---

## 📋 **Fases del Framework (WSTG)**

| Fase | ID | Descripción | Herramientas Kali |
|------|-----|-------------|-----------------|
| 1 | **WSTG-INFO** | Information Gathering | Nmap, Dirb, Gobuster |
| 2 | **WSTG-CONF** | Configuration Testing | Nikto, TestSSL, Nmap |
| 3 | **WSTG-IDNT** | Identity Management | Hydra, CeWL |
| 4 | **WSTG-ATHN** | Authentication Testing | Hydra, Hashcat, John |
| 5 | **WSTG-ATHZ** | Authorization Testing | Burp Suite, OWASP ZAP |
| 6 | **WSTG-SESS** | Session Management | Wireshark, Burp Suite |
| 7 | **WSTG-INPV** | Input Validation | Sqlmap, XSSer |
| 8 | **WSTG-ERRH** | Error Handling | Curl, Wfuzz |
| 9 | **WSTG-CRYP** | Cryptography | TestSSL, Hashcat |
| 10 | **WSTG-BUSL** | Business Logic | Burp Suite, OWASP ZAP |
| 11 | **WSTG-CLNT** | Client-side Testing | Selenium, OWASP ZAP |
| 12 | **WSTG-APIT** | API Testing | OWASP ZAP, Postman |

---

## 💻 **Uso del Framework**

### **Ejecución Completa**
```bash
# Todas las fases
python complete_wstg_framework.py --target example.com

# Con opciones avanzadas
python complete_wstg_framework.py \
  --target example.com \
  --verbose \
  --output-dir ./reports
```

### **Ejecución por Fases**
```bash
# Orquestador principal
python wstg_framework.py --target example.com --phase all
python wstg_framework.py --target example.com --phase info,conf,auth

# Scripts individuales
python 01-Information_Gathering/info_tester.py --target example.com
python 04-Authentication_Testing/authentication_tester.py --target example.com
python 05-Authorization_Testing/authorization_tester.py --target example.com
```

### **Con Integración Kali**
```bash
# Usar herramientas Kali
python 04-Authentication_Testing/authentication_tester.py \
  --target example.com \
  --kali-tools \
  --hydra-threads 50
```

---

## 📊 **Ejemplos de Reportes**

### **Resumen Ejecutivo**
```
==========================================
OWASP WSTG Complete Security Report
Target: example.com
Date: 2024-01-01
Risk Level: HIGH
==========================================

Total Phases: 12
Total Vulnerabilities: 23
Critical: 3
High: 8
Medium: 10
Low: 2

⚠️  HIGH RISK: 11 vulnerabilities found - Action required soon
```

---

## 🛠️ **Herramientas de Kali Integradas**

| Herramienta | Uso en Framework | Comando Kali |
|-------------|-------------------|-------------|
| **Nmap** | Port scanning, service detection | `nmap -sV target.com` |
| **Hydra** | Brute force authentication | `hydra -L users.txt -P passwords.txt` |
| **Nikto** | Web vulnerability scanning | `nikto -h https://target.com` |
| **Gobuster** | Directory/file enumeration | `gobuster dir -u https://target.com` |
| **SQLMap** | SQL Injection testing | `sqlmap -u "https://target.com"` |
| **Burp Suite** | Manual testing, proxy | `burpsuite` |
| **OWASP ZAP** | Automated scanning | `zaproxy` |
| **Hashcat** | Password cracking | `hashcat -m 0 hash.txt wordlist.txt` |

---

## 🎯 **Casos de Uso**

### **🔍 Para Pentesters**
```bash
# Escaneo completo
python complete_wstg_framework.py --target pentest-target.com

# Análisis rápido de configuración
python 02-Configuration_and_Deployment_Management/configuration_testing.py --target target.com
```

### **🏢 Para Empresas**
```bash
# Auditoría regular
python wstg_framework.py --target company-website.com --phase info,conf,auth --output-dir ./audit-2024-Q1

# Cumplimiento PCI-DSS
python 04-Authentication_Testing/authentication_tester.py --target payment-site.com --compliance pci-dss
```

### **👨‍💻 Para Desarrolladores (DevSecOps)**
```bash
# Testing en desarrollo
python complete_wstg_framework.py --target dev-app.internal --phase inpv,clnt,apit

# Integración CI/CD
python wstg_framework.py --target ci-build.test --phase conf,inpv --format json
```

---

## 🏆 **Ventajas Competitivas**

| Característica | Nuestro Framework | Nessus | Burp Suite Pro |
|---------------|------------------|--------|--------------|
| **Costo** | **100% Gratis** | 💰 $$$$ | 💰 $$$$ |
| **OWASP Standard** | ✅ 100% | ⚠️ Parcial | ⚠️ Parcial |
| **Kali Integration** | ✅ Nativa | ❌ Manual | ⚠️ Limitado |
| **Código Fuente** | ✅ Completo | ❌ Cerrado | ❌ Cerrado |
| **Personalización** | ✅ Total | ❌ Limitada | ⚠️ Limitada |
| **Reportes** | ✅ Multi-formato | ✅ Profesionales | ✅ Profesionales |
| **12 Fases** | ✅ Completo | ⚠️ Incompleto | ⚠️ Incompleto |

---

## 📁 **Estructura del Proyecto**

```
owasp-wstg-framework/
├── 📁 core/                          # Módulos centrales
├── 📁 01-Information_Gathering/      # Phase 1: Reconnaissance
├── 📁 02-Configuration_and_Deployment_Management/  # Phase 2: Config testing
├── 📁 03-Identity_Management/        # Phase 3: Identity mgmt
├── 📁 04-Authentication_Testing/      # Phase 4: Authentication
├── 📁 05-Authorization_Testing/      # Phase 5: Authorization
├── 📁 06-Session_Management/          # Phase 6: Session testing
├── 📁 07-Input_Validation/            # Phase 7: Input validation
├── 📁 08-Error_Handling/              # Phase 8: Error handling
├── 📁 09-Cryptography/                # Phase 9: Crypto testing
├── 📁 10-Business_Logic/              # Phase 10: Business logic
├── 📁 11-Client_Side/                 # Phase 11: Client-side
├── 📁 12-API_Testing/                 # Phase 12: API testing
├── 🐍 complete_wstg_framework.py       # Script unificado
├── 🎯 wstg_framework.py                # Orquestador principal
├── 🔧 setup_kali.sh                   # Script instalación Kali
├── 📦 requirements.txt                # Dependencias Python
└── 📖 README.md                      # Esta documentación
```

---

## 🤝 **Contribuciones**

¡Las contribuciones son bienvenidas!

1. Fork el repositorio
2. Crea una rama de feature: `git checkout -b feature/amazing-feature`
3. Commit tus cambios: `git commit -m 'Add amazing feature'`
4. Push a la rama: `git push origin feature/amazing-feature`
5. Abre un Pull Request

---

## 📜 **Licencia**

Este proyecto está licenciado bajo la **MIT License**.

---

## 🙏 **Agradecimientos**

- **OWASP Foundation** - Por el Web Security Testing Guide
- **Kali Linux Team** - Por la excelente plataforma de testing
- **Security Community** - Por feedback y contribuciones

---

## 📞 **Soporte**

- 🐛 **Issues**: Report bugs y solicitudes de features
- 📚 **Wiki**: Documentación extendida
- 💬 **Discussions**: Comunidad y soporte

---

<div align="center">

**🛡️ Made with ❤️ for the Security Community**

[![OWASP](https://img.shields.io/badge/OWASP-Community-green.svg)](https://owasp.org/)
[![Kali Linux](https://img.shields.io/badge/Kali_Linux-Community-orange.svg)](https://www.kali.org/)
[![Python](https://img.shields.io/badge/Python-Loves_Security-blue.svg)](https://python.org/)

</div>
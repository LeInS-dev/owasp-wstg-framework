# 🚀 PROCEDIMIENTO DE INSTALACIÓN COMPLETO
## OWASP WSTG Security Testing Framework v2.0

## 📋 REQUISITOS PREVIOS

### Sistema Operativo
- **Recomendado**: Kali Linux 2023.3+ o Ubuntu 22.04+
- **Alternativas**: Debian 12+, CentOS 9+, Arch Linux
- **Windows**: WSL2 con Ubuntu/Kali

### Python
- **Versión mínima**: Python 3.9+
- **Recomendada**: Python 3.11+
- **Verificar versión**: `python3 --version`

### Hardware
- **RAM**: Mínimo 4GB, Recomendado 8GB+
- **Almacenamiento**: 20GB libres (incluyendo herramientas)
- **Procesador**: 2+ cores para escaneos concurrentes

## 🔧 INSTALACIÓN PASO A PASO

### 1. Actualización del Sistema

#### En Kali Linux/Ubuntu:
```bash
sudo apt update
sudo apt upgrade -y
sudo apt autoremove -y
```

#### En Windows WSL2:
```bash
# Actualizar paquetes
sudo apt update && sudo apt upgrade -y

# Instalar herramientas esenciales
sudo apt install -y curl wget git build-essential
```

### 2. Instalación de Python y Pip

#### Si Python 3.11 no está instalado:
```bash
# Ubuntu/Debian
sudo apt install -y python3.11 python3.11-pip python3.11-dev python3.11-venv

# Verificar instalación
python3.11 --version
```

### 3. Herramientas de Seguridad Esenciales (Kali Linux)

#### Instalar herramientas básicas del sistema:
```bash
# Herramientas de red y escaneo
sudo apt install -y nmap nikto hydra dirb gobuster sqlmap wpscan

# Análisis SSL/TLS
sudo apt install -y testssl.sh openssl

# Análisis web
sudo apt install -y burpsuite owasp-zap

# Frameworks de exploits
sudo apt install -y metasploit-framework

# Análisis de DNS y recon
sudo apt install -y dnsenum dnsrecon fierce

# Web application testing
sudo apt install -y whatweb wafw00f

# Password cracking
sudo apt install -y john hashcat

# Forensics y análisis de red
sudo apt install -y wireshark tcpdump
```

### 4. Clonación y Configuración del Framework

```bash
# Clonar el repositorio (si no está ya clonado)
cd /opt/
sudo git clone https://github.com/tu-usuario/owasp-wstg-framework.git
cd owasp-wstg-framework

# Establecer permisos adecuados
sudo chown -R $USER:$USER /opt/owasp-wstg-framework

# Hacer ejecutables los scripts principales
chmod +x *.py
```

### 5. Creación y Activación de Entorno Virtual

```bash
# Crear entorno virtual con Python 3.11
python3.11 -m venv venv_wstg

# Activar entorno virtual
source venv_wstg/bin/activate

# Actualizar pip en el entorno virtual
pip install --upgrade pip setuptools wheel
```

### 6. Instalación de Dependencias Python

#### Opción A: Instalación completa (Recomendada)
```bash
# Instalar todas las dependencias
pip install -r requirements.txt

# Si hay problemas con algunas dependencias, instalar por grupos:
pip install --upgrade requests beautifulsoup4 lxml certifi urllib3
```

#### Opción B: Instalación por grupos
```bash
# Grupo 1: Core dependencies
pip install requests>=2.31.0 beautifulsoup4>=4.12.0 lxml>=4.9.0 certifi>=2023.0.0 urllib3>=2.0.0

# Grupo 2: Data handling
pip install python-dateutil>=2.8.0 pydantic>=2.0.0 faker>=19.0.0

# Grupo 3: Networking
pip install dnspython>=2.4.0 python-whois>=0.8.0 ipaddress>=1.0.0

# Grupo 4: SSL/TLS
pip install pyOpenSSL>=23.0.0 cryptography>=41.0.0

# Grupo 5: Web automation
pip install selenium>=4.11.0 playwright>=1.36.0 undetected-chromedriver>=3.5.0

# Grupo 6: Dashboard web
pip install Flask>=2.3.0 Flask-CORS>=4.0.0 flask-socketio>=5.3.0
pip install plotly>=5.15.0 bokeh>=3.2.0 pandas>=2.0.0

# Grupo 7: Machine Learning (opcional)
pip install scikit-learn>=1.3.0 numpy>=1.24.0

# Grupo 8: Testing y desarrollo
pip install pytest>=7.4.0 black>=23.0.0 flake8>=6.0.0
```

### 7. Instalación de Herramientas Adicionales

#### Navegadores para Selenium/Playwright:
```bash
# Instalar navegadores para Playwright
playwright install

# Instalar ChromeDriver para Selenium
sudo apt install -y chromium-browser
# O descargar manualmente:
# wget https://chromedriver.storage.googleapis.com/LATEST_RELEASE
```

#### Herramientas de análisis de código:
```bash
# Instalar herramientas de análisis estático
pip install bandit safety semgrep

# Herramientas de análisis de dependencias
pip install pip-audit
```

### 8. Configuración Base

#### Crear archivo de configuración:
```bash
# Copiar configuración base
cp config/config.yaml.example config/config.yaml

# Editar configuración
nano config/config.yaml
```

#### Configurar variables de entorno:
```bash
# Crear archivo .env
cat > .env << EOF
# Configuración del Framework
WSTG_HOME=/opt/owasp-wstg-framework
WSTG_LOG_LEVEL=INFO
WSTG_MAX_CONCURRENT=5

# Base de datos
WSTG_DB_PATH=./data/wstg.db

# Reportes
WSTG_REPORTS_DIR=./reports

# API Keys (opcional)
WSTG_VIRUSTOTAL_API=your_api_key_here
WSTG_SHODAN_API=your_api_key_here
EOF
```

### 9. Verificación de la Instalación

#### Test de integración:
```bash
# Verificar que todo está instalado correctamente
python3 wstg_framework.py --version

# Ejecutar test de diagnóstico
python3 wstg_framework.py --diagnostic

# Test rápido con un objetivo seguro
python3 wstg_framework.py --target http://httpbin.org --quick-scan
```

#### Verificación de módulos:
```bash
# Verificar imports principales
python3 -c "import requests, bs4, selenium, flask, pandas; print('✅ All modules imported successfully')"

# Verificar herramientas del sistema
which nmap nikto sqlmap hydra gobuster
echo "✅ Security tools found"
```

### 10. Configuración Adicional

#### Base de datos SQLite:
```bash
# Crear directorio para datos
mkdir -p data logs reports

# Inicializar base de datos
python3 -c "from core.database import init_db; init_db()"
```

#### Servicios adicionales (opcional):
```bash
# Instalar Redis para cola de tareas
sudo apt install -y redis-server
sudo systemctl enable redis-server
sudo systemctl start redis-server

# Instalar PostgreSQL (alternativa a SQLite)
sudo apt install -y postgresql postgresql-contrib
sudo systemctl enable postgresql
sudo systemctl start postgresql
```

## 🐛 SOLUCIÓN DE PROBLEMAS COMUNES

### Problemas Frecuentes:

#### 1. Error con Playwright:
```bash
# Solución
playwright install-deps
sudo apt install -y libnss3-dev libatk1.0-dev libdrm2 libxcomposite1 libxdamage1 libxrandr2 libgbm1 libxss1 libasound2
```

#### 2. Problemas con Selenium/ChromeDriver:
```bash
# Instalar Chrome uq Chromium
sudo apt install -y chromium-browser chromium-chromedriver

# O usar Chrome versión para testing
wget -q -O - https://dl-ssl.google.com/linux/linux_signing_key.pub | sudo apt-key add -
echo "deb [arch=amd64] http://dl.google.com/linux/chrome/deb/ stable main" | sudo tee /etc/apt/sources.list.d/google-chrome.list
sudo apt update && sudo apt install -y google-chrome-stable
```

#### 3. Problemas de permisos:
```bash
# Solución
sudo chown -R $USER:$USER /opt/owasp-wstg-framework
chmod +x /opt/owasp-wstg-framework/*.py
```

#### 4. Error de dependencias:
```bash
# Limpiar caché de pip
pip cache purge

# Reinstalar dependencias
pip install --force-reinstall -r requirements.txt
```

#### 5. Problemas con librerías de sistema:
```bash
# Instalar build essentials
sudo apt install -y build-essential python3-dev libffi-dev libssl-dev

# Librerías para procesamiento de imágenes
sudo apt install -y libjpeg-dev libpng-dev libtiff-dev

# Librerías para análisis de XML
sudo apt install -y libxml2-dev libxslt1-dev
```

## ⚡ INSTALACIÓN RÁPIDA (Script Automatizado)

```bash
#!/bin/bash
# quick_install.sh

echo "🚀 Iniciando instalación rápida de OWASP WSTG Framework..."

# Actualizar sistema
sudo apt update && sudo apt upgrade -y

# Instalar Python y herramientas básicas
sudo apt install -y python3.11 python3.11-pip python3.11-dev python3.11-venv build-essential git curl wget

# Instalar herramientas de seguridad
sudo apt install -y nmap nikto hydra dirb gobuster sqlmap wpscan burpsuite owasp-zap testssl.sh

# Clonar framework (si no existe)
if [ ! -d "/opt/owasp-wstg-framework" ]; then
    sudo git clone https://github.com/tu-usuario/owasp-wstg-framework.git /opt/owasp-wstg-framework
    sudo chown -R $USER:$USER /opt/owasp-wstg-framework
fi

cd /opt/owasp-wstg-framework

# Crear y activar entorno virtual
python3.11 -m venv venv_wstg
source venv_wstg/bin/activate

# Actualizar pip
pip install --upgrade pip setuptools wheel

# Instalar dependencias en batches
echo "📦 Instalando dependencias core..."
pip install requests beautifulsoup4 lxml certifi urllib3 python-dateutil pydantic faker

echo "📦 Instalando herramientas de red..."
pip install dnspython python-whois ipaddress pyOpenSSL cryptography

echo "📦 Instalando herramientas web..."
pip install selenium playwright undetected-chromedriver

echo "📦 Instalando dashboard..."
pip install Flask Flask-CORS flask-socketio plotly pandas numpy

echo "📦 Instalando herramientas adicionales..."
pip install click rich tqdm colorama pyyaml python-dotenv

# Configurar navegadores
playwright install

# Crear estructura de directorios
mkdir -p data logs reports config

echo "✅ Instalación completada!"
echo "🔧 Para usar el framework:"
echo "   cd /opt/owasp-wstg-framework"
echo "   source venv_wstg/bin/activate"
echo "   python3 wstg_framework.py --help"
```

## 📊 VERIFICACIÓN POST-INSTALACIÓN

### Test Completo del Sistema:
```bash
# Ejecutar diagnóstico completo
python3 wstg_framework.py --full-diagnostic

# Verificar todos los módulos
python3 -c "
try:
    import requests, bs4, selenium, flask, pandas, plotly
    import nmap, whois, ssl, subprocess
    print('✅ Todos los módulos importados correctamente')
except ImportError as e:
    print(f'❌ Error importando: {e}')
"

# Test con objetivo de ejemplo
python3 wstg_framework.py \
    --target http://httpbin.org \
    --phase info \
    --output test_run.json
```

### Verificar espacio en disco:
```bash
# Espacio usado por el framework
du -sh /opt/owasp-wstg-framework/

# Espacio disponible
df -h
```

## 🎯 PRÓXIMOS PASOS

1. **Configurar API Keys** para servicios externos (VirusTotal, Shodan, etc.)
2. **Personalizar configuración** en `config/config.yaml`
3. **Leer documentación** de cada módulo específico
4. **Ejecutar primer scan** con un objetivo de prueba
5. **Configurar reportes** según necesidades específicas

## 📚 RECURSOS ADICIONALES

- **Documentación completa**: `docs/`
- **Ejemplos de configuración**: `examples/`
- **Templates de reportes**: `templates/`
- **Wiki del proyecto**: [GitHub Wiki](link)
- **Issues y soporte**: [GitHub Issues](link)

---

## 🚨 NOTAS IMPORTANTES

1. **Reiniciar sistema** después de instalar herramientas del sistema
2. **Verificar permisos** en archivos de configuración
3. **Configurar firewall** si se ejecuta en producción
4. **Actualizar framework** regularmente: `git pull origin main`
5. **Backup de configuración**: copiar directorio `config/`

**¡Listo para comenzar testing de seguridad profesional! 🔒**
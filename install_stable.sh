#!/bin/bash
# install_stable.sh - Instalación estable y compatible del OWASP WSTG Framework

echo "🚀 Instalación ESTABLE del OWASP WSTG Framework"
echo "=============================================="

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Verificar Python
echo -e "${BLUE}🐍 Verificando Python...${NC}"
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
    echo -e "${GREEN}✅ Python encontrado: $PYTHON_VERSION${NC}"
else
    echo -e "${RED}❌ Python 3 no encontrado${NC}"
    echo "Instala Python 3.9+ con: sudo apt install python3 python3-pip"
    exit 1
fi

# Verificar pip
if ! command -v pip3 &> /dev/null; then
    echo -e "${YELLOW}⚠️ pip3 no encontrado, instalando...${NC}"
    sudo apt update && sudo apt install -y python3-pip
fi

# Actualizar pip
echo -e "${BLUE}📦 Actualizando pip...${NC}"
python3 -m pip install --upgrade pip setuptools wheel

# Crear entorno virtual (recomendado)
echo -e "${BLUE}🔄 Creando entorno virtual...${NC}"
if [ ! -d "venv_wstg" ]; then
    python3 -m venv venv_wstg
fi

# Activar entorno virtual
echo -e "${BLUE}🔧 Activando entorno virtual...${NC}"
source venv_wstg/bin/activate

# Instalar dependencias en batches para evitar timeouts
echo -e "${BLUE}📦 Instalando dependencias esenciales...${NC}"
pip install requests beautifulsoup4 lxml certifi urllib3
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✅ Dependencias esenciales OK${NC}"
else
    echo -e "${RED}❌ Error en dependencias esenciales${NC}"
    exit 1
fi

echo -e "${BLUE}📦 Instalando herramientas de análisis...${NC}"
pip install dnspython python-whois netaddr pyyaml python-dotenv
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✅ Herramientas de análisis OK${NC}"
else
    echo -e "${YELLOW}⚠️ Algunas herramientas de análisis fallaron${NC}"
fi

echo -e "${BLUE}📦 Instalando criptografía y seguridad...${NC}"
pip install cryptography pyOpenSSL bcrypt PyJWT
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✅ Criptografía OK${NC}"
else
    echo -e "${RED}❌ Error en criptografía${NC}"
    exit 1
fi

echo -e "${BLUE}📦 Instalando herramientas de datos...${NC}"
pip install pandas numpy openpyxl matplotlib plotly seaborn
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✅ Herramientas de datos OK${NC}"
else
    echo -e "${YELLOW}⚠️ Algunas herramientas de datos fallaron${NC}"
fi

echo -e "${BLUE}📦 Instalando web automation...${NC}"
pip install selenium undetected-chromedriver
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✅ Web automation OK${NC}"
else
    echo -e "${YELLOW}⚠️ Web automation falló${NC}"
fi

echo -e "${BLUE}📦 Instalando framework web...${NC}"
pip install Flask Flask-CORS Werkzeug jinja2 click rich tqdm colorama
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✅ Framework web OK${NC}"
else
    echo -e "${YELLOW}⚠️ Framework web parcial${NC}"
fi

echo -e "${BLUE}📦 Instalando testing y desarrollo...${NC}"
pip install pytest pytest-cov scikit-learn
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✅ Testing OK${NC}"
else
    echo -e "${YELLOW}⚠️ Testing parcial${NC}"
fi

echo -e "${BLUE}📦 Instalando herramientas adicionales...${NC}"
pip install sqlalchemy aiohttp aiofiles psutil scapy python-nmap
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✅ Herramientas adicionales OK${NC}"
else
    echo -e "${YELLOW}⚠️ Algunas herramientas adicionales fallaron${NC}"
fi

# Configurar Playwright/Selenium (opcional)
echo -e "${BLUE}🌐 Configurando navegadores...${NC}"
read -p "¿Quieres instalar navegadores para testing web? (s/N): " install_browsers

if [[ $install_browsers =~ ^[Ss]$ ]]; then
    echo -e "${BLUE}📥 Instalando Playwright...${NC}"
    pip install playwright
    if [ $? -eq 0 ]; then
        echo -e "${BLUE}🔧 Instalando navegadores de Playwright...${NC}"
        playwright install
        echo -e "${GREEN}✅ Playwright OK${NC}"
    else
        echo -e "${YELLOW}⚠️ Playwright falló, puedes instalarlo después${NC}"
    fi
fi

# Verificar herramientas del sistema
echo -e "${BLUE}🔍 Verificando herramientas del sistema...${NC}"

tools=("nmap" "nikto" "sqlmap" "gobuster" "dirb" "hydra")
missing_tools=()

for tool in "${tools[@]}"; do
    if command -v "$tool" &> /dev/null; then
        echo -e "${GREEN}✅ $tool encontrado${NC}"
    else
        echo -e "${YELLOW}⚠️ $tool NO encontrado${NC}"
        missing_tools+=("$tool")
    fi
done

if [ ${#missing_tools[@]} -gt 0 ]; then
    echo -e "${YELLOW}⚠️ Herramientas faltantes: ${missing_tools[*]}${NC}"
    echo -e "${BLUE}💡 Instalar con: sudo apt install ${missing_tools[*]}${NC}"
fi

# Crear estructura de directorios
echo -e "${BLUE}📁 Creando estructura de directorios...${NC}"
mkdir -p data logs reports config temp

# Crear archivo de configuración base
if [ ! -f "config/config.yaml" ]; then
    echo -e "${BLUE}📝 Creando configuración base...${NC}"
    cat > config/config.yaml << EOF
# OWASP WSTG Framework - Configuración Base

# General
framework:
  name: "OWASP WSTG Framework"
  version: "2.0"
  debug: false
  log_level: "INFO"

# Database
database:
  type: "sqlite"
  path: "./data/wstg.db"

# Reports
reports:
  output_dir: "./reports"
  formats: ["json", "html", "pdf"]

# Security
security:
  max_concurrent_scans: 5
  request_timeout: 30
  user_agent: "OWASP-WSTG-Framework/2.0"

# APIs (opcional)
apis:
  virustotal_api_key: ""
  shodan_api_key: ""

# Tools paths
tools:
  nmap: "/usr/bin/nmap"
  nikto: "/usr/bin/nikto"
  sqlmap: "/usr/bin/sqlmap"
  gobuster: "/usr/bin/gobuster"
EOF
    echo -e "${GREEN}✅ Configuración base creada${NC}"
fi

# Test de instalación
echo -e "${BLUE}🧪 Verificando instalación...${NC}"

python3 -c "
import sys
try:
    import requests, bs4, flask, pandas, numpy
    import yaml, click, rich, tqdm
    import cryptography, selenium, sqlalchemy
    print('✅ Todos los módulos principales importados correctamente')
    sys.exit(0)
except ImportError as e:
    print(f'❌ Error importando: {e}')
    sys.exit(1)
"

if [ $? -eq 0 ]; then
    echo -e "${GREEN}🎉 ¡Instalación completada con éxito!${NC}"
else
    echo -e "${YELLOW}⚠️ Instalación parcial - algunos módulos fallaron${NC}"
fi

echo ""
echo -e "${GREEN}🚀 Framework listo para usar!${NC}"
echo ""
echo "📝 Para usar el framework:"
echo "   1. Activar entorno: source venv_wstg/bin/activate"
echo "   2. Ejecutar framework: python3 wstg_framework.py --help"
echo "   3. Verificar instalación: python3 wstg_framework.py --version"
echo ""
echo "📚 Documentación completa en: INSTALACION.md"
echo "🔧 Para instalar herramientas del sistema:"
echo "   sudo apt install nmap nikto sqlmap gobuster dirb hydra"
echo ""
echo -e "${BLUE}¡Happy hacking! 🔒${NC}"
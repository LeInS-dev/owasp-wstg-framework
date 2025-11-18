#!/bin/bash
# update_framework.sh - Script para actualizar el OWASP WSTG Framework

echo "🔄 Actualizador de OWASP WSTG Framework"
echo "========================================"

# Configuración
REPO_URL="https://github.com/tu-usuario/owasp-wstg-framework.git"
FRAMEWORK_DIR="/opt/owasp-wstg-framework"
BACKUP_DIR="/opt/owasp-wstg-framework-backup-$(date +%Y%m%d_%H%M%S)"

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Función para verificar ejecución como root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}Este script debe ejecutarse como root (sudo)${NC}"
        exit 1
    fi
}

# Función para verificar conexión a internet
check_internet() {
    echo "🔍 Verificando conexión a internet..."
    if ping -c 1 google.com &> /dev/null; then
        echo -e "${GREEN}✅ Conexión a internet OK${NC}"
    else
        echo -e "${RED}❌ Sin conexión a internet${NC}"
        exit 1
    fi
}

# Función para backup
backup_current() {
    echo "📦 Creando backup de la instalación actual..."
    if [ -d "$FRAMEWORK_DIR" ]; then
        cp -r "$FRAMEWORK_DIR" "$BACKUP_DIR"
        echo -e "${GREEN}✅ Backup creado en: $BACKUP_DIR${NC}"
    else
        echo -e "${YELLOW}⚠️  No existe directorio para hacer backup${NC}"
    fi
}

# Función para instalar/actualizar con Git
update_with_git() {
    echo "🔄 Actualizando con Git..."

    # Si ya existe el directorio, actualizar
    if [ -d "$FRAMEWORK_DIR/.git" ]; then
        echo "📁 El framework ya es un repositorio Git, actualizando..."
        cd "$FRAMEWORK_DIR"
        git fetch origin
        git pull origin main

    else:
        # Si no es Git, clonar fresh
        echo "📁 Clonando repositorio fresh..."
        rm -rf "$FRAMEWORK_DIR"
        git clone "$REPO_URL" "$FRAMEWORK_DIR"
    fi

    # Establecer permisos
    chown -R $USER:$USER "$FRAMEWORK_DIR"
    chmod +x "$FRAMEWORK_DIR"/*.py
    chmod +x "$FRAMEWORK_DIR"/*.sh

    echo -e "${GREEN}✅ Framework actualizado con Git${NC}"
}

# Función para actualizar sin Git (download HTTP)
update_without_git() {
    echo "🔄 Actualizando sin Git (descarga HTTP)..."

    # Crear directorio temporal
    TEMP_DIR="/tmp/wstg_framework_update_$(date +%s)"
    mkdir -p "$TEMP_DIR"

    # Descargar última versión (asumiendo que es ZIP)
    echo "📥 Descargando última versión..."
    wget -O "$TEMP_DIR/framework.zip" "$REPO_URL/archive/main.zip"

    # Extraer
    cd "$TEMP_DIR"
    unzip framework.zip

    # Mover a destino
    rm -rf "$FRAMEWORK_DIR"
    mv owasp-wstg-framework-main "$FRAMEWORK_DIR"

    # Limpiar
    rm -rf "$TEMP_DIR"

    # Permisos
    chown -R $USER:$USER "$FRAMEWORK_DIR"
    chmod +x "$FRAMEWORK_DIR"/*.py

    echo -e "${GREEN}✅ Framework actualizado vía HTTP${NC}"
}

# Función para correcciones post-actualización
post_update_fixes() {
    echo "🔧 Aplicando correcciones post-actualización..."

    cd "$FRAMEWORK_DIR"

    # Corregir requirements.txt si es necesario
    if grep -q "^sqlite3" requirements.txt; then
        echo "📝 Corrigiendo requirements.txt..."
        sed -i 's/^sqlite3/#sqlite3/' requirements.txt
    fi

    if grep -q "^asyncio" requirements.txt; then
        echo "📝 Corrigiendo requirements.txt..."
        sed -i 's/^asyncio/#asyncio/' requirements.txt
    fi

    # Crear directorios necesarios
    mkdir -p data logs reports config

    echo -e "${GREEN}✅ Correcciones aplicadas${NC}"
}

# Función para verificar actualización
verify_update() {
    echo "🔍 Verificando actualización..."

    if [ -f "$FRAMEWORK_DIR/wstg_framework.py" ]; then
        echo -e "${GREEN}✅ wstg_framework.py encontrado${NC}"
    else
        echo -e "${RED}❌ wstg_framework.py NO encontrado${NC}"
        return 1
    fi

    if [ -f "$FRAMEWORK_DIR/requirements.txt" ]; then
        echo -e "${GREEN}✅ requirements.txt encontrado${NC}"
    else
        echo -e "${RED}❌ requirements.txt NO encontrado${NC}"
        return 1
    fi

    # Verificar versión
    if [ -f "$FRAMEWORK_DIR/INSTALACION.md" ]; then
        echo -e "${GREEN}✅ INSTALACION.md encontrado${NC}"
        echo "📋 Última versión de documentación disponible"
    fi

    return 0
}

# Función principal
main() {
    echo "🚀 Iniciando actualización del OWASP WSTG Framework..."

    check_root
    check_internet
    backup_current

    # Preguntar método de actualización
    echo ""
    echo "📋 Método de actualización:"
    echo "1) Git (recomendado, permite actualizaciones futuras)"
    echo "2) HTTP/Download (sin Git)"
    echo ""
    read -p "Elige método (1-2): " method

    case $method in
        1)
            update_with_git
            ;;
        2)
            update_without_git
            ;;
        *)
            echo -e "${RED}❌ Opción no válida${NC}"
            exit 1
            ;;
    esac

    post_update_fixes

    if verify_update; then
        echo ""
        echo -e "${GREEN}🎉 ¡Actualización completada con éxito!${NC}"
        echo ""
        echo "📝 Próximos pasos:"
        echo "1. cd $FRAMEWORK_DIR"
        echo "2. source venv_wstg/bin/activate  # si tienes entorno virtual"
        echo "3. pip install -r requirements.txt  # reinstalar dependencias"
        echo "4. python3 wstg_framework.py --version  # verificar"
        echo ""
        echo "📦 Backup guardado en: $BACKUP_DIR"
    else
        echo -e "${RED}❌ Hubo errores en la actualización${NC}"
        echo "🔄 Restaurando desde backup..."
        rm -rf "$FRAMEWORK_DIR"
        mv "$BACKUP_DIR" "$FRAMEWORK_DIR"
        exit 1
    fi
}

# Ejecutar función principal
main "$@"
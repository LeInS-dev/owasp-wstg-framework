# Fase 1: Information Gathering (WSTG-INFO)

## Objetivo
La fase de recopilación de información es fundamental en cualquier prueba de seguridad web. El objetivo es recopilar toda la información posible sobre el objetivo sin interactuar directamente con el sistema, o con interacciones mínimas.

## Descripción General
Esta fase consiste en obtener información sobre la infraestructura, tecnología, aplicaciones y posibles vectores de ataque. La información recopilada servirá como base para las fases posteriores de testing.

## Tests Incluidos

### WSTG-INFO-01: Conduct Search Engine Discovery and Reconnaissance for Information Leakage
**Objetivo**: Descubrir información sensible a través de motores de búsqueda
**Técnicas**:
- Google Hacking/Google Dorks
- Búsqueda de información filtrada
- Descubrimiento de subdominios
- Identificación de tecnología

**Comandos útiles**:
```bash
site:ejemplo.com
site:ejemplo.com filetype:pdf
site:ejemplo.com inurl:admin
site:ejemplo.com intitle:"index of"
```

### WSTG-INFO-02: Fingerprint Web Server
**Objetivo**: Identificar el servidor web y su versión
**Técnicas**:
- Análisis de headers HTTP
- Banners de servidor
- Respuestas a errores específicas

**Herramientas**: Netcat, Nmap, WhatWeb, HTTPie

### WSTG-INFO-03: Review Webserver Metafiles for Information Leakage
**Objetivo**: Analizar archivos de metadatos y configuración
**Archivos a revisar**:
- robots.txt
- sitemap.xml
- .htaccess
- web.config
- security.txt

### WSTG-INFO-04: Enumerate Applications on Webserver
**Objetivo**: Descubrir aplicaciones y servicios adicionales
**Técnicas**:
- Escaneo de puertos
- Enumeración de servicios
- Identificación de aplicaciones web adicionales

### WSTG-INFO-05: Review Webpage Content for Information Leakage
**Objetivo**: Analizar el contenido en busca de información sensible
**Elementos a revisar**:
- Comentarios HTML
- Código JavaScript
- Metadatos de archivos
- Información de contacto

### WSTG-INFO-06: Identify Application Entry Points
**Objetivo**: Identificar puntos de entrada de la aplicación
**Puntos a identificar**:
- Endpoints de API
- Formularios
- Parámetros URL
- Funcionalidades AJAX

### WSTG-INFO-07: Map Execution Paths Through Application
**Objetivo**: Mapear flujos de ejecución de la aplicación
**Técnicas**:
- Análisis de flujo de navegación
- Identificación de workflows
- Mapeo de transacciones

### WSTG-INFO-08: Fingerprint Web Application Framework
**Objetivo**: Identificar el framework de la aplicación
**Indicadores**:
- Cookies específicas
- Headers personalizados
- Estructura de URLs
- Errores característicos

### WSTG-INFO-09: Fingerprint Web Application
**Objetivo**: Identificar la aplicación específica
**Técnicas**:
- Análisis de firma
- Comparación con fingerprints conocidos
- Análisis de comportamiento

### WSTG-INFO-10: Map Application Architecture
**Objetivo**: Entender la arquitectura de la aplicación
**Componentes a identificar**:
- Tecnologías del lado del servidor
- Base de datos
- Servidores externos
- CDN y caches

## Herramientas Recomendadas
- **Reconocimiento**: theHarvester, Recon-ng, Maltego
- **Análisis Web**: WhatWeb, Wappalyzer, BuiltWith
- **Escaneo**: Nmap, Dirb, Gobuster
- **Dorks**: Google Hacking Database (GHDB)

## Consideraciones Importantes
1. **Legalidad**: Asegurarse de tener autorización para realizar las pruebas
2. **Impacto**: Las pruebas de esta fase suelen ser no intrusivas
3. **Documentación**: Registrar todos los hallazgos detalladamente
4. **Stealth**: Algunas técnicas pueden ser detectadas por sistemas de seguridad

## Salida Esperada
Al finalizar esta fase, deberás tener:
- Mapa completo del objetivo
- Identificación de tecnologías utilizadas
- Puntos de entrada identificados
- Información potencialmente sensible encontrada
- Base para las siguientes fases de testing

## Métricas a Medir
- Cantidad de subdominios descubiertos
- Tecnologías identificadas
- Puntos de entrada mapeados
- Información sensible encontrada
- Superficies de ataque identificadas

## Referencias
- OWASP Testing Guide - Information Gathering
- MITRE ATT&CK - Reconnaissance
- PTES - Intelligence Gathering Phase
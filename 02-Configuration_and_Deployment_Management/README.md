# Fase 2: Configuration and Deployment Management Testing (WSTG-CONF)

## Objetivo
Evaluar la configuración del servidor web, plataforma de aplicación y la infraestructura de despliegue para identificar debilidades de configuración que puedan ser explotadas por atacantes.

## Descripción General
Esta fase se centra en verificar que la infraestructura y configuración de despliegue sigan las mejores prácticas de seguridad. Las configuraciones incorrectas son una de las causas más comunes de brechas de seguridad.

## Tests Incluidos

### WSTG-CONF-01: Test Network Infrastructure Configuration
**Objetivo**: Evaluar la configuración de la infraestructura de red
**Areas a verificar**:
- Configuración de firewall
- Segmentación de red
- DNS configuration
- Load balancers
- Configuración de red privada

**Verificaciones comunes**:
```bash
# Escaneo de puertos
nmap -sS -O target.com

# Verificación de firewall
nmap -sA target.com

# Información de red
whois target.com
dig target.com ANY
```

### WSTG-CONF-02: Test Application Platform Configuration
**Objetivo**: Revisar la configuración de la plataforma de aplicación
**Elementos a verificar**:
- Versión y parches del servidor web
- Módulos y extensions habilitadas
- Configuración de SSL/TLS
- Límites de recursos
- Configuración de logging

### WSTG-CONF-03: Test File Extensions Handling for Sensitive Information
**Objetivo**: Verificar el manejo de extensiones de archivo
**Extensiones sensibles a verificar**:
- .bak, .backup, .old
- .conf, .config, .ini
- .log, .txt
- .sql, .db
- .p12, .pem, .key

### WSTG-CONF-04: Review Old Backup and Unreferenced Files for Sensitive Information
**Objetivo**: Buscar archivos de backup y referencias no utilizadas
**Archivos a buscar**:
- Copias de seguridad
- Archivos temporales
- Archivos de versiones antiguas
- Archivos de configuración de desarrollo

### WSTG-CONF-05: Enumerate Infrastructure and Application Admin Interfaces
**Objetivo**: Identificar interfaces administrativas
**Interfaces comunes**:
- Panel de administración
- Interfaces de gestión
- Consolas de servidor
- APIs administrativas

### WSTG-CONF-06: Test HTTP Methods
**Objetivo**: Verificar métodos HTTP habilitados
**Métodos peligrosos**:
- PUT: Permitir creación de archivos
- DELETE: Permitir eliminación de recursos
- TRACE: Potencial de XSS
- OPTIONS: Revelar métodos habilitados
- PATCH: Modificación parcial de recursos

**Comando de prueba**:
```bash
curl -X OPTIONS http://target.com/ -v
curl -X PUT http://target.com/test.txt -d "test" -v
```

### WSTG-CONF-07: Test HTTP Strict Transport Security (HSTS)
**Objetivo**: Verificar la implementación de HSTS
**Headers a verificar**:
```
Strict-Transport-Security: max-age=31536000; includeSubDomains
```

### WSTG-CONF-08: Test RIA Cross Domain Policy
**Objetivo**: Revisar políticas de dominio cruzado para aplicaciones ricas
**Archivos a verificar**:
- crossdomain.xml (Flash)
- clientaccesspolicy.xml (Silverlight)

### WSTG-CONF-09: Test File Permission
**Objetivo**: Verificar permisos de archivos
**Permisos problemáticos**:
- Archivos ejecutables con permisos excesivos
- Directorios con permisos de escritura pública
- Archivos de configuración accesibles

### WSTG-CONF-10: Test for Subdomain Takeover
**Objetivo**: Identificar posibles takeovers de subdominios
**Escenarios**:
- DNS apuntando a servicios descontinuados
- CNAMEs a servicios cloud no configurados
- Subdominios huérfanos

### WSTG-CONF-11: Test Cloud Storage
**Objetivo**: Revisar configuración de almacenamiento cloud
**Servicios a verificar**:
- Amazon S3 buckets
- Azure Blob Storage
- Google Cloud Storage
- Configuración de permisos

### WSTG-CONF-12: Testing for Content Security Policy
**Objetivo**: Verificar implementación de CSP
**Header esperado**:
```
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'
```

### WSTG-CONF-13: Test Path Confusion
**Objetivo**: Identificar confusión de paths
**Vectores**:
- Path traversal relativo
- Decodificación doble URL
- Normalización de path

### WSTG-CONF-14: Test Other HTTP Security Header Misconfigurations
**Objetivo**: Verificar otros headers de seguridad
**Headers importantes**:
```
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
Referrer-Policy: strict-origin-when-cross-origin
Feature-Policy: ...
```

## Herramientas Recomendadas
- **Escaneo de red**: Nmap, Masscan
- **Análisis web**: Nikto, OWASP ZAP, Burp Suite
- **Headers**: SecurityHeaders.com, testssl.sh
- **Cloud**: AWS CLI, Azure CLI, CloudBrute
- **Subdomain takeover**: Subjack, Subzy

## Checklist de Verificación

### Configuración del Servidor Web
- [ ] Versiones actualizadas del servidor web
- [ ] Módulos innecesarios deshabilitados
- [ ] Configuración segura de SSL/TLS
- [ ] Headers de seguridad implementados
- [ ] Métodos HTTP restringidos

### Gestión de Archivos
- [ ] Sin archivos de backup accesibles
- [ ] Extensiones sensibles bloqueadas
- [ ] Permisos de archivo correctos
- [ ] Directorios sin listado

### Infraestructura
- [ ] Firewall correctamente configurado
- [ ] Segmentación de red adecuada
- [ ] Interfaces administrativas protegidas
- [ ] Monitoreo implementado

### Cloud y Servicios Externos
- [ ] Buckets S3 privados
- [ ] Sin subdominios vulnerables a takeover
- [ ] CDN configurado correctamente
- [ ] APIs externas aseguradas

## Consideraciones de Seguridad

### Impacto de las vulnerabilidades
- **High**: Subdomain takeover, backup files exposure
- **Medium**: HTTP methods inseguros, headers faltantes
- **Low**: Configuraciones menores de seguridad

### Riesgos asociados
- Compromiso de infraestructura
- Exposición de datos sensibles
- Escalada de privilegios
- Denegación de servicio

## Métricas a Medir
- Cantidad de vulnerabilidades de configuración encontradas
- Nivel de cumplimiento de headers de seguridad
- Cantidad de archivos sensibles expuestos
- Servicios cloud mal configurados
- Interfaces administrativas no protegidas

## Recomendaciones Generales
1. Implementar hardening de servidor web
2. Configurar headers de seguridad adecuados
3. Restringir métodos HTTP innecesarios
4. Proteger archivos sensibles y backups
5. Implementar monitoring y alertas
6. Realizar auditorías periódicas de configuración

## Referencias
- OWASP Testing Guide - Configuration Testing
- NIST Cybersecurity Framework
- CIS Benchmarks
- Security Technical Implementation Guides (STIGs)
- Cloud Security Alliance (CSA) Guidance
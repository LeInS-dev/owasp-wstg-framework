# Fase 3: Identity Management Testing (WSTG-IDNT)

## Objetivo
Evaluar el sistema de gestión de identidades y los procesos relacionados con el ciclo de vida de las identidades de usuarios en la aplicación web.

## Descripción General
Esta fase se centra en verificar cómo la aplicación gestiona las identidades de los usuarios, desde la creación y aprovisionamiento hasta la definición de roles y políticas de nombres de usuario. Una gestión inadecuada de identidades puede llevar a brechas de seguridad significativas.

## Tests Incluidos

### WSTG-IDNT-01: Test Role Definitions
**Objetivo**: Verificar la definición y gestión de roles de usuario
**Aspectos a evaluar**:
- Definición clara de roles y privilegios
- Separación de responsabilidades
- Jerarquía de roles implementada correctamente
- Verificación de asignación de roles

**Verificaciones comunes**:
```bash
# Verificar diferentes roles con diferentes permisos
curl -X GET http://target.com/admin/resource -H "Cookie: user_session=..."
curl -X GET http://target.com/user/resource -H "Cookie: admin_session=..."
```

### WSTG-IDNT-02: Test User Registration Process
**Objetivo**: Evaluar la seguridad del proceso de registro de usuarios
**Puntos a verificar**:
- Validación de entradas en el registro
- Protección contra registro automatizado (CAPTCHA)
- Verificación de email
- Políticas de nombres de usuario seguras
- Protección contra enumeración de usuarios

**Pruebas específicas**:
- Registro con datos inválidos
- Registro masivo automatizado
- Enumeración a través de mensajes de error
- Verificación de email bypass

### WSTG-IDNT-03: Test Account Provisioning Process
**Objetivo**: Evaluar el proceso de aprovisionamiento de cuentas
**Flujos a probar**:
- Aprovisionamiento automático vs manual
- Tiempo de activación de cuentas
- Aprobación requerida para nuevos usuarios
- Asignación de recursos por defecto
- Configuración inicial de privilegios

**Consideraciones**:
```python
# Ejemplo de prueba de aprovisionamiento
def test_account_provisioning():
    # 1. Registrar nuevo usuario
    # 2. Verificar estado inicial
    # 3. Probar acceso a recursos
    # 4. Verificar asignación de rol
```

### WSTG-IDNT-04: Testing for Account Enumeration and Guessable User Account
**Objetivo**: Identificar posibles vectores de enumeración de cuentas
**Técnicas de enumeración**:
- Respuestas diferenciadas en login/recuperación
- Mensajes de error específicos
- Funcionalidad de "¿Olvidaste tu contraseña?"
- Funciones de registro
- Páginas de perfil público

**Ejemplos de pruebas**:
```bash
# Enumeración por respuesta de servidor
curl -X POST http://target.com/login -d "username=admin&password=wrong"
curl -X POST http://target.com/login -d "username=nonexistent&password=wrong"

# Enumeración por timing
time curl -X POST http://target.com/forgot-password -d "email=admin@target.com"
time curl -X POST http://target.com/forgot-password -d "email=nonexistent@target.com"
```

### WSTG-IDNT-05: Testing for Weak or Unenforced Username Policy
**Objetivo**: Verificar políticas de nombres de usuario
**Políticas a evaluar**:
- Longitud mínima y máxima
- Caracteres permitidos/prohibidos
- Nombres de usuario predecibles
- Palabras comunes prohibidas
- Casesensitivity y normalización

**Pruebas recomendadas**:
- Registro con nombres de usuario comunes (admin, root, etc.)
- Nombres de usuario muy cortos o largos
- Caracteres especiales y Unicode
- Nombres de usuario simbólicos

## Herramientas Recomendadas
- **Automatización**: Burp Suite Intruder, OWASP ZAP Fuzzer
- **Enumeración**: Metasploit modules, custom scripts
- **Análisis de tiempo**: Time-based attack scripts
- **Automatización de registro**: Selenium, Puppeteer

## Checklist de Verificación

### Definición de Roles
- [ ] Roles definidos claramente
- [ ] Principio de mínimo privilegio implementado
- [ ] Separación de responsabilidades
- [ ] Auditoría de cambios de roles

### Registro de Usuarios
- [ ] Validación adecuada de entradas
- [ ] Protección contra automatización
- [ ] Verificación de identidad requerida
- [ ] Sin fugas de información en errores

### Aprovisionamiento
- [ ] Proceso de aprobación definido
- [ ] Asignación segura de recursos iniciales
- [ ] Logging de aprovisionamiento
- [ ] Revisión periódica de cuentas

### Políticas de Usuario
- [ ] Políticas de nombres de usuario robustas
- [ ] Protección contra enumeración
- [ ] Validación de formatos
- [ ] Detección de patrones inseguros

## Vectores de Ataque Comunes

### 1. Account Enumeration
- **Timing attacks**: Diferencias en tiempo de respuesta
- **Error messages**: Mensajes específicos que revelan existencia
- **Password reset**: Comportamiento diferenciado

### 2. Weak Username Policies
- **Predictable usernames**: admin, admin1, testuser
- **Case sensitivity**: User vs user como diferentes
- **Special characters**: Inyección a través de nombres

### 3. Registration Abuse
- **Mass registration**: Creación masiva de cuentas
- **Bypass verification**: Saltar verificación de email
- **Privilege escalation**: Registro con rol elevado

## Métricas de Evaluación

### Seguridad del Sistema
- Tiempo de respuesta consistente
- Mensajes de error genéricos
- Tasa de éxito/fallo consistente
- Políticas de nombre robustas

### Detección de Vulnerabilidades
- Intentos de enumeración detectados
- Registro anómalo identificado
- Validaciones implementadas
- Logging adecuado configurado

## Impacto de Vulnerabilidades

### Crítico
- Escalada de privilegios durante registro
- Bypass completo de autenticación
- Acceso no autorizado a cuentas administrativas

### Alto
- Enumeración masiva de usuarios
- Creación automatizada de cuentas maliciosas
- Fuga de información de usuarios

### Medio
- Políticas débiles de nombres de usuario
- Aprovisionamiento inseguro de recursos
- Logging insuficiente

## Recomendaciones de Seguridad

### Implementación
1. **Validación robusta**: Validar todos los inputs según políticas estrictas
2. **Mensajes genéricos**: Usar respuestas consistentes independientemente del resultado
3. **Rate limiting**: Implementar límites para prevenir ataques de fuerza bruta
4. **Verificación obligatoria**: Requerir verificación de email/telefono

### Monitoreo
1. **Logging detallado**: Registrar todos los eventos de gestión de identidades
2. **Análisis de comportamiento**: Detectar patrones anómalos
3. **Alertas**: Configurar notificaciones para actividades sospechosas
4. **Auditoría regular**: Revisar periódicamente las cuentas existentes

### Diseño
1. **Principio de mínimo privilegio**: Dar solo los permisos necesarios
2. **Segregación de duties**: Separar responsabilidades críticas
3. **Ciclo de vida claro**: Definir procesos claros de creación, modificación y eliminación
4. **Defensa en profundidad**: Múltiples capas de validación y control

## Escenarios de Prueba

### Escenario 1: Enumeración por Password Reset
```python
# Script para probar enumeración
def test_password_reset_enumeration():
    usernames = ["admin", "user1", "nonexistent"]
    responses = {}

    for username in usernames:
        response = requests.post('/reset-password',
                               data={'username': username})
        responses[username] = {
            'status': response.status_code,
            'content': response.text[:200]
        }

    return responses
```

### Escenario 2: Validación de Registro
```python
# Prueba de validación de políticas de nombre
def test_username_policy():
    test_usernames = [
        "a",  # Demasiado corto
        "user" * 100,  # Demasiado largo
        "admin",  # Nombre reservado
        "user@domain.com",  # Caracteres especiales
        "测试用户",  # Unicode
    ]

    results = {}
    for username in test_usernames:
        response = requests.post('/register',
                               data={'username': username,
                                   'password': 'Test123!'})
        results[username] = response.status_code

    return results
```

## Referencias
- OWASP Testing Guide - Identity Management Testing
- NIST SP 800-63B - Digital Identity Guidelines
- ISO/IEC 24760-1 - Identity management framework
- CWE-204: Observable Response Discrepancy
- CWE-613: Insufficient Session Expiration
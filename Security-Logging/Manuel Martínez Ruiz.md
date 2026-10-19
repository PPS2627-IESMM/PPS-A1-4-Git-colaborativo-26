# Exposición de datos sensibles en logs de aplicación
## Clasificación
* Categoría OWASP Top 10: [A09:2025-Security Logging and Alerting Failures]
* Control OWASP ASVS: [V7.1.1 (ASVS 4.0.3)] 
* Documentado por: [Manuel Martínez Ruiz]
---
## Descripción
Se produce cuando una aplicación registra en sus logs información sensible, como contraseñas, tokens de sesión, claves de API, números de tarjeta o datos personales (DNI, correo, dirección). Los logs suelen tener menos protección que la base de datos: se almacenan en texto plano, se copian a servidores de terceros (SIEM, herramientas de monitorización), se comparten con soporte técnico y se conservan durante mucho tiempo. Cualquier persona o atacante con acceso a ellos puede leer esos datos sin necesidad de vulnerar la aplicación.

## Ejemplo de código vulnerable

```python
import logging

logging.basicConfig(level=logging.INFO, filename="app.log")

def iniciar_sesion(usuario, password):
    logging.info(f"El usuario {usuario} ha iniciado sesión con la contraseña {password}")
    # ... validación de credenciales ...
```

Cada inicio de sesión deja en `app.log` el usuario y su contraseña en texto plano. Cualquiera con acceso de lectura al archivo (un atacante, un administrador, una herramienta de monitorización o un backup) puede obtener credenciales válidas. Además, el problema se agrava si el nivel de log es DEBUG, porque suelen registrarse también cabeceras, tokens y cuerpos de petición.

## Código mitigado/seguro

```python
import logging

logging.basicConfig(level=logging.INFO, filename="app.log")

def iniciar_sesion(usuario, password):
    logging.info(f"El usuario {usuario} ha iniciado sesión")
    # ... validación de credenciales ...
```

La contraseña ya no se registra. Solo se deja constancia del evento (quién inició sesión), que es lo necesario para auditar

## Referencias

* OWASP Top 10:2025 - A09 Security Logging and Alerting Failures
* OWASP ASVS (V7.1.1 en 4.0.3)
* OWASP Logging Cheat Sheet
* CWE-532

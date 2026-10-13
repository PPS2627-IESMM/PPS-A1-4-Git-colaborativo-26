# Exposición de datos sensibles en logs de aplicación
## Clasificación
* Categoría OWASP Top 10: [A09:2025-Security Logging and Alerting Failures]
* Control OWASP ASVS: [V16.2.5]
* Documentado por: [Manuel Martínez Ruiz]
---
## Descripción
Se trata de una vulnerabilidad en el que la información sensible de los logs quedan expuestos para los ciberatacantes. Información como contraseñas, datos personales, etcétera.

## Ejemplo de código vulerable
* logging.info(f"El usuario {usuario} ha iniciado sesión con la contraseña {password}")
En este código se muestra como información como la contraseña es emitida, pudiendo ser leída por un agente malicioso.

## Código mitigado/seguro
* logging.info(f"El usuario {usuario} ha iniciado sesión")
En este ejemplo, la contraseña no es revelada por lo que un agente externo no sería capaz de interceptarla. Es una buena práctica de código.

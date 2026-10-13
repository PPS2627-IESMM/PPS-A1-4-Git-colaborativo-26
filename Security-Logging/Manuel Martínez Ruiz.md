# [Nombre de la vulnerabilidad]
## Clasificación
* Categoría OWASP Top 10: [Formato AXX:XXXX-Nombre]
* Control OWASP ASVS: [Formato VN.N.N]
* Documentado por: [Manuel Martínez Ruiz]
---
## Descripción
Se trata de una vulnerabilidad en el que la información sensible de los logs quedan expuestos para los ciberatacantes. Información como contraseñas, datos personales, etcétera.

## Ejemplo de código vulerable
* logging.info(f"El usuario {usuario} ha iniciado sesión con la contraseña {password}")
En este código se muestra como información como la contraseña es emitida, pudiendo ser leída por un agente malicioso.

## Código mitigado/seguro
* logging.info(f"El usuario {usuario} ha iniciado sesión")
En este ejemplo, la contraseña no es revelada por lo que un agente externo no sería capaz de interceptarla.

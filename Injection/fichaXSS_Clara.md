# [Nombre de la vulnerabilidad]
Cross Site Scripting (XSS) Reflejado
## Clasificación
* Categoría OWASP Top 10: A05:2021/2025-Inyección
* Control OWASP ASVS: [Formato VN.N.N]
* Documentado por: Clara Frigolet Paiva
---
## Descripción
El XSS reflejado es una vulnerabilidad que permite a un atacante inyectar código JavaScript en una página que luego se ejecuta en el navegador de otro usuario. No ataca al servidor, ataca a quien visita la web después del atacante. En el caso de XSS reflejado, el script viaja en la propia URL o en un parámetro de un formulario. 

En una aplicación en producción, al ejecutarse el código malicioso directamente en el navegador del usuario, el atacante puede saltarse los mecanismos de seguridad de la aplicación y actuar en su nombre, pudiendo suplantar su identidad, modificar elementos de la página con JavaScript para hacer phishing y robar credenciales. 

## Ejemplo de código vulerable
Puedes usar el lenguaje que quiera, pero el código debe estar completamente comentado explicándolo.

## Código mitigado/seguro
Incluye el código anterior corregido (sanitizado)

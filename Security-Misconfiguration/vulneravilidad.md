# Exposición de pila de errores en producción

## Clasificación

* **Categoría OWASP Top 10:** A05:2021-Security Misconfiguration
* **Control OWASP ASVS:** V7.4.1 (v4.0.3)
* **Documentado por:** Marcos Ruiz

---

## Descripción

Esta vulnerabilidad ocurre cuando una aplicación muestra al usuario el *stack trace* o mensajes de error internos. En producción, esta información puede revelar rutas, clases, tecnologías y detalles de implementación que faciliten futuros ataques.

## Ejemplo de código vulnerable

```java
catch (Exception e) {
    // Establece el código HTTP de error interno.
    response.setStatus(500);

    // VULNERABLE: expone el mensaje interno de la excepción.
    response.getWriter().println(e.getMessage());

    // VULNERABLE: revela el stack trace al usuario.
    e.printStackTrace(response.getWriter());
}
```

## Código mitigado/seguro

```java
catch (Exception e) {
    // Registra la excepción únicamente en los logs del servidor.
    LOGGER.log(Level.SEVERE, "Error interno", e);

    // Devuelve un código de error sin revelar detalles internos.
    response.setStatus(500);

    // Muestra un mensaje genérico al usuario.
    response.getWriter().println("Error interno del servidor.");
}
```

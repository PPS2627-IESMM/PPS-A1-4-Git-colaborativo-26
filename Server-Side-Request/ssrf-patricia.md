# SSRF - Falsificación de Peticiones del Lado del Servidor

## Clasificación

- **Categoría OWASP Top 10:** A10:2021 - Server-Side Request Forgery (SSRF)
- **Control OWASP ASVS 4.0.3:** V12.6.1 - Protección contra SSRF
- **Documentado por:** Patricia García Pérez - Equipo 8

## Descripción

SSRF es una vulnerabilidad que aparece cuando una aplicación permite que el servidor haga peticiones a direcciones proporcionadas por los usuarios sin comprobar si son seguras.

Por ejemplo, una página web permite introducir una URL para descargar una imagen. Si no comprueba esa dirección, un atacante podría conseguir que el servidor acceda a servicios internos de la empresa.

Esto puede provocar el acceso a información privada o a servicios que normalmente no están disponibles desde Internet.

## Ejemplo de código vulnerable

Ejemplo en Python utilizando la librería requests:

```python
import requests  # Librería para realizar peticiones HTTP

# Pedimos al usuario una dirección web.
url = input("Introduce la URL de la imagen: ")

# VULNERABILIDAD: no comprobamos si la dirección es segura.
# El servidor intenta acceder a cualquier URL introducida.
respuesta = requests.get(url, timeout=5)

# Mostramos el resultado de la petición.
print("Código de respuesta:", respuesta.status_code)
```

**¿Dónde está el fallo?**

El programa acepta cualquier dirección sin validarla. Un atacante podría introducir una URL que apunte a un servicio interno y conseguir que el servidor realice la petición.

## Código mitigado/seguro

En este ejemplo limitamos las peticiones a una dirección previamente autorizada.

```python
import requests  # Librería para realizar peticiones HTTP

# Definimos las únicas direcciones que permitimos consultar.
urls_permitidas = {
    "https://www.example.com/imagen.jpg"
}

# Pedimos al usuario la dirección de la imagen.
url = input("Introduce la URL de la imagen: ")

# Comprobamos que la dirección esté en nuestra lista autorizada.
if url in urls_permitidas:
    # Solo realizamos la petición si la URL está permitida.
    # Desactivamos las redirecciones para evitar cambios de destino.
    respuesta = requests.get(
        url,
        timeout=5,
        allow_redirects=False
    )
    print("Código de respuesta:", respuesta.status_code)
else:
    # Rechazamos cualquier dirección que no esté autorizada.
    print("Acceso denegado: URL no permitida")
```

**¿Por qué es más seguro?**

Ahora el programa no acepta cualquier URL. Solo permite consultar la dirección que hemos autorizado previamente y no sigue redirecciones.

Este ejemplo es una demostración sencilla. En una aplicación real también habría que controlar la resolución DNS, las direcciones IP y las conexiones de red para evitar otras formas de SSRF.

## Referencias

- OWASP Top 10 (2021): https://top10.owasp.org/2021/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/
- OWASP ASVS 4.0.3: https://github.com/OWASP/ASVS/blob/master/4.0/en/0x20-V12-Files-Resources.md

# Ficha de Seguridad: Server-Side Request Forgery (SSRF)

- **Categoría OWASP Top 10:** A10:2021 - Server-Side Request Forgery (SSRF)
- **Control OWASP ASVS (v4.0.3):** V12.6.1 - Protección contra SSRF
- **Autor:** Raúl Díaz Ramos
- **Revisor asignado:** Patricia García Pérez

## 1. Descripción del fallo

El **SSRF** ocurre cuando un atacante consigue que un servidor haga peticiones a direcciones que no debería permitir, como otros equipos de la red interna.

Esto puede ocurrir cuando una aplicación utiliza una URL proporcionada por el usuario sin comprobarla.

- **Impacto:** Puede permitir el acceso a información privada o a servicios internos.

## 2. Ejemplo de código vulnerable

Este código recibe una URL y accede a ella sin comprobar si es segura.

```python
import requests
from flask import Flask, request

app = Flask(__name__)

@app.route('/fetch-image')
def fetch_image():
    # Se acepta la URL que envía el usuario.
    url = request.args.get('url')

    # El servidor accede a ella sin comprobarla.
    response = requests.get(url, timeout=5)

    return f'Contenido: {response.text[:200]}'
```

**Problema:** El usuario podría indicar una dirección interna para intentar acceder a información privada.

## 3. Ejemplo de código seguro

En este caso, el usuario solo puede elegir entre direcciones autorizadas por la aplicación.

```python
import requests
from flask import Flask, abort, request

app = Flask(__name__)

# Direcciones permitidas por la aplicación.
ALLOWED_SOURCES = {
    'logo': 'https://images.example.com/logo.png',
    'banner': 'https://images.example.com/banner.png'
}

@app.route('/fetch-image')
def fetch_image():
    # El usuario elige un recurso de la lista.
    source = request.args.get('source')

    # Se rechazan los recursos no autorizados.
    if source not in ALLOWED_SOURCES:
        abort(403, description='Recurso no autorizado')

    # Se obtiene la dirección desde la lista segura.
    url = ALLOWED_SOURCES[source]

    try:
        # No se permiten redirecciones automáticas.
        response = requests.get(
            url, timeout=5, allow_redirects=False
        )

        # Se rechazan las redirecciones.
        if response.is_redirect:
            abort(502, description='Redirección no permitida')

        response.raise_for_status()
        return f'Contenido: {response.text[:200]}'

    except requests.RequestException:
        abort(502, description='Error al obtener el recurso')
```

**¿Por qué es más seguro?**

- Solo permite elegir recursos de una lista.
- Evita seguir redirecciones automáticamente.
- Controla el tiempo de espera y los errores.

*Nota:* En una aplicación real también habría que comprobar las direcciones IP y controlar las conexiones de red para evitar otros ataques SSRF.

## 4. Referencias

- OWASP Top 10 (2021): https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/
- OWASP ASVS 4.0.3: https://github.com/OWASP/ASVS/blob/master/4.0/en/0x20-V12-Files-Resources.md
- OWASP SSRF Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
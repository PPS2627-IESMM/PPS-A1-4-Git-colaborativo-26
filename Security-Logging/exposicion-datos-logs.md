# Exposición de datos sensibles en logs de aplicación

## Clasificación
* Categoría OWASP Top 10: A09:2025-Security Logging and Alerting Failures
* Control OWASP ASVS: V16.2.5 (ASVS 5.0)
* Documentado por: Daniel López Núñez
---
## Descripción

Esta vulnerabilidad aparece cuando la aplicación escribe en sus logs información que nunca debería salir de la memoria o de la base de datos. Hablamos de contraseñas en texto claro, tokens de sesión o JWT, números de tarjeta, CVV o datos personales como el DNI, el email o el teléfono. Casi nunca se hace con mala intención. Las causas típicas son estas:

- Se vuelca el cuerpo completo de una petición para depurar.
- Se registran todas las cabeceras HTTP, incluidas `Authorization` y `Cookie`.
- Se deja el nivel `DEBUG` activo en producción.
- Se registra una excepción junto con el objeto que la provocó, o la propia excepción ya incluye el dato en su mensaje.

El problema es que los logs se protegen mucho peor que la base de datos:

- **Los lee mucha más gente:** desarrolladores, operaciones, soporte y proveedores externos.
- **Se replican:** acaban en el SIEM, en plataformas como ELK o en servicios de monitorización en la nube, y también en las copias de seguridad.
- **Duran mucho y casi nunca se cifran:** se conservan durante meses en texto plano.

**Impacto en producción:** cualquiera con acceso a los logs, ya sea un empleado, un proveedor o un atacante que haya comprometido un servidor secundario, consigue credenciales válidas. También puede secuestrar sesiones activas reutilizando el token y obtiene datos de pago listos para cometer fraude. Además, incumple directamente PCI DSS, que prohíbe almacenar el CVV después de la autorización, y el RGPD.

No es un fallo teórico. En 2018 Twitter tuvo que pedir a sus usuarios que cambiaran la contraseña porque un error las había dejado sin hashear en un log interno. En 2019 Facebook reconoció que cientos de millones de contraseñas estaban en texto claro en sus sistemas internos, y en 2024 la autoridad irlandesa de protección de datos le impuso una multa de 91 millones de euros por ello.

El control ASVS V16.2.5 lo resume así: cada dato se registra según su nivel de protección. Hay datos que no pueden registrarse nunca, como las credenciales o los datos de pago. Otros, como los tokens de sesión, solo pueden registrarse hasheados o enmascarados, total o parcialmente.

## Ejemplo de código vulnerable

API en Python 3 con Flask, con un endpoint de login y otro de pago.

**`app_vulnerable.py`**
```python
import logging
import secrets
from flask import Flask, request, jsonify

app = Flask(__name__)

# Configuración del logger.
# FALLO 1: nivel DEBUG en producción -> se registra absolutamente todo,
# incluidos los volcados de depuración pensados solo para desarrollo.
logging.basicConfig(
    filename="app_vulnerable.log",
    level=logging.DEBUG,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger("tienda")


# --- Funciones simuladas (no forman parte del fallo) ---
def autenticar(usuario, password):
    # En un caso real se compararía contra un hash bcrypt/argon2 en BD
    return usuario == "ana" and password == "S3cr3ta!"

def generar_token(usuario):
    return secrets.token_urlsafe(32)

def procesar_pago(tarjeta, cvv, importe):
    # La pasarela falla e incluye la tarjeta en el mensaje de la excepción
    raise ValueError(f"Pasarela rechaza la tarjeta {tarjeta}")


@app.route("/login", methods=["POST"])
def login():
    datos = request.get_json()

    # FALLO 2: se vuelca el cuerpo completo de la petición.
    # El JSON incluye la contraseña en texto claro, que queda escrita en disco.
    logger.debug(f"Petición de login recibida: {datos}")

    # FALLO 3: se registran todas las cabeceras HTTP.
    # Authorization (token Bearer) y Cookie (sesión) acaban en el log.
    logger.debug(f"Cabeceras: {dict(request.headers)}")

    usuario = datos.get("usuario")
    password = datos.get("password")

    if not autenticar(usuario, password):
        # FALLO 4: en un login fallido se guarda la contraseña probada.
        # Suele ser la contraseña real con una errata, o la de otro servicio
        # (el usuario se ha equivocado de web): es oro para un atacante.
        logger.warning(f"Login fallido para {usuario} con contraseña {password}")
        return jsonify({"error": "Credenciales incorrectas"}), 401

    token = generar_token(usuario)

    # FALLO 5: el token de sesión completo queda en el log.
    # Quien lea el fichero puede suplantar al usuario mientras el token siga vigente.
    logger.info(f"Login correcto: usuario={usuario} token={token}")
    return jsonify({"token": token})


@app.route("/pago", methods=["POST"])
def pago():
    datos = request.get_json()
    try:
        procesar_pago(datos["tarjeta"], datos["cvv"], datos["importe"])
    except Exception:
        # FALLO 6: logger.exception añade la traza completa, y aquí además
        # se concatena el diccionario entero con número de tarjeta y CVV.
        # El CVV no puede almacenarse nunca tras la autorización (PCI DSS).
        logger.exception(f"Error procesando el pago: {datos}")
        return jsonify({"error": "Error en el pago"}), 500

    # FALLO 7: número de tarjeta (PAN) completo en el log.
    logger.info(f"Pago realizado con tarjeta {datos['tarjeta']} por {datos['importe']} EUR")
    return jsonify({"estado": "ok"})
```

### Resultado en `app_vulnerable.log`
Esta es la salida real tras un login fallido, uno correcto y un pago con error. Se han omitido las marcas de tiempo y parte de las cabeceras.
```text
DEBUG tienda: Petición de login recibida: {'password': 'S3cr3ta1', 'usuario': 'ana'}
DEBUG tienda: Cabeceras: {..., 'Authorization': 'Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbmEifQ.abc123'}
WARNING tienda: Login fallido para ana con contraseña S3cr3ta1
INFO tienda: Login correcto: usuario=ana token=WJBJgE1SHfdy4xkg2hbCw3XOUMYE_qHwR5fRHF34lA0
ERROR tienda: Error procesando el pago: {'cvv': '123', 'importe': 49.99, 'tarjeta': '4111 1111 1111 1111'}
Traceback (most recent call last):
  ...
ValueError: Pasarela rechaza la tarjeta 4111 1111 1111 1111
```
Fíjate en el login fallido. La contraseña probada es `S3cr3ta1` y la real es `S3cr3ta!`, así que con el log en la mano un atacante la saca en pocos intentos.

## Código mitigado/seguro

La técnica es el **enmascaramiento en logs**, aplicado en dos capas:

1. **En el origen:** cada punto de log registra solo los campos que hacen falta, ya tratados. La contraseña y el CVV no se registran nunca, la tarjeta se enmascara y el token se hashea.
2. **Red de seguridad:** un `logging.Filter` en el handler enmascara con expresiones regulares cualquier dato sensible que se haya colado, también dentro de las trazas de excepción.

**`app_seguro.py`**
```python
import hashlib
import logging
import os
import re
import secrets
import uuid
from flask import Flask, request, jsonify

app = Flask(__name__)


class FiltroEnmascarado(logging.Filter):
    """
    Red de seguridad: enmascara datos sensibles en CUALQUIER registro que pase
    por el handler, aunque un desarrollador se equivoque y los registre.
    No sustituye a no loguear el dato: es una segunda capa (defensa en profundidad).
    """

    PATRONES = [
        # Números de tarjeta (13-19 dígitos, con espacios o guiones opcionales).
        # Se conservan solo los 4 últimos, el máximo que permite PCI DSS mostrar.
        (re.compile(r"\b(?:\d[ -]?){9,15}(\d{4})\b"), r"****-****-****-\1"),
        # Tokens Bearer en cabeceras Authorization.
        (re.compile(r"(Bearer\s+)[A-Za-z0-9\-._~+/]+=*", re.IGNORECASE), r"\1[REDACTADO]"),
        # Pares clave/valor con nombres sensibles, en formato clave=valor o JSON/dict.
        (re.compile(
            r"(?i)(['\"]?(?:password|passwd|pwd|contrase[ñn]a|cvv|token|secret|api_?key)['\"]?\s*[:=]\s*)"
            r"(['\"]?)[^'\"\s,}]+\2"
        ), r"\1\2[REDACTADO]\2"),
    ]

    def _enmascarar(self, texto: str) -> str:
        for patron, reemplazo in self.PATRONES:
            texto = patron.sub(reemplazo, texto)
        return texto

    def filter(self, record: logging.LogRecord) -> bool:
        # getMessage() une el mensaje con sus argumentos (%s) antes de enmascarar.
        mensaje = self._enmascarar(record.getMessage())
        # Extra: se neutralizan saltos de línea para evitar inyección en logs
        # (un atacante no puede falsificar líneas nuevas con su entrada).
        record.msg = mensaje.replace("\r", "\\r").replace("\n", "\\n")
        record.args = None
        # Las trazas de excepción también se enmascaran: el mensaje de una
        # excepción puede contener datos sensibles (p. ej. el número de tarjeta).
        if record.exc_info:
            traza = logging.Formatter().formatException(record.exc_info)
            record.exc_text = self._enmascarar(traza)
        return True  # True = el registro se escribe (ya enmascarado)


# Configuración del logger.
# Nivel según entorno: INFO por defecto en producción, DEBUG solo si se pide.
nivel = os.getenv("LOG_LEVEL", "INFO").upper()
handler = logging.FileHandler("app_seguro.log")
handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
# El filtro va en el HANDLER, no en el logger: así se aplica a todo lo que
# se escriba en el fichero, incluidos los registros de librerías de terceros.
handler.addFilter(FiltroEnmascarado())
logging.basicConfig(level=nivel, handlers=[handler])
logger = logging.getLogger("tienda")


# --- Funciones de enmascarado explícito ---
def enmascarar_tarjeta(pan: str) -> str:
    """Deja visibles solo los 4 últimos dígitos del PAN."""
    digitos = re.sub(r"\D", "", str(pan))
    return f"****-****-****-{digitos[-4:]}" if len(digitos) >= 4 else "****"

def huella_token(token: str) -> str:
    """
    ASVS V16.2.5: los tokens de sesión solo pueden registrarse hasheados o enmascarados.
    Un prefijo del SHA-256 permite correlacionar eventos de la misma sesión
    sin que nadie pueda reutilizar el token leyendo el log.
    """
    return "sha256:" + hashlib.sha256(token.encode()).hexdigest()[:12]


# --- Funciones simuladas (idénticas a la versión vulnerable) ---
def autenticar(usuario, password):
    return usuario == "ana" and password == "S3cr3ta!"

def generar_token(usuario):
    return secrets.token_urlsafe(32)

def procesar_pago(tarjeta, cvv, importe):
    raise ValueError(f"Pasarela rechaza la tarjeta {tarjeta}")


@app.route("/login", methods=["POST"])
def login():
    datos = request.get_json(silent=True) or {}
    usuario = str(datos.get("usuario", ""))
    password = datos.get("password", "")

    # CORREGIDO: ya no se vuelca el cuerpo ni las cabeceras. Se registra solo
    # lo necesario para investigar (quién, desde dónde, qué ha pasado).

    if not autenticar(usuario, password):
        # CORREGIDO: se registra el evento de seguridad (útil para detectar
        # fuerza bruta, ASVS V16.3.1) pero NUNCA la contraseña probada.
        logger.warning("Login fallido usuario=%s ip=%s", usuario, request.remote_addr)
        return jsonify({"error": "Credenciales incorrectas"}), 401

    token = generar_token(usuario)

    # CORREGIDO: en lugar del token se guarda su huella irreversible.
    logger.info("Login correcto usuario=%s ip=%s sesion=%s",
                usuario, request.remote_addr, huella_token(token))
    return jsonify({"token": token})


@app.route("/pago", methods=["POST"])
def pago():
    datos = request.get_json(silent=True) or {}
    # Identificador de operación: permite cruzar el log con la BD de pagos
    # sin necesidad de guardar el número de tarjeta.
    id_operacion = uuid.uuid4().hex[:8]
    tarjeta_mask = enmascarar_tarjeta(datos.get("tarjeta", ""))

    try:
        procesar_pago(datos["tarjeta"], datos["cvv"], datos["importe"])
    except Exception:
        # CORREGIDO: solo campos concretos y enmascarados; el CVV no aparece.
        # exc_info=True mantiene la traza para depurar, y el filtro la enmascara.
        logger.error("Error en pago op=%s tarjeta=%s", id_operacion, tarjeta_mask, exc_info=True)
        return jsonify({"error": "Error en el pago"}), 500

    logger.info("Pago realizado op=%s tarjeta=%s importe=%s EUR",
                id_operacion, tarjeta_mask, datos.get("importe"))
    return jsonify({"estado": "ok"})
```

### Resultado en `app_seguro.log`
Estas son las mismas peticiones que antes. La última línea simula un log descuidado que un desarrollador deja en el código, y que el filtro intercepta.
```text
WARNING tienda: Login fallido usuario=ana ip=127.0.0.1
INFO tienda: Login correcto usuario=ana ip=127.0.0.1 sesion=sha256:3830498d203c
ERROR tienda: Error en pago op=73798f7e tarjeta=****-****-****-1111
Traceback (most recent call last):
  ...
ValueError: Pasarela rechaza la tarjeta ****-****-****-1111
INFO tienda: Debug olvidado: {'password': '[REDACTADO]', 'cvv': '[REDACTADO]', 'tarjeta': '****-****-****-0004'}
```

### Claves de la mitigación

| Dato | Tratamiento en el log |
|---|---|
| Contraseña, CVV | No se registran nunca, ni siquiera hasheados |
| Número de tarjeta (PAN) | Enmascarado; solo se ven los 4 últimos dígitos |
| Token de sesión / JWT | Huella SHA-256 truncada: sirve para correlacionar sin poder reutilizarlo |
| Usuario, IP, resultado | Sí se registran: hacen falta para detectar ataques (ASVS V16.3.1) |

* **Hashear el token sí es seguro.** El token es aleatorio de 256 bits, así que su hash no se puede invertir por fuerza bruta. Con una contraseña no pasaría, porque es predecible, y por eso no se registra de ninguna forma.
* **El filtro con regex es la segunda capa, no la principal.** Solo detecta los formatos que conoce, así que la defensa real es no pasar el dato al logger.
* **El nivel `INFO` se fija por variable de entorno.** Así el `DEBUG` no llega a producción por descuido.
* **Los saltos de línea se neutralizan.** Esto evita la inyección en logs (ASVS V16.4.1), es decir, que un atacante falsifique líneas con su entrada.
* **Los propios logs se protegen.** El fichero debe tener permisos restrictivos y enviarse a un sistema separado para su análisis (ASVS V16.4.2 y V16.4.3).

## Referencias
* [OWASP Top 10:2025 - A09 Security Logging and Alerting Failures](https://owasp.org/Top10/2025/A09_2025-Security_Logging_and_Alerting_Failures/)
* [OWASP ASVS 5.0 - V16 Security Logging and Error Handling](https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x25-V16-Security-Logging-and-Error-Handling.md)
* [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)

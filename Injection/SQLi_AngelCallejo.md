# Inyección SQL (SQLi)
## Clasificación
* Categoría OWASP Top 10: A03:2021 - Injection
* Control OWASP ASVS: V1.2.4
* Documentado por: Ángel Callejo Galán
---
## Descripción
La Inyección SQL (SQLi) es una vulnerabilidad de seguridad que permite a un atacante interferir con las consultas que una aplicación realiza a su base de datos. Esto puede permitir el acceso no autorizado a información sensible, la modificación o eliminación de datos, según los permisos de la cuenta utilizada por la aplicación.

## Ejemplo de código vulnerable

```python
import sqlite3

def buscar_usuario(nombre_usuario):
    # Conexión a la base de datos de prueba
    conexion = sqlite3.connect('usuarios.db')
    cursor = conexion.cursor()

    # PELIGROSO: la entrada se concatena directamente en la consulta SQL.
    # Una entrada manipulada puede cambiar el significado de la consulta.
    consulta = "SELECT * FROM usuarios WHERE username = '" + nombre_usuario + "'"

    cursor.execute(consulta)
    resultados = cursor.fetchall()
    conexion.close()
    return resultados
```

### Explicación

`nombre_usuario` se incorpora directamente a la cadena SQL. Por tanto, el contenido recibido deja de ser tratado únicamente como un dato y puede modificar la estructura de la consulta. El problema está en la concatenación, no en `sqlite3.connect()` ni en `fetchall()`.

## Código mitigado/seguro

```python
import sqlite3

def buscar_usuario_seguro(nombre_usuario):
    # Conexión a la base de datos de prueba
    conexion = sqlite3.connect('usuarios.db')
    cursor = conexion.cursor()

    # SEGURO: ? es un marcador de parámetro.
    consulta = "SELECT * FROM usuarios WHERE username = ?"

    # El valor se envía separado del código SQL.
    cursor.execute(consulta, (nombre_usuario,))
    resultados = cursor.fetchall()
    conexion.close()
    return resultados
```

### Explicación

`?` reserva el lugar del valor sin incorporarlo al texto SQL. `cursor.execute(consulta, (nombre_usuario,))` pasa el nombre como parámetro y SQLite lo trata como dato literal, aunque contenga comillas u otros caracteres especiales. Esta separación entre código y datos evita que el usuario cambie la intención de la consulta.

La parametrización debe utilizarse también en consultas `INSERT`, `UPDATE` y `DELETE`. Para nombres de tablas, columnas u opciones de ordenación, que no pueden pasarse como valores, se debe utilizar una lista permitida definida por la aplicación.
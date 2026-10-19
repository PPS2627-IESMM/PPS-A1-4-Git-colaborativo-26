# Exposición de información sensible en mensajes de error (Stack Trace Leakage)

## Clasificación
- Categoría OWASP Top 10: A05:2021-Security Misconfiguration
- Control OWASP ASVS: V7.4.1
- Documentado por: Adrián Rojas

---

## Descripción
Ocurre cuando la aplicación no gestiona adecuadamente las excepciones internas y devuelve al usuario trazas del sistema (*stack traces*) o errores de base de datos.

**Impacto en producción:**
- Revela rutas internas del servidor (`/home/ubuntu/...`) y versiones de dependencias.
- Facilita ataques dirigidos (como inyecciones SQL) al mostrar la consulta fallida completa.

---

## Ejemplo de código vulnerable

```javascript
// Importamos Express (framework web) y el módulo propio de acceso a la base de datos
const express = require('express');
const db = require('./db');

// Creamos la aplicación Express
const app = express();

// FALLO 1: no se fuerza el modo producción.
// Si la variable de entorno NODE_ENV no vale "production", Express
// devuelve la traza completa en los errores no controlados.

// Ruta que devuelve un usuario a partir de su ID
app.get('/usuarios/:id', async (req, res) => {
  try {
    // Consulta a la base de datos. Puede lanzar errores (conexión, sintaxis SQL, etc.)
    // Además, concatena la entrada del usuario directamente en la consulta (otro fallo: SQLi)
    const usuario = await db.query('SELECT * FROM usuarios WHERE id = ' + req.params.id);
    res.json(usuario);
  } catch (err) {
    // FALLO 2: se devuelve el error completo al cliente.
    // err.message puede incluir la consulta SQL o el host de la base de datos,
    // y err.stack incluye rutas internas del servidor (ej. /home/ubuntu/app/db.js:42).
    res.status(500).json({
      error: err.message,
      stack: err.stack
    });
  }
});

// FALLO 3: manejador global de errores que reenvía todo el detalle al navegador.
// Cualquier excepción no controlada muestra la traza completa al usuario.
app.use((err, req, res, next) => {
  res.status(500).send('<pre>' + err.stack + '</pre>');
});

// Arrancamos el servidor en el puerto 3000
app.listen(3000);
```

Si un atacante pide `/usuarios/'`, recibe algo como esto:

```json
{
  "error": "ER_PARSE_ERROR: You have an error in your SQL syntax near ''' at line 1",
  "stack": "Error: ER_PARSE_ERROR ...\n    at Query.Sequence._packetToError (/home/ubuntu/app/node_modules/mysql/lib/protocol/sequences/Sequence.js:47:14)\n    at /home/ubuntu/app/db.js:42:11"
}
```

---

## Código mitigado/seguro

```javascript
// Importamos Express, el módulo de crypto (para generar IDs únicos),
// la base de datos y un logger interno (por ejemplo winston o pino)
const express = require('express');
const crypto = require('crypto');
const db = require('./db');
const logger = require('./logger');

const app = express();

// CORRECCIÓN 1: ejecutar siempre con NODE_ENV=production en el despliegue
// (ej. NODE_ENV=production node app.js). Así Express no incluye trazas en las respuestas.

// Ruta que devuelve un usuario a partir de su ID
app.get('/usuarios/:id', async (req, res, next) => {
  try {
    // Consulta parametrizada: el ID viaja como parámetro y no se concatena
    // (esto además evita la inyección SQL del ejemplo anterior)
    const usuario = await db.query('SELECT * FROM usuarios WHERE id = ?', [req.params.id]);

    if (!usuario) {
      // Error controlado con un mensaje genérico, sin detalles internos
      return res.status(404).json({ error: 'Recurso no encontrado' });
    }
    res.json(usuario);
  } catch (err) {
    // CORRECCIÓN 2: no se responde con el error aquí;
    // se delega en el manejador global con next(err)
    next(err);
  }
});

// CORRECCIÓN 3: manejador global de errores.
// Debe declararse después de todas las rutas.
app.use((err, req, res, next) => {
  // Generamos un identificador único para relacionar la respuesta con el log
  const errorId = crypto.randomUUID();

  // El detalle completo (mensaje y stack) se guarda SOLO en el log del servidor,
  // que no es accesible desde fuera
  logger.error({ errorId, message: err.message, stack: err.stack, url: req.originalUrl });

  // Al cliente solo se le envía un mensaje genérico y el ID de referencia
  res.status(500).json({
    error: 'Error interno del servidor',
    referencia: errorId
  });
});

// Arrancamos el servidor en el puerto 3000
app.listen(3000);
```

Con este código el atacante solo recibiría esto:

```json
{
  "error": "Error interno del servidor",
  "referencia": "3f2a9c1e-7b64-4d8a-9a51-0c2d6e4b8f10"
}
```
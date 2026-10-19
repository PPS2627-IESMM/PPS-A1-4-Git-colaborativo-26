# Falta de límite de intentos de inicio de sesión por cuenta (Rate Limiting)

## Clasificación

- Categoría OWASP Top 10: A07:2025-Authentication Failures
    
- Control OWASP ASVS: V2.2.1 (ASVS 4.0.3)
    
- Documentado por: Kevin Mejías Pérez
    

---

## Descripción

Esta vulnerabilidad aparece cuando una aplicación permite realizar intentos de inicio de sesión ilimitados contra una misma cuenta.

Un atacante puede automatizar pruebas de contraseñas mediante ataques de fuerza bruta o utilizar credenciales filtradas de otros servicios. Si no existe un límite por cuenta, puede continuar probando contraseñas incluso cambiando de dirección IP.

Esto puede provocar el acceso no autorizado a cuentas y el robo de información personal. Para evitarlo, se deben contabilizar los intentos fallidos y aplicar restricciones temporales cuando se supere el límite establecido.

## Ejemplo de código vulnerable

```
<?php
// Recibimos las credenciales enviadas desde el formulario de login.
$email = $_POST['email'] ?? '';
$password = $_POST['password'] ?? '';

// Buscamos al usuario en la base de datos mediante su correo.
$user = findUserByEmail($email);

// Comprobamos si el usuario existe y si la contraseña coincide
// con el hash almacenado en la base de datos.
if ($user && password_verify($password, $user['password_hash'])) {

    // Si las credenciales son correctas, permitimos el acceso.
    echo "Inicio de sesión correcto";

} else {

    // Si las credenciales son incorrectas, mostramos un error.
    // VULNERABILIDAD: No se registran los fallos ni se limita
    // el número de intentos realizados contra esta cuenta.
    // Un atacante puede repetir el proceso tantas veces como quiera.
    http_response_code(401);
    echo "Credenciales incorrectas";
}

// Función de ejemplo para simular la búsqueda del usuario.
// En una aplicación real, consultaría la base de datos.
function findUserByEmail($email) {
    return null;
}
```

## Código mitigado/seguro

```
<?php
// Conectamos con Redis para almacenar los intentos entre peticiones.
// Redis debe estar configurado y disponible en el servidor.
$redis = new Redis();
$redis->connect('127.0.0.1', 6379);

// Recibimos las credenciales del formulario.
$email = $_POST['email'] ?? '';
$password = $_POST['password'] ?? '';

// Normalizamos el identificador para que el mismo correo
// siempre utilice el mismo contador de intentos.
$emailNormalizado = strtolower(trim($email));

// Creamos una clave de Redis para contar los fallos de esa cuenta.
// En producción conviene proteger este identificador con un hash.
$clave = 'login_fallos:' . hash('sha256', $emailNormalizado);

// Permitimos un máximo de cinco intentos fallidos en quince minutos.
$maxIntentos = 5;
$ventana = 900;

// Consultamos cuántos intentos fallidos acumula la cuenta.
$intentos = (int) ($redis->get($clave) ?: 0);

// Si se ha alcanzado el límite, detenemos el inicio de sesión.
if ($intentos >= $maxIntentos) {
    http_response_code(429);
    exit('Demasiados intentos. Inténtelo más tarde.');
}

// Buscamos al usuario y verificamos su contraseña.
$user = findUserByEmail($emailNormalizado);

if ($user && password_verify($password, $user['password_hash'])) {

    // Si el acceso es correcto, eliminamos el contador de fallos.
    $redis->del($clave);

    echo "Inicio de sesión correcto";

} else {

    // Registramos el intento fallido de forma atómica.
    // INCR incrementa el contador y devuelve su nuevo valor.
    $intentos = $redis->incr($clave);

    // La primera vez establecemos una caducidad de quince minutos.
    if ($intentos === 1) {
        $redis->expire($clave, $ventana);
    }

    // No revelamos si el correo existe en la aplicación.
    http_response_code(401);
    echo "Credenciales incorrectas";
}

// Función de ejemplo para simular la búsqueda del usuario.
function findUserByEmail($email) {
    return null;
}
```

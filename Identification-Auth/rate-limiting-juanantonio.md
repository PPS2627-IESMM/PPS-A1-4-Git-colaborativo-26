# Falta de límite de intentos (Rate Limiting)
## Clasificación
- Categoría OWASP Top 10: A07:2025-Authentication Failures
- Control OWASP ASVS: V2.2.1
- Documentado por: Juan Antonio Jiménez Hornillo
---
## Descripción
La falta de límite de intentos (*Rate Limiting*) ocurre cuando una aplicación expone endpoints sensibles (como `/login` o `/reset-password`) sin restringir el número ni la frecuencia de peticiones que un cliente puede emitir en un lapso de tiempo determinado.

En entornos de producción, esta vulnerabilidad permite a atacantes automatizar ataques de fuerza bruta y *credential stuffing* para adivinar contraseñas sin bloqueos ni retrasos. Asimismo, provoca riesgos de denegación de servicio (DoS) a nivel de aplicación al forzar la ejecución masiva de cálculos criptográficos de verificación de hashes (como bcrypt o Argon2), saturando la CPU y la base de datos del servidor.

## Ejemplo de código vulerable
```php
<?php
// Endpoint vulnerable en PHP puro: login.php
header('Content-Type: application/json');

$email =$_POST['email'] ?? '';
$password =$_POST['password'] ?? '';

// PELIGRO: No se valida el número de intentos previos desde esta IP o usuario.
// Un atacante puede ejecutar un script automatizado enviando miles de peticiones
// por minuto sin penalización temporal ni bloqueo.
$user = findUserByEmail($email);

// password_verify() consume ciclos deliberados de CPU.
// Al permitir peticiones infinitas, un bot puede saturar el servidor o adivinar la clave.
if ($user && password_verify($password,$user['password_hash'])) {
    echo json_encode(['status' => 'success', 'token' => 'jwt_token_demo']);
} else {
    // Retorna error 401, pero no registra el intento fallido ni restringe reintentos inmediatos.
    http_response_code(401);
    echo json_encode(['status' => 'error', 'message' => 'Credenciales inválidas']);
}

function findUserByEmail($email) {
    return ['password_hash' => '$2y$10$e8wF...hashDemo'];
}
```
## Código mitigado/seguro
```php
<?php
// Endpoint mitigado en PHP utilizando Redis con operaciones atómicas
header('Content-Type: application/json');

$redis = new Redis();
$redis->connect('127.0.0.1', 6379);

// Identificamos el origen por IP
$ip = $_SERVER['REMOTE_ADDR'];
$rateKey = "login_attempts:" . $ip;

$maxAttempts = 5;
$windowSeconds = 900; // Ventana de 15 minutos (900s)

// MITIGACIÓN ATÓMICA: Incrementamos directamente en Redis.
// Al usar incr(), evitamos condiciones de carrera entre lectura y escritura.
$currentAttempts = $redis->incr($rateKey);

// Si es la primera petición (devuelve 1), fijamos el tiempo de expiración (TTL)
// para evitar que la clave quede persistente indefinidamente si el script falla después.
if ($currentAttempts === 1) {
    $redis->expire($rateKey, $windowSeconds);
}

// Comprobamos el límite antes de procesar lógica pesada o hashes criptográficos
if ($currentAttempts > $maxAttempts) {
    http_response_code(429);
    echo json_encode([
        'status' => 'error',
        'message' => 'Demasiados intentos fallidos. Inténtelo de nuevo en 15 minutos.'
    ]);
    exit;
}

$email = $_POST['email'] ?? '';
$password = $_POST['password'] ?? '';
$user = findUserByEmail($email);

if ($user && password_verify($password, $user['password_hash'])) {
    // Si la autenticación es exitosa, reseteamos el contador de la IP
    $redis->del($rateKey);
    echo json_encode(['status' => 'success', 'token' => 'jwt_token_demo']);
} else {
    // Retornamos 401 si falla; el incremento ya fue contabilizado atómicamente al inicio
    http_response_code(401);
    echo json_encode(['status' => 'error', 'message' => 'Credenciales inválidas']);
}

function findUserByEmail($email) {
    return ['password_hash' => '$2y$10$e8wF...hashDemo'];
}

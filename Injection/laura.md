# Inyección SQL (SQLi)
## Clasificación
* Categoría OWASP Top 10: A03:2025-Injection
* Control OWASP ASVS: V1.2.4
* Documentado por: Laura Castillo Ortiz
---
## Descripción
La inyección SQL (SQLi) es una vulnerabilidad que permite a un atacante interferir con las consultas que una aplicación envía a su base de datos. Esto, en una aplicación en producción, puede ser catastrófico ya que puede resultar en la filtración de datos personales, credenciales, información financiera, etc. Así como la manipulación o borrado de datos, inyección de malware y caídas de servicio, con las consecuencias legales y de pérdida de confianza y prestigio que eso supone para la empresa.

## Ejemplo de código vulerable
```php
<?php

// Conexión a la BBDD
$conn = new mysqli("localhost", "user", "psswd", "db_name");

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
	// 1. Recoge los datos del input directamente
	$user = $_POST['username'];
	$psswd = $_POST['password'];

	// 2. Consulta a la BBDD
	$qry = "SELECT * FROM usuarios WHERE user = '$user' AND pass = '$psswd'"; // <-- AQUÍ: El texto crudo se pasa directamente al motor SQL.

	$res = $conn->query($qry);

	if ($res && $res->num_rows > 0) {
		echo "Login exitoso.";
	} else {
		echo "Credenciales incorrectas.";
	}
}
?>
```
## Código mitigado/seguro
```php
<?php
// Conexión segura usando PDO
try {
	$pdo = new PDO("", "", "");
	$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
	die("Error de conexión: " . $e->getMessage());
}
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
        // 1. Recoge los datos del input directamente
        $user = $_POST['username'] ?? '';
        $psswd = $_POST['password'] ?? '';

        // 2. Consulta segura a la BBDD usando sentencias preparadas (Prepared Statements)
        $stmt = $pdo->prepare("SELECT * FROM usuarios WHERE user = :user AND pass = :pass");
        
        // Ejecución pasando los parámetros de forma separada para evitar SQLi
        $stmt->execute([
                'user' => $user,
                'pass' => $psswd
        ]);

        if ($stmt->rowCount() > 0) {
                echo "Login exitoso.";
        } else {
                echo "Credenciales incorrectas.";
        }
}
?>
```

En un entorno real, las contraseñas deben almacenarse usando hashes seguros (con `password_hash()`) y validarse con `password_verify()`.
De esta manera el código quedaría tal que:
```php
<?php
// Conexión segura usando PDO
try {
        $pdo = new PDO("mysql:host=localhost;dbname=db_name;charset=utf8mb4", "user", "psswd");
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
        die("Error de conexión: " . $e->getMessage());
}

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
        $user =$_POST['username'] ?? '';
        $psswd =$_POST['password'] ?? '';

        // 1. Consulta segura usando Prepared Statements para evitar SQLi
        $stmt =$pdo->prepare("SELECT password_hash FROM usuarios WHERE user = :user");
        $stmt->execute(['user' =>$user]);
        $usuario =$stmt->fetch(PDO::FETCH_ASSOC);

        // 2. Verificación segura de la contraseña mediante hash
        if ($usuario && password_verify($psswd,$usuario['password_hash'])) {
                echo "Login exitoso.";
        } else {
                echo "Credenciales incorrectas.";
        }
}
?>
```

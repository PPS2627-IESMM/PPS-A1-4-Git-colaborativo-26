
# Contraseñas almacenadas en texto plano/MD5
## Clasificación
* Categoría OWASP Top 10: A02:2021 – Cryptographic Failure
* Control OWASP ASVS: V6.2.5 – Uso de algoritmos criptográficos débiles, como MD5 y SHA1.
* Documentado por: María Gómez Iglesias
---
## Descripción
Esta vulnerabilidad consiste en almacenar contraseñas en texto plano o utilizando funciones hash débiles, como MD5, que no ofrecen una protección adecuada frente a ataques.

En una aplicación en producción, si un atacante consigue acceder a la base de datos, podría obtener las contraseñas directamente si están en texto plano o recuperarlas mediante ataques de cracking si están almacenadas con hashes débiles. Esto podría permitir el acceso no autorizado a las cuentas de los usuarios y comprometer otros servicios en los que utilicen las mismas contraseñas.

## Ejemplo de código vulnerable
Puedes usar el lenguaje que quieras, pero el código debe estar completamente comentado explicándolo.

## Código mitigado/seguro

```PHP
<?php
// Ejemplo de creación segura de un usuario
if (isset($_POST['crear_usuario'])) {
    $usuario = $_POST['usuario'] ?? '';
    $clave = $_POST['clave'] ?? '';

    try {
 // Generar el hash de la contraseña
        $clave_hash = password_hash($clave, PASSWORD_DEFAULT);

// Insertar el usuario de forma segura
        $sql = $mysqli->prepare("INSERT INTO usuarios (usuario, clave) VALUES (?, ?)");
        $sql->bind_param("ss", $usuario, $clave_hash);
        $sql->execute();
        $sql->close();
        echo "Usuario creado correctamente.";

    } catch (mysqli_sql_exception $e) {
        echo "Error al crear el usuario.";
        error_log($e->getMessage());
    }
}
?>
```
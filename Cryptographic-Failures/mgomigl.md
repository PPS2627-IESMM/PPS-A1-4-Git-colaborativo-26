# Contraseñas almacenadas en texto plano/MD5
## Clasificación
* Categoría OWASP Top 10: A02:2021 - Fallos Criptográficos
* Control OWASP ASVS: V6.2.5 - Uso de algoritmos criptográficos débiles, como MD5 y SHA1.
* Control OWASP ASVS: V2.4.1 - Almacenamiento de credenciales.
* Documentado por: María Gómez Iglesias
---
## Descripción
Esta vulnerabilidad consiste en almacenar contraseñas en texto plano o utilizando funciones hash débiles, como MD5, que no ofrecen una protección adecuada frente a ataques.

En una aplicación en producción, si un atacante consigue acceder a la base de datos, podría obtener las contraseñas si están en texto plano o recuperarlas mediante ataques de cracking si están almacenadas con hashes débiles. Esto podría permitir el acceso no autorizado a las cuentas de los usuarios y comprometer otros servicios en los que utilicen las mismas contraseñas.

Para corregir esta vulnerabilidad, se deben utilizar funciones de hash diseñadas específicamente para el almacenamiento de contraseñas, que permiten aplicar un factor de coste para dificultar los ataques de fuerza bruta.
## Ejemplo de código vulnerable

````PHP
<?php
// Ejemplo de creación no segura de un usuario
if (isset($_POST['crear_usuario'])) {
    $usuario = $_POST['usuario'] ?? '';
    $clave = $_POST['clave'] ?? '';

    try {
        // Comprobar que el usuario y la contraseña no estén vacíos
        if (trim($usuario) !== '' && trim($clave) !== ''){
        
            // **VULNERABILIDAD** MD5 no es adecuado para almacenar contraseñas
			  $clave_hash = md5($clave);
			  
            // La consulta preparada evita la inyección SQL, pero MD5 no es seguro para almacenar contraseñas.
            $sql = $mysqli->prepare("INSERT INTO usuarios (usuario, clave) VALUES (?, ?)");
            $sql->bind_param("ss", $usuario, $clave_hash);
            $sql->execute();
            $sql->close();
            echo "Usuario creado correctamente.";
        } else {
            // Lanzar una excepción si faltan datos
            throw new Exception("El usuario y la contraseña son obligatorios.");
        }
        
    } catch (Exception $e) {
        // Mostrar el error
        echo "Error al crear el usuario.";
    }
}
?>
````
## Código mitigado/seguro

```PHP
<?php
// Ejemplo de creación segura de un usuario
if (isset($_POST['crear_usuario'])) {
    $usuario = $_POST['usuario'] ?? '';
    $clave = $_POST['clave'] ?? '';
    
    try {
        // Comprobar que el usuario y la contraseña no estén vacíos
        if (trim($usuario) !== '' && trim($clave) !== ''){
        
            // Generar el hash seguro de la contraseña
            $clave_hash = password_hash($clave, PASSWORD_DEFAULT);
            
            // Insertar el usuario de forma segura
            $sql = $mysqli->prepare("INSERT INTO usuarios (usuario, clave) VALUES (?, ?)");
            $sql->bind_param("ss", $usuario, $clave_hash);
            $sql->execute();
            $sql->close();
            echo "Usuario creado correctamente.";
        } else {
            // Lanzar una excepción si faltan datos
            throw new Exception("El usuario y la contraseña son obligatorios.");
        }
        
    } catch (Exception $e) {
        // Mostrar el error
        echo "Error al crear el usuario.";
    }
}
?>
```
## Referencias
- Open Worldwide Application Security Project. (s. f.). _V2: Authentication (ASVS 4.0.3)_. GitHub. [https://github.com/OWASP/ASVS/blob/v4.0.3/4.0/en/0x11-V2-Authentication.md#v2-authentication](https://github.com/OWASP/ASVS/blob/v4.0.3/4.0/en/0x11-V2-Authentication.md#v2-authentication)
- Open Worldwide Application Security Project. (s. f.). _V6: Stored cryptography (ASVS 4.0.3)_. GitHub. [https://github.com/OWASP/ASVS/blob/v4.0.3/4.0/en/0x14-V6-Cryptography.md#v6-stored-cryptography](https://github.com/OWASP/ASVS/blob/v4.0.3/4.0/en/0x14-V6-Cryptography.md#v6-stored-cryptography)
- Open Worldwide Application Security Project. (2021). _A02:2021 – Cryptographic failures_. OWASP Top 10. [https://top10.owasp.org/2021/A02_2021-Cryptographic_Failures/](https://top10.owasp.org/2021/A02_2021-Cryptographic_Failures/)
- The PHP Group. (s. f.). _password_hash_. PHP Manual. [https://www.php.net/manual/es/function.password-hash.php](https://www.php.net/manual/es/function.password-hash.php)
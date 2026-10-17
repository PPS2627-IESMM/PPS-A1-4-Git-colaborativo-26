# Clasificación

* Categoría OWASP Top 10: A06:2025 - Insecure Design
* Control OWASP ASVS: V12.1.1 (Validación de subida)
* Documentado por: Ana María Ordóñez Soto

# Descripción

La subida ilimitada de archivos ejecutables (CWE-434) ocurre cuando una aplicación web permite a los usuarios subir archivos al servidor sin validar correctamente su tipo, extensión o contenido. Esto afecta gravemente a un aplicativo en producción, ya que un atacante podría aprovechar este fallo de diseño para subir un archivo malicioso y ejecutar código en el servidor.

# Ejemplo de código vulnerable

```php
<?php
// Código vulnerable: No valida la extensión ni el tipo de archivo subido
if (isset($_FILES['archivo'])) {
    $nombre =$_FILES['archivo']['name'];
    // Se guarda directamente sin filtros, permitiendo subir ejecutables
    move_uploaded_file($_FILES['archivo']['tmp_name'], "uploads/" . $nombre);
}
?>

# Codigo corregido

<?php
// Código corregido / sanitizado cumpliendo con ASVS V12.1.1
if (isset($_FILES['archivo'])) {
    $nombreOriginal =$_FILES['archivo']['name'];
    $extension = strtolower(pathinfo($nombreOriginal, PATHINFO_EXTENSION));
    
    // Lista blanca con solo extensiones permitidas
    $extensionesPermitidas = ['jpg', 'jpeg', 'png', 'pdf'];

    if (in_array($extension,$extensionesPermitidas)) {
        $nuevoNombre = bin2hex(random_bytes(10)) . '.' .$extension;
        move_uploaded_file($_FILES['archivo']['tmp_name'], "uploads/" . $nuevoNombre);
        echo "Archivo subido de forma segura.";
    } else {
        echo "Error: Tipo de archivo no permitido.";
    }
}
?>

<?php
$nombre = "Maria";
?>

<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Practica 1.11 - Mi aplicacion con Docker</title>
</head>
<body>
    <h5>Hola, soy <?php echo htmlspecialchars($nombre, ENT_QUOTES, 'UTF-8'); ?></h5>
    <p>Aplicacion PHP ejecutandose en Docker.</p>
</body>
</html>



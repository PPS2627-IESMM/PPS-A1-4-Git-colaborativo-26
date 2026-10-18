# Cross Site Scripting (XSS) Reflejado
## Clasificación
* Categoría OWASP Top 10: A05:2021 - Inyección
* Control OWASP ASVS: V5.2.7
* Documentado por: Pablo Correa Cuendes
---
## Descripción
Los ataques de Cross Site Scripting (más conocido como XSS) consisten en la inyección de código malicioso en páginas web fiables. Normalmente, estos ataques se suelen hacer mediante JavaScript. Se buscan sitios web vulnerables donde el atacante pueda inyectar código malicioso. El XSS reflejado, concretamente, consiste en inyectar dicho código en una URL o un formulario. Es decir, en estos casos, es el usuario el que debe realizar una acción para ejecutar el código. Una vez hecho, el delincuente puede realizar acciones en nombre del usuario. Lo más frecuente para este tipo de ataques es el phishing.

En un entorno de producción, puede tener graves consecuencias para los usuarios de una página web. Por ejemplo:

- Obtener las cookies de un usuario y robar tokens de inicio de sesión.
- Acceder al historial del usuario.
- Redirigir usuarios a sitios maliciosos.
- Robar credenciales (dependiendo del ataque, puede llegar a nivel de navegador).

## Ejemplo de código vulnerable
```
    <form action="procesar.php" method="GET">
        <label for="nombre">Nombre:</label>
        <input type="text" id="nombre" name="nombre">
        <button type="submit">Enviar</button>
    </form>
    <h2>Hola, <?php echo $_GET['nombre']; ?>!</h2>
```
En este ejemplo, tenemos un formulario donde el usuario puede introducir su nombre. Es un ejemplo muy sencillo. El atacante podría introducir algo como esto en ese campo:

```
<script>alert('XSS')</script>
```
Si no se hace una sanitización de ese campo, se podría usar código JavaScript para ejecutar código como ese. En este caso, solo se mostraría una alerta inofensiva en la pantalla del usuario, pero se puede ejecutar cualquier código.


## Código mitigado/seguro
```
    <form action="procesar.php" method="GET">
        <label for="nombre">Nombre:</label>
        <input type="text" id="nombre" name="nombre">
        <button type="submit">Enviar</button>
    </form>
    
    <?php
    if (isset($_GET['nombre'])) {
        $nombre = htmlspecialchars($_GET['nombre'], ENT_QUOTES, 'UTF-8');
    } else {
        $nombre = 'Invitado';
    }
    ?>
    
    <h2>Hola, <?php echo $_GET['nombre']; ?>!</h2>
```
Añadiendo una simple comprobación, nos aseguramos de que el texto introducido en ese campo no pueda ser un script.

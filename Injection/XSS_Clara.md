# [Nombre de la vulnerabilidad]
Cross Site Scripting (XSS) Reflejado
## Clasificación
* Categoría OWASP Top 10: A05:2025-Inyección
* Control OWASP ASVS: V5.3.3
* Documentado por: Clara Frigolet Paiva
---
## Descripción
El XSS reflejado es una vulnerabilidad que permite a un atacante inyectar código JavaScript en una página que luego se ejecuta en el navegador de otro usuario. No ataca al servidor, ataca a quien visita la web después del atacante. En el caso de XSS reflejado, el script viaja en la propia URL o en un parámetro de un formulario. 

En una aplicación en producción, al ejecutarse el código malicioso directamente en el navegador del usuario, el atacante puede saltarse los mecanismos de seguridad de la aplicación y actuar en su nombre, pudiendo suplantar su identidad, modificar elementos de la página con JavaScript para hacer phishing y robar credenciales. 

## Ejemplo de código vulerable
Lenguaje: HTML con JavaScript

```html
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>Buscador de productos</title>
</head>
<body>

    <h1>Buscador de productos</h1>

    <!-- Formulario que envía la búsqueda que haga el usuario mediante la URL -->
    <form action="" method="GET">
        <input type="text" name="busqueda"
               placeholder="Escribe un producto">
        <button type="submit">Buscar</button>
    </form>

    <h2>Resultados de búsqueda:</h2>

    <div id="resultado"></div>

    <script>
        // Se obtienen los parámetros que aparecen en la URL.
        const parametros = new URLSearchParams(
            window.location.search
        );

        // Se lee el valor del parámetro "busqueda".
        // Por ejemplo, si la URL termina en ?busqueda=zapatos,
        // la variable busqueda contendrá "zapatos".
        const busqueda = parametros.get("busqueda");

        // Comprobamos que el usuario haya introducido una búsqueda.
        if (busqueda) {

            // VULNERABILIDAD:
            // innerHTML interpreta el contenido como HTML.
            // Si el parámetro contiene código malicioso,
            // el navegador podría interpretarlo y ejecutarlo.
            document.getElementById("resultado").innerHTML =
                "Has buscado: " + busqueda;
        }
    </script>

</body>
</html>
```

Ejemplo de búsqueda normal: 
https://tienda.ejemplo/?busqueda=zapatos

Ejemplo de búsqueda maliciosa: 
https://tienda.ejemplo/?busqueda=<script>alert('Has sido hackeado')</script> -> Si la web no filtrara correctamente lo que introduce el usuario, esta dirección podría ejecutar un script que enseñará un mensaje flotante en la pantalla. En este caso es un script inofensivo, pero un atacante real podría aprovechar esta vulnerabilidad para ejecutar código malicioso.

## Código mitigado/seguro
Incluye el código anterior corregido (sanitizado)
```html

<script>

    // Se obtienen los parámetros de la URL
    const parametros = new URLSearchParams(
        window.location.search
    );

    // Se lee el término de búsqueda introducido por el usuario
    const busqueda = parametros.get("busqueda");

    // Se busca el elemento donde se muestra el resultado de la búsqueda.
    const resultado = document.getElementById("resultado");

    // Se comprueba que existe un término de búsqueda.
    if (busqueda) {

        // Se crea un párrafo para mostrar el resultado.
        const mensaje = document.createElement("p");

        // CORRECCIÓN DE LA VULNERABILIDAD:
        // Usamos textContent en lugar de innerHTML ya que inserta el valor como texto plano.
        // Aunque la búsqueda contenga etiquetas HTML o JavaScript,
        //textContent no las interpreta como código ejecutable.
        mensaje.textContent = "Has buscado: " + busqueda;

        // Finalmente se añade el párrafo al elemento de resultados.
        resultado.appendChild(mensaje);
    }

</script>
```

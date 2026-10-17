# Asignación masiva (Mass Assignment)
## Clasificación
* Categoría OWASP Top 10: [Formato A08:2021-Fallas en el Software y en la Integridad de los Datos]
* Control OWASP ASVS: [Formato V5.1.2]
* Documentado por: [Ana Montero Rodríguez]
---
## Descripción
La vulnerabilidad consiste en que el servidor copiaría todos los datos que le llegan desde el cliente a su objeto interno sin comprobar los campos que había puesto el usuario y los que tenía permitido tocar. 

Esta vulnerabilidad hace que, si un usuario está rellenando un formulario donde tiene que indicar su nombre y apellidos y además de eso el usuario pone `isAdmin = true`, si hubiera un valor que fuera `isAdmin` entonces se colocaría a ese usuario como un `admin`.

Esta vulnerabilidad puede resultar en una **escalada de privilegios** (cualquiera se podría volver administrador), en una **pérdida de integridad de los datos** (porque se pueden modificar campos que tendrían que ser intocables), **facilidad de explotación** y obviamente **peligro para el negocio**.
## Ejemplo de código vulnerable
Puedes usar el lenguaje que quieras, pero el código debe estar completamente comentado explicándolo.

```
public class Main { public static void main(String[] args) {
	//un nuevo mapa de cadenas y de objetos
	Map<String, Object> user = new HashMap<>(); 
	
	//se agrega un nuevo valor que sería la cadena "name" y una cadena vacía
	user.put("name", "");
	
	//se agrega otro valor que sería "isAdmin" y que estaría a false
	user.put("isAdmin", false);
	
	//esto sería la petición en sí, lo que le llega al programa cuando el cliente
	//envía el formulario (en el que solo se le pedía el nombre). la petición nos
	//llega modificada por el atacante que ha incluido el valor isAdmin a true
	Map<String, Object> request = Map.of("name", "Pepito", "isAdmin", true);
	
	//y el problema vendría en que no se comprueba en ningún momento el request y
	//por lo tanto aparece la vulnerabilidad, que el usuario ahora tendría
	//isAdmin a true
	user.putAll(request);
	
	//si ahora se hiciera un print del usuario se podría ver que es un administrador
	System.out.println(user);
	} 
}
```

## Código mitigado/seguro
```
public class Main { public static void main(String[] args) {
	//un nuevo mapa de cadenas y de objetos
	Map<String, Object> user = new HashMap<>();

	//se agrega un nuevo valor que sería la cadena "name" y una cadena vacía
	user.put("name", "");

	//se agrega otro valor que sería "isAdmin" y que estaría a false
	user.put("isAdmin", false);

	//igual que antes, el atacante envía una petición modificada para que su usuario
	//escale privilegios poniendo isAdmin en true
	Map<String, Object> request = Map.of("name", "Pepito", "isAdmin", true);
	
	//ahora en vez de copiar todo lo que nos llega de la petición, solo se copia el
	//campo permitido que en este caso sería name y el resto de campos que lleguen se
	//ignoran
	user.put("name", request.get("name"));

	//ahora el print mostrará name=Pepito e isAdmin=false
	System.out.println(user);
	}
}
```


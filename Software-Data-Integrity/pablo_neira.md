# Asignación masiva (Mass Assignment)
## Clasificación
* Categoría OWASP Top 10: [Formato A08:2021-Fallas en el Software y en la Integridad de los Datos]
* Control OWASP ASVS: [Formato V5.1.2]
* Documentado por: [Pablo Neira Sánchez]
---
## Descripción
Esta vulnerabilidad sucede cuando una aplicación o un programa vincula todos los datos que envía un usuario en una petición (como un formulario) directamente a un objeto del código sin filtrar que campos están permitidos. Esto permite al atacante agregar parámetros ocultos en su petición ("saldo": 9999) para modificar propiedades internas que no deben ser tocadas.

## Ejemplo de código vulnerable
```java
// Base de datos
@Entity
public class Usuario {
    @Id private Long id;
    public String nombre;
    public boolean esAdmin = false; // Campo sensible expuesto
}

// Controlador
@RestController
public class UsuarioController {
    @Autowired private UsuarioRepository repo;

    @PostMapping("/actualizar")
    public Usuario actualizar(@RequestBody Usuario usuario) {
        // Si el JSON trae el nombre del usuario y "esAdmin": true ({"nombre": "Pablo", "esAdmin": true}), Spring modificará el canpo 'esAdmin' y lo guardará.
        return repo.save(usuario);
    }
}
```


## Código mitigado/seguro
```java
// Base de Datos
@Entity
public class Usuario {
    @Id private Long id;
    public String nombre;
    public boolean esAdmin = false;
}

// Filtro que SOLO contiene los campos permitidos
public record UsuarioDTO(String nombre) {}

// Controlador 
@RestController
public class UsuarioController {
    @Autowired private UsuarioRepository repo;

    @PostMapping("/actualizar/{id}")
    public Usuario actualizar(@PathVariable Long id, @RequestBody UsuarioDTO dto) {
        Usuario u = repo.findById(id).orElseThrow();
        
        // Solo se copia el nombre, 'esAdmin' no se puede copiar 
        u.nombre = dto.nombre(); 
        return repo.save(u);
    }
}
```


# Vulnerabilidad: Subida Ilimitada de Archivos Ejecutables 

**Categoría OWASP Top 10:** Insecure Design (Diseño Inseguro)
**Control OWASP ASVS (v4.0.3):** V12 File Upload Validation Requirements

---

## Explicación del fallo

Esta vulnerabilidad ocurre cuando una aplicación web permite a los usuarios subir archivos a su servidor sin validar adecuadamente el nombre, tipo, tamaño o contenido de este. 

Si un atacante logra subir un archivo ejecutable (por ejemplo, un script `.py`, `.php`, `.sh`,  etc) a un directorio donde el servidor web tiene permisos de ejecución o que es accesible públicamente, el atacante puede forzar al servidor a ejecutar ese código. Esto suele resultar en **RCE (Ejecución Remota de Código)**, permitiendo al atacante tomar el control total del servidor, robar bases de datos o utilizar el servidor para atacar a otros sistemas.

---

## Ejemplo de código vulnerable (Python)

En este ejemplo, el código acepta cualquier archivo y lo guarda directamente usando el nombre proporcionado por el usuario, sin realizar ninguna comprobación.

```python
def guardar_archivo(nombre_archivo, contenido):
    # VULNERABLE: El programa guarda cualquier cosa sin preguntar
    # Si el atacante envía "virus.exe", se guardará tal cual.
    with open(nombre_archivo, 'w') as archivo:
        archivo.write(contenido)
    print(f"Se ha guardado: {nombre_archivo}")

# Simulación de un ataque:
guardar_archivo("foto.jpg", "datos de la imagen...")    # Archivo normal
guardar_archivo("malware.exe", "código malicioso...")  # Se guarda un ejecutable
```

---

## Ejemplo de código corregido/seguro (Python)

Para mitigar esta vulnerabilidad, debemos aplicar el principio de "Defensa en Profundidad": usar listas blancas de extensiones y limitar los tamaños.

```python
import os

# 1. Definimos explícitamente qué extensiones son seguras (Lista Blanca)
EXTENSIONES_PERMITIDAS = {'.txt', '.jpg', '.png'}

def guardar_archivo_seguro(nombre_archivo, contenido):
    # 2. Extraemos la extensión del nombre del archivo (ej: ".exe")
    nombre_base, extension = os.path.splitext(nombre_archivo)
    
    # 3. CONTROL DE SEGURIDAD: Si la extensión no está en la lista, bloqueamos
    if extension.lower() not in EXTENSIONES_PERMITIDAS:
        print(f"Error de seguridad: La extensión '{extension}' no está permitida.")
        return # Cortamos la ejecución aquí, el archivo no se guarda
        
    # Si pasa el control, lo guardamos
    with open(nombre_archivo, 'w') as archivo:
        archivo.write(contenido)
    print(f"Se ha guardado de forma segura: {nombre_archivo}")

# Simulación del código seguro:
guardar_archivo_seguro("foto.jpg", "datos de la imagen...")  # Guardado con éxito
guardar_archivo_seguro("malware.exe", "código malicioso...") # Error de seguridad, es bloqueado
```
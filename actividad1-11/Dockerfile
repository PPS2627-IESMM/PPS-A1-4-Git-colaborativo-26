# Imagen oficial de PHP con versión concreta.
FROM php:8.4.27-cli-bookworm

# Establecer el directorio de trabajo.
WORKDIR /app

# Crear un usuario sin privilegios de root.
RUN useradd --system --create-home --no-log-init maria-sin-privilegios

# Copiar la aplicación asignando la propiedad al usuario.
COPY --chown=maria-sin-privilegios:maria-sin-privilegios index.php ./index.php

# Ejecutar como usuario no root.
USER maria-sin-privilegios

# Indicar el puerto de la aplicación.
EXPOSE 8080

# Iniciar el servidor PHP en el puerto 8080.
CMD ["php", "-S", "0.0.0.0:8080", "index.php"]

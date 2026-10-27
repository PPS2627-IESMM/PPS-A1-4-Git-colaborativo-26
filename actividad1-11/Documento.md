## Descarga y comprobación de la imagen

```
docker pull php:8.4.13-cli-bookworm
docker images
```

## Construcción de la imagen

```
docker build -t actividad1-11-maria .
```

## Ejecución del contenedor

```
docker run -d --name actividad1-11-maria -p 8080:8080 actividad1-11-maria
```

## Comprobación del usuario

```
docker inspect -f '{{.Config.User}}' actividad1-11-maria
```
![[2.png]]
## Análisis de seguridad con Trivy

```
trivy image actividad1-11-maria
trivy image --format json --output informe-trivy.json actividad1-11-maria
```

## Aplicación web
![[1.png]]
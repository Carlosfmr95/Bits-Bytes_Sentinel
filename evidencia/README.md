# Evidencia de la serie de validación

Material capturado durante los cuatro ciclos consecutivos ejecutados el 23 de agosto de 2026 sobre Metasploitable 2 (192.168.100.11), con la misma configuración de escaneo y el mismo catálogo de pruebas congelado. Es la evidencia que sostiene el Capítulo 7, la Discusión y el Anexo D del Trabajo Final Integrador.

**El tercer ciclo es el de referencia del Capítulo 7** (`scan_id` 1b903443-9202-4b7b-bfa5-78f5db1aab24). Los cuatro subdirectorios tienen la misma estructura.

> Los archivos son capturas: no se editaron para hacerlos coincidir con el texto. Donde una cifra del archivo difiere en su forma de la que el trabajo consigna, la diferencia se explica más abajo.

---

## Estructura

| Archivo | Qué es |
|---|---|
| `gmp_report_sin_filtro.xml` | Reporte nativo del gestor de vulnerabilidades, recuperado con `min_qod=0 apply_overrides=0 rows=1000`. Contiene los resultados **antes** del umbral de calidad de detección |
| `gmp_report_qod70.xml` | El mismo reporte con `min_qod=70`: es el que el orquestador consume |
| `gmp_report_meta.xml` | Metadatos del reporte (identificadores, marcas temporales de inicio y fin) |
| `gmp_feeds.xml` | Versión de los feeds NVT, SCAP y CERT en el momento de la corrida |
| `gvmapi_report_detail.json` | Respuesta del microservicio `gvm-api`, tal como la recibe el orquestador |
| `gvmapi_reports_list.json` | Listado de reportes disponibles en el gestor |
| `n8n_execution_XX.json` | Registro completo de la ejecución del workflow, extraído de la base del orquestador |
| `vulnerability_scans.csv` | Las filas persistidas del ciclo (tabla `vulnerability_scans`) |
| `scan_history.txt` | Resumen estadístico de la ejecución (tabla `scan_history`) |
| `conteo_severidad.txt` | Conteo por nivel de severidad — **ver nota 2** |
| `conteo_herramienta.txt` | Filas y puertos distintos por herramienta |
| `qod_comparacion.txt` | Cadena de reducción y distribución de la calidad de detección |
| `tiempos.txt` | Inicio y fin del escaneo según el reloj del motor de OpenVAS |
| `tiempo_ciclo.txt` | Duración del ciclo de extremo a extremo — **ver nota 1** |
| `docker_images.txt` | Imágenes y versiones desplegadas |
| `metadata.txt` | Identificadores del ciclo y procedencia de la captura |

---

## Notas de lectura

### 1. `tiempo_ciclo.txt` informa 48 min 17 s; el trabajo consigna 48 min 08 s

No es una discrepancia de medición sino de precisión en el extremo inicial. El archivo toma la hora de disparo redondeada al minuto (`18:55`), mientras que el trabajo usa la marca exacta del registro de ejecución (`18:55:09`). El extremo final es el mismo en ambos: la persistencia en la base, a las `19:43:17`.

```
19:43:17 − 18:55:00 = 48 min 17 s   (archivo, disparo redondeado al minuto)
19:43:17 − 18:55:09 = 48 min 08 s   (trabajo, marca exacta del log)
```

La cifra del trabajo es la precisa, y es la que cierra con `scan.complete total=2888s` del propio registro. La descomposición del Fragmento D.1 del Anexo D se apoya en ella.

### 2. `conteo_severidad.txt` está filtrado por herramienta

La consulta que generó ese archivo cuenta **sólo las filas de OpenVAS**: por eso suma 191 y reporta 9 de nivel alto. El panel del tablero, en cambio, muestra el total de las 221 filas persistidas, donde los niveles agregan la contribución de Nmap:

| Nivel | OpenVAS | Nmap | Panel |
|---|---|---|---|
| Critical | 14 | — | 14 |
| High | 9 | 4 | 13 |
| Medium | 39 | 13 | 52 |
| Low | 6 | 13 | 19 |
| Info | 123 | — | 123 |
| **Total** | **191** | **30** | **221** |

Los aportes de Nmap figuran en `scan_history.txt` (`nmap_high`, `nmap_medium`, `nmap_low`). El conteo completo sobre las 221 filas se reproduce agrupando `vulnerability_scans.csv` por `severidad_label` sin filtrar por herramienta.

### 3. La versión del feed

`gmp_feeds.xml` declara la versión del feed NVT como `202603030713`. El trabajo la consigna como `20260303T0713`: es la misma marca temporal —3 de marzo de 2026, 07:13— con el separador de fecha y hora que emplea la documentación de Greenbone.

### 4. Los 68 hallazgos y los 89 CVE

Ambas cifras se definen sobre el mismo subconjunto y conviene explicitarlo, porque el CSV admite otros recortes:

- **68 hallazgos** = filas de OpenVAS con severidad asignada, es decir las 191 menos las 123 de categoría informativa.
- **89 CVE** = identificadores distintos de la columna `cves` **en esas 68 filas**. Contados sobre las 191 filas de OpenVAS el total es 90: el adicional, `CVE-1999-0632`, proviene de un registro informativo y por lo tanto queda fuera del conjunto de hallazgos.

---

## Lo que este material no incluye

Las imágenes de las máquinas virtuales y el volumen de datos de Greenbone, por su tamaño. El entorno se reconstruye desde cero con el `docker-compose.yml` y el `schema.sql` publicados en la raíz del repositorio, según el procedimiento del Anexo B del trabajo.

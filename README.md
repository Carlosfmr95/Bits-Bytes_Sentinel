# Sentinel — Sistema Automatizado de Escaneo de Vulnerabilidades

**Trabajo Integrador Final — UTN FRM**  
Tecnicatura en Ciberseguridad — Bits & Bytes  
Marín, Agustín · Muñoz, Carlos · Raía, Sofía

---

## Descripción

Sentinel es un sistema de escaneo automatizado de vulnerabilidades para redes de laboratorio. Integra Nmap, OpenVAS y n8n en un pipeline orquestado que descubre hosts, escanea puertos y ejecuta análisis de vulnerabilidades, almacenando los resultados en PostgreSQL y visualizándolos en un dashboard web en tiempo real.

El sistema puede dispararse automáticamente por schedule, manualmente desde n8n, o bajo demanda desde el dashboard con seguimiento de progreso en tiempo real.

---

## Arquitectura

```
┌─────────────────────────────────────────────────────────────┐
│                        Ubuntu Server 24.04                   │
│                                                             │
│  ┌──────────┐    ┌──────────┐    ┌──────────────────────┐  │
│  │ Dashboard│    │   n8n    │    │  Greenbone / OpenVAS │  │
│  │  :5002   │◄──►│  :5678   │◄──►│        :9392         │  │
│  └──────────┘    └──────────┘    └──────────────────────┘  │
│       │               │                                     │
│       │          ┌────┴─────┐    ┌──────────┐              │
│       │          │ nmap-api │    │  gvm-api │              │
│       │          │  :5000   │    │  :5001   │              │
│       │          └──────────┘    └──────────┘              │
│       │                                                     │
│       ▼                                                     │
│  ┌──────────┐                                              │
│  │PostgreSQL│                                              │
│  │  :5432   │                                              │
│  └──────────┘                                              │
└─────────────────────────────────────────────────────────────┘
```

### Servicios

| Servicio | Puerto | Descripción |
|---|---|---|
| Dashboard | 5002 | Interfaz web de visualización y control |
| n8n | 5678 | Motor de automatización del workflow |
| nmap-api | 5000 | Microservicio REST wrapper de Nmap |
| gvm-api | 5001 | Microservicio REST wrapper de OpenVAS |
| PostgreSQL | 5432 | Base de datos de resultados |
| Greenbone GSA | 9392 | Interfaz web de OpenVAS |

---

## Requisitos

- Ubuntu Server 24.04
- Docker 24+
- Docker Compose v2+
- 8 GB RAM mínimo (16 GB recomendado para OpenVAS)
- 50 GB de disco libre

---

## Instalación

### 1 — Clonar el repositorio

```bash
git clone https://github.com/Carlosfmr95/Bits-Bytes_Sentinel
cd sentinel
```

### 2 — Configurar variables de entorno

```bash
cp .env.example .env
nano .env
```

Completar todos los campos del `.env`. Como mínimo:

```env
POSTGRES_USER=n8n_user
POSTGRES_PASSWORD=tu_password_seguro
POSTGRES_DB=security_scans
DB_USER=n8n_user
DB_PASSWORD=tu_password_seguro
DB_NAME=security_scans
N8N_ENCRYPTION_KEY=clave_aleatoria_larga
WEBHOOK_URL=http://<IP_DE_TU_VM>:5678/
GVM_USER=admin
GVM_PASSWORD=tu_password_openvas
N8N_WEBHOOK_URL=http://n8n:5678/webhook/start-scan
```

### 3 — Levantar el stack

```bash
docker compose up -d
```

La primera vez tarda entre 10 y 30 minutos porque OpenVAS descarga las bases de datos de vulnerabilidades.

### 4 — Verificar que todos los servicios están corriendo

```bash
docker compose ps
```

Todos los servicios deben mostrar `running` o `healthy`. Si alguno da error, correr de nuevo docker compose up -d para comprobar si no es un falso positivo.

### 5 — Usar schema.sql para crear la base de datos

### 6 — Importar el workflow en n8n

1. Abrir `http://<IP_VM>:5678`
2. Crear cuenta de administrador
3. Ir a **Workflows → Import from file**
4. Seleccionar el archivo `n8n/workflow.json`
5. Configurar las credenciales de PostgreSQL en los nodos correspondientes
6. Hacer click en **Publish** para activar el webhook

---

## Uso

### Dashboard

Acceder a `http://<IP_VM>:5002`

Desde el dashboard podés:
- Ver todos los resultados de escaneos con filtros por host, severidad, herramienta y fecha
- Buscar vulnerabilidades por nombre o CVE
- Exportar resultados a CSV
- Ver el historial de escaneos
- Lanzar nuevos escaneos con seguimiento en tiempo real

### Lanzar un escaneo manualmente

Hacer click en **▶ NUEVO ESCANEO** en el header del dashboard, ingresar la IP objetivo y seleccionar el tipo de escaneo.

### Escaneo automático

El workflow está configurado para ejecutarse automáticamente a las 2:00 AM. Puede modificarse en n8n → Schedule Trigger.

---

## Estructura del proyecto

```
sentinel/
├── .env.example          # Variables de entorno requeridas
├── .gitignore
├── README.md
├── docker-compose.yml
├── dashboard/
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── app.py            # Backend Flask (API REST + scan trigger)
│   └── templates/
│       └── index.html    # Frontend (CSS + JS embebidos)
├── gvm-api/
│   ├── Dockerfile
│   ├── requirements.txt
│   └── app.py            # Wrapper REST para OpenVAS via GMP socket
├── nmap-api/
│   ├── Dockerfile
│   ├── requirements.txt
│   └── app.py            # Wrapper REST para Nmap
└── n8n/
    └── workflow.json     # Workflow de automatización exportado
```

---

## Red de laboratorio

El sistema está configurado para escanear únicamente la red `192.168.100.0/24`. Para modificar este rango editar:

- `nmap-api/app.py` → variable `ALLOWED_NETWORKS`
- `gvm-api/app.py` → validación en `scan_start()`
- Nodo **Nmap - Descubrir hosts activos** en n8n → campo `target`

---

## Tecnologías

- **Python 3.11** / Flask — backend de microservicios
- **PostgreSQL 16** — almacenamiento de resultados
- **n8n** — orquestación del workflow de escaneo
- **Nmap** — descubrimiento de hosts y escaneo de puertos
- **OpenVAS / Greenbone Community Edition** — análisis de vulnerabilidades
- **Docker / Docker Compose** — contenedores y orquestación

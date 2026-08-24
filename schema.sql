-- =====================================================================
-- Bits & Bytes Sentinel — esquema de base de datos
--
-- Proyecto : Escaneo automatizado de vulnerabilidades y generación de
--            informes. Pipeline open source orquestado con N8N.
-- Trabajo  : Trabajo Final Integrador — UTN FRM, Tecnicatura
--            Universitaria en Programación, 2026.
-- Grupo    : Bits & Bytes — Marín (52689), Muñoz (52715), Raia (52741)
--
-- Base     : security_scans
-- Motor    : PostgreSQL 16 (contenedor postgres-scans)
-- Zona horaria de las columnas TIMESTAMP: America/Argentina/Buenos_Aires
--
-- Este archivo se corresponde con el Anexo B del informe.
-- Uso: psql -U <usuario> -d security_scans -f schema.sql
-- =====================================================================

-- ---------------------------------------------------------------------
-- scan_history — una fila por ejecución completa del workflow.
-- Guarda los contadores agregados por herramienta y nivel de severidad.
-- ---------------------------------------------------------------------
CREATE TABLE scan_history (
    id               SERIAL PRIMARY KEY,
    scan_id          VARCHAR(36) NOT NULL UNIQUE,
        -- UUID v4 generado por el nodo 2 del workflow ("Generar Scan ID").
        -- Son 36 caracteres: 32 hexadecimales mas 4 guiones.
    fecha            TIMESTAMP NOT NULL,
    total_hosts      INTEGER NOT NULL DEFAULT 0,

    -- Contadores de Nmap, asignados por la heuristica de severidad
    -- documentada en la Seccion 6.2.1 (clasifica por nombre de servicio,
    -- con respaldo por numero de puerto). No produce nivel CRITICAL.
    nmap_high        INTEGER NOT NULL DEFAULT 0,
    nmap_medium      INTEGER NOT NULL DEFAULT 0,
    nmap_low         INTEGER NOT NULL DEFAULT 0,

    -- Contadores de OpenVAS, derivados del score CVSS 3.1 del feed.
    openvas_critical INTEGER NOT NULL DEFAULT 0,   -- CVSS >= 9.0
    openvas_high     INTEGER NOT NULL DEFAULT 0,   -- CVSS >= 7.0
    openvas_medium   INTEGER NOT NULL DEFAULT 0,   -- CVSS >= 4.0
    openvas_low      INTEGER NOT NULL DEFAULT 0,   -- CVSS  > 0.0

    created_at       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- ---------------------------------------------------------------------
-- vulnerability_scans — una fila por resultado granular del ciclo.
-- Contiene tanto los puertos descubiertos por Nmap como los resultados
-- del reporte de OpenVAS.
-- ---------------------------------------------------------------------
CREATE TABLE vulnerability_scans (
    id              SERIAL PRIMARY KEY,
    scan_id         VARCHAR(36) NOT NULL,
    fecha           TIMESTAMP NOT NULL,
    host_ip         VARCHAR(50) NOT NULL,
    herramienta     VARCHAR(20) NOT NULL,
        -- valores admitidos: 'nmap' | 'openvas'
    severidad_label VARCHAR(10),
        -- valores admitidos: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO'
    puerto          VARCHAR(20),
    servicio        VARCHAR(100),
        -- poblado solo en registros nmap; NULL en openvas
    version         VARCHAR(200),
        -- poblado solo en registros nmap; NULL en openvas
    nombre_vuln     VARCHAR(500),
        -- poblado solo en registros openvas; NULL en nmap
    cves            TEXT,
        -- poblado solo en registros openvas; lista de CVEs separada por
        -- comas. Para contar CVEs distintos hay que desagregarla:
        --   SELECT COUNT(DISTINCT cve)
        --   FROM vulnerability_scans,
        --        unnest(string_to_array(cves, ',')) AS cve
        --   WHERE herramienta = 'openvas' AND cves IS NOT NULL;
    severidad_cvss  DECIMAL(4,1),
        -- poblado solo en registros openvas; rango 0.0 - 10.0
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    -- -----------------------------------------------------------------
    -- Integridad referencial: NO se declara FOREIGN KEY hacia
    -- scan_history de forma deliberada.
    --
    -- El workflow inserta primero los registros granulares (nodo 15,
    -- "Guardar en PostgreSQL") y recien despues la fila de historial
    -- (nodo 17, "Guardar Historial"). Con la clave foranea activa, la
    -- insercion del nodo 15 seria rechazada por inexistencia de la fila
    -- padre. La correlacion entre ambas tablas se sostiene por el Scan ID
    -- unico que genera el nodo 2 y se indexa mas abajo.
    --
    -- Invertir el orden de los nodos 15 y 17 permitiria declarar:
    --   CONSTRAINT fk_scan_history FOREIGN KEY (scan_id)
    --       REFERENCES scan_history(scan_id) ON DELETE CASCADE
    -- y delegar la integridad referencial en el motor. Se consigna como
    -- mejora en la Seccion 9.2.2 del informe.
    -- -----------------------------------------------------------------

    CONSTRAINT chk_herramienta
        CHECK (herramienta IN ('nmap', 'openvas')),
    CONSTRAINT chk_severidad_label
        CHECK (severidad_label IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')
               OR severidad_label IS NULL),
    CONSTRAINT chk_severidad_cvss
        CHECK (severidad_cvss IS NULL
               OR (severidad_cvss >= 0.0 AND severidad_cvss <= 10.0))
);

-- ---------------------------------------------------------------------
-- Indices para las consultas frecuentes del dashboard y del analisis
-- comparativo entre ciclos (Fragmento 6.4 del informe).
-- ---------------------------------------------------------------------
CREATE INDEX idx_vuln_scans_scan_id      ON vulnerability_scans(scan_id);
CREATE INDEX idx_vuln_scans_host_ip      ON vulnerability_scans(host_ip);
CREATE INDEX idx_vuln_scans_herramienta  ON vulnerability_scans(herramienta);
CREATE INDEX idx_vuln_scans_severidad    ON vulnerability_scans(severidad_label);
CREATE INDEX idx_scan_history_fecha      ON scan_history(fecha DESC);

-- =====================================================================
-- Nota sobre el volumen persistido por ciclo
--
-- Sobre el objetivo de laboratorio (Metasploitable 2), un ciclo persiste
-- 221 filas en vulnerability_scans: 30 de Nmap y 191 de OpenVAS.
--
-- Las 191 filas de OpenVAS se componen de los 159 resultados de primer
-- nivel del reporte GMP mas 32 elementos <result> anidados dentro de
-- bloques <detection>, que registran el origen de la deteccion
-- (producto, ubicacion y OID del NVT) y no llevan atributo de severidad,
-- por lo que se persisten con severidad_label = 'INFO'.
--
-- De ahi que la distribucion por severidad de un ciclo sea:
--   CRITICAL 14 | HIGH 9 | MEDIUM 39 | LOW 6 | INFO 123
-- donde los 123 informativos son 91 resultados de categoria Log mas los
-- 32 registros anidados. Los hallazgos propiamente dichos son 68.
--
-- El tope de 200 filas de la consulta GMP se aplica sobre los 159
-- resultados de primer nivel (ocupacion del 79,5 %), no sobre las 191
-- filas persistidas. Ver Seccion 6.4 del informe.
-- =====================================================================

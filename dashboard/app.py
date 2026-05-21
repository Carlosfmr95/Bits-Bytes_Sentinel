import csv
import io
import os
import uuid
import requests as http_client
import psycopg2
import psycopg2.extras
from datetime import datetime
from typing import Optional
from flask import Flask, render_template, request, jsonify, Response

app = Flask(__name__)

# ── Database config ───────────────────────────────────────────────────────────

DB_CONFIG = {
    "host":     os.environ.get("DB_HOST", "postgres-scans"),
    "database": os.environ.get("DB_NAME", "security_scans"),
    "user":     os.environ.get("DB_USER", "n8n_user"),
    "password": os.environ.get("DB_PASSWORD", "n8n_pass"),
    "port":     int(os.environ.get("DB_PORT", 5432)),
}

def get_conn():
    return psycopg2.connect(**DB_CONFIG)


# ── Scan trigger config ───────────────────────────────────────────────────────

N8N_WEBHOOK_URL = os.environ.get(
    "N8N_WEBHOOK_URL",
    "http://n8n:5678/webhook/start-scan",
)

# In-memory store for active scan jobs.
# NOTE: jobs are lost on container restart — acceptable for this project's scope.
scan_jobs: dict = {}

ALLOWED_SCAN_TYPES = {"quick", "full"}


def create_scan_job(target: str, scan_type: str) -> dict:
    scan_id = str(uuid.uuid4())
    scan_jobs[scan_id] = {
        "id":         scan_id,
        "target":     target,
        "scan_type":  scan_type,
        "status":     "queued",
        "progress":   5,
        "logs":       [f"[SYSTEM] Scan queued for {target}"],
        "created_at": datetime.utcnow().isoformat(),
    }
    return scan_jobs[scan_id]


def update_scan_job(
    scan_id: str,
    status: str,
    progress: int,
    log: Optional[str] = None,
) -> None:
    job = scan_jobs.get(scan_id)
    if not job:
        return
    job["status"]   = status
    job["progress"] = progress
    if log:
        job["logs"].append(log)


# ── Query helpers ─────────────────────────────────────────────────────────────

EXPORT_COLUMNS = [
    "scan_id", "fecha", "host_ip", "herramienta", "severidad_label",
    "puerto", "servicio", "version", "nombre_vuln", "cves", "severidad_cvss",
]

PER_PAGE_MAX = 500


def build_where(args):
    conditions, params = [], []

    if args.get("host"):
        conditions.append("host_ip = %s")
        params.append(args["host"])
    if args.get("severidad"):
        conditions.append("severidad_label = %s")
        params.append(args["severidad"])
    if args.get("herramienta"):
        conditions.append("herramienta = %s")
        params.append(args["herramienta"])
    if args.get("scan_id"):
        conditions.append("scan_id = %s")
        params.append(args["scan_id"])
    if args.get("fecha_from"):
        conditions.append("fecha >= %s")
        params.append(args["fecha_from"])
    if args.get("fecha_to"):
        conditions.append("fecha <= %s")
        params.append(args["fecha_to"] + " 23:59:59")
    if args.get("q"):
        term = f"%{args['q']}%"
        conditions.append(
            "(nombre_vuln ILIKE %s OR cves ILIKE %s OR host_ip ILIKE %s)"
        )
        params.extend([term, term, term])

    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    return where, params


# ── Dashboard routes ──────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/filters")
def api_filters():
    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                "SELECT DISTINCT host_ip FROM vulnerability_scans "
                "WHERE host_ip IS NOT NULL ORDER BY host_ip"
            )
            hosts = [r["host_ip"] for r in cur.fetchall()]

            cur.execute(
                "SELECT DISTINCT herramienta FROM vulnerability_scans "
                "WHERE herramienta IS NOT NULL ORDER BY herramienta"
            )
            herramientas = [r["herramienta"] for r in cur.fetchall()]

            cur.execute(
                "SELECT DISTINCT severidad_label FROM vulnerability_scans "
                "WHERE severidad_label IS NOT NULL ORDER BY severidad_label"
            )
            severidades = [r["severidad_label"] for r in cur.fetchall()]

            cur.execute("""
                SELECT scan_id, MIN(fecha) as fecha
                FROM vulnerability_scans
                WHERE scan_id IS NOT NULL
                GROUP BY scan_id
                ORDER BY MIN(fecha) DESC
            """)
            scans = [
                {
                    "scan_id": r["scan_id"],
                    "fecha":   r["fecha"].strftime("%Y-%m-%d %H:%M"),
                }
                for r in cur.fetchall()
            ]

            cur.execute("SELECT MIN(fecha), MAX(fecha) FROM vulnerability_scans")
            row = cur.fetchone()
            fecha_min = row["min"].strftime("%Y-%m-%d") if row["min"] else ""
            fecha_max = row["max"].strftime("%Y-%m-%d") if row["max"] else ""

            cur.execute("SELECT MAX(fecha) as last FROM scan_history")
            last_row = cur.fetchone()
            last_scan_fecha = (
                last_row["last"].isoformat() if last_row and last_row["last"] else None
            )

    return jsonify({
        "hosts":           hosts,
        "herramientas":    herramientas,
        "severidades":     severidades,
        "scans":           scans,
        "fecha_min":       fecha_min,
        "fecha_max":       fecha_max,
        "last_scan_fecha": last_scan_fecha,
    })


@app.route("/api/scans")
def api_scans():
    page     = max(1, int(request.args.get("page", 1)))
    per_page = min(max(1, int(request.args.get("per_page", 50))), PER_PAGE_MAX)
    offset   = (page - 1) * per_page
    where, params = build_where(request.args)

    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                f"SELECT COUNT(*) as total FROM vulnerability_scans {where}",
                params,
            )
            total = cur.fetchone()["total"]

            cur.execute(f"""
                SELECT id, scan_id, fecha, host_ip, herramienta, severidad_label,
                       puerto, servicio, version, nombre_vuln, cves, severidad_cvss
                FROM vulnerability_scans {where}
                ORDER BY fecha DESC, severidad_cvss DESC NULLS LAST
                LIMIT %s OFFSET %s
            """, params + [per_page, offset])
            rows = cur.fetchall()
            for r in rows:
                if isinstance(r.get("fecha"), datetime):
                    r["fecha"] = r["fecha"].strftime("%Y-%m-%d %H:%M")

    return jsonify({
        "total":    total,
        "page":     page,
        "per_page": per_page,
        "rows":     rows,
    })


@app.route("/api/stats")
def api_stats():
    where, params = build_where(request.args)

    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(f"""
                SELECT
                    COUNT(*) as total,
                    SUM(CASE WHEN severidad_label = 'HIGH'   THEN 1 ELSE 0 END) as high,
                    SUM(CASE WHEN severidad_label = 'MEDIUM' THEN 1 ELSE 0 END) as medium,
                    SUM(CASE WHEN severidad_label = 'LOW'    THEN 1 ELSE 0 END) as low,
                    COUNT(DISTINCT host_ip) as hosts,
                    COUNT(DISTINCT CASE WHEN herramienta = 'openvas'
                          THEN nombre_vuln END) as cves_unicos
                FROM vulnerability_scans {where}
            """, params)
            stats = cur.fetchone()

            cur.execute(f"""
                SELECT host_ip,
                    SUM(CASE WHEN severidad_label = 'HIGH'   THEN 1 ELSE 0 END) as high,
                    SUM(CASE WHEN severidad_label = 'MEDIUM' THEN 1 ELSE 0 END) as medium,
                    SUM(CASE WHEN severidad_label = 'LOW'    THEN 1 ELSE 0 END) as low,
                    COUNT(*) as total
                FROM vulnerability_scans {where}
                GROUP BY host_ip ORDER BY total DESC
            """, params)
            por_host = cur.fetchall()

    return jsonify({
        "stats":    dict(stats),
        "por_host": [dict(r) for r in por_host],
    })


@app.route("/api/history")
def api_history():
    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""
                SELECT id, scan_id, fecha, total_hosts,
                       nmap_high, nmap_medium, nmap_low,
                       openvas_high, openvas_medium, openvas_low
                FROM scan_history
                ORDER BY fecha DESC
                LIMIT 20
            """)
            rows = cur.fetchall()
            for r in rows:
                if isinstance(r.get("fecha"), datetime):
                    r["fecha"] = r["fecha"].strftime("%Y-%m-%d %H:%M")

    return jsonify({"history": [dict(r) for r in rows]})


@app.route("/api/export")
def api_export():
    where, params = build_where(request.args)

    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(f"""
                SELECT {', '.join(EXPORT_COLUMNS)}
                FROM vulnerability_scans {where}
                ORDER BY fecha DESC, severidad_cvss DESC NULLS LAST
                LIMIT 10000
            """, params)
            rows = cur.fetchall()

    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=EXPORT_COLUMNS, extrasaction="ignore")
    writer.writeheader()
    for r in rows:
        if isinstance(r.get("fecha"), datetime):
            r["fecha"] = r["fecha"].strftime("%Y-%m-%d %H:%M")
        writer.writerow(dict(r))

    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={
            "Content-Disposition": (
                f"attachment; filename=secscan_export_"
                f"{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"
            )
        },
    )


# ── Scan trigger endpoints ────────────────────────────────────────────────────

@app.route("/api/scans/start", methods=["POST"])
def start_scan():
    data      = request.get_json(force=True) or {}
    target    = data.get("target", "").strip()
    scan_type = data.get("scan_type", "quick")

    if not target:
        return jsonify({"error": "Target is required"}), 400
    if scan_type not in ALLOWED_SCAN_TYPES:
        return jsonify({"error": "Invalid scan type"}), 400

    job = create_scan_job(target, scan_type)

    try:
        http_client.post(
            N8N_WEBHOOK_URL,
            json={
                "scan_id":   job["id"],
                "target":    target,
                "scan_type": scan_type,
            },
            timeout=5,
        )
    except http_client.exceptions.RequestException as exc:
        update_scan_job(
            job["id"], "failed", 0,
            f"[ERROR] No se pudo contactar el motor de workflow: {exc}",
        )
        return jsonify({"error": "Unable to reach workflow engine"}), 502

    return jsonify({"scan_id": job["id"], "status": "queued"})


@app.route("/api/scans/<scan_id>/status", methods=["GET"])
def get_scan_status(scan_id):
    job = scan_jobs.get(scan_id)
    if not job:
        return jsonify({"error": "Scan not found"}), 404
    return jsonify(job)


@app.route("/api/scans/<scan_id>/update", methods=["POST"])
def update_scan_status(scan_id):
    data = request.get_json(force=True) or {}
    update_scan_job(
        scan_id=scan_id,
        status=data.get("status", "running"),
        progress=int(data.get("progress", 0)),
        log=data.get("log"),
    )
    return jsonify({"success": True})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5002, debug=False)
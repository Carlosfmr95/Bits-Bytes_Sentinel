import os
import select
import socket
import logging
import datetime
import xml.etree.ElementTree as ET
from flask import Flask, jsonify, request

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

GVM_USER    = os.environ.get("GVM_USER", "admin")
GVM_PASS    = os.environ.get("GVM_PASSWORD", "admin")
SOCKET_PATH = os.environ.get("GVM_SOCKET", "/run/gvmd/gvmd.sock")

# Scan config UUIDs — verificables en http://<vm>:9392 → Configuration → Scan Configs
SCAN_CONFIG_FULL_FAST       = "daba56c8-73ec-11df-a475-002264764cea"  # Full and fast
SCAN_CONFIG_SYSTEM_DISCOVERY = "bbca7412-a950-11e3-9109-406186ea4fc5" # System Discovery (quick)

SCANNER_OPENVAS  = "08b69003-5fc2-4037-a479-93b440211c73"
PORT_LIST_ALL_TCP = "33d0cd82-57c6-11e1-8ed1-406186ea4fc5"

ALLOWED_SCAN_TYPES = {"quick", "full"}


def read_response(sock, timeout=2):
    buf = bytearray()
    while True:
        r, _, _ = select.select([sock], [], [], timeout)
        if not r:
            break
        chunk = sock.recv(65536)
        if not chunk:
            break
        buf.extend(chunk)
    return buf.decode('utf-8')


def gmp_cmd(xml_str):
    """Abre conexión, autentica, ejecuta un comando y devuelve el Element XML."""
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(60)
    try:
        s.connect(SOCKET_PATH)

        auth = (
            f"<authenticate><credentials>"
            f"<username>{GVM_USER}</username>"
            f"<password>{GVM_PASS}</password>"
            f"</credentials></authenticate>"
        )
        s.sendall(auth.encode())
        auth_resp = read_response(s)
        elem = ET.fromstring(auth_resp)
        if elem.get("status") != "200":
            raise Exception(f"Auth fallida: {auth_resp[:200]}")

        s.sendall(xml_str.encode())
        resp = read_response(s)
        return ET.fromstring(resp)
    finally:
        s.close()


# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.route("/health", methods=["GET"])
def health():
    try:
        resp = gmp_cmd("<get_version/>")
        version = resp.findtext(".//version") or "desconocida"
        return jsonify({"status": "ok", "gvmd_version": version})
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return jsonify({"status": "error", "detail": str(e)}), 503


@app.route("/scan/start", methods=["POST"])
def scan_start():
    data = request.get_json()
    if not data or "target" not in data:
        return jsonify({"error": "Falta campo 'target'"}), 400

    target_ip = data["target"]

    if not target_ip.startswith("192.168.100."):
        return jsonify({"error": "Target fuera de la subred permitida"}), 403

    # Elegir config de escaneo según scan_type.
    # "quick" usa System Discovery (más liviano).
    # "full" usa Full and fast (análisis completo de vulnerabilidades).
    # Cualquier valor desconocido cae en "full" como default seguro.
    scan_type = data.get("scan_type", "full")
    if scan_type not in ALLOWED_SCAN_TYPES:
        scan_type = "full"

    scan_config_id = (
        SCAN_CONFIG_SYSTEM_DISCOVERY if scan_type == "quick"
        else SCAN_CONFIG_FULL_FAST
    )

    ts        = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
    scan_name = f"AutoScan-{target_ip}-{ts}"

    try:
        r_target = gmp_cmd(
            f"<create_target>"
            f"<name>Target-{target_ip}-{ts}</name>"
            f"<hosts>{target_ip}</hosts>"
            f"<port_list id='{PORT_LIST_ALL_TCP}'/>"
            f"</create_target>"
        )
        if r_target.get("status") != "201":
            return jsonify({
                "error":  "No se pudo crear el target",
                "detail": ET.tostring(r_target).decode(),
            }), 500
        target_id = r_target.get("id")

        r_task = gmp_cmd(
            f"<create_task>"
            f"<name>{scan_name}</name>"
            f"<config id='{scan_config_id}'/>"
            f"<target id='{target_id}'/>"
            f"<scanner id='{SCANNER_OPENVAS}'/>"
            f"</create_task>"
        )
        if r_task.get("status") != "201":
            return jsonify({
                "error":  "No se pudo crear la tarea",
                "detail": ET.tostring(r_task).decode(),
            }), 500
        task_id = r_task.get("id")

        r_start = gmp_cmd(f"<start_task task_id='{task_id}'/>")
        report_id = r_start.findtext(".//report_id") or ""

        return jsonify({
            "status":    "started",
            "task_id":   task_id,
            "target_id": target_id,
            "report_id": report_id,
            "target_ip": target_ip,
            "scan_name": scan_name,
            "scan_type": scan_type,
        })

    except Exception as e:
        logger.error(f"Error scan_start: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/scan/status/<task_id>", methods=["GET"])
def scan_status(task_id):
    try:
        resp = gmp_cmd(f"<get_tasks task_id='{task_id}'/>")
        task = resp.find(".//task")
        if task is None:
            return jsonify({"error": "Tarea no encontrada"}), 404

        status    = task.findtext("status") or "Unknown"
        progress  = task.findtext("progress") or "0"
        name      = task.findtext("name") or ""
        last_rep  = task.find(".//last_report/report")
        report_id = last_rep.get("id") if last_rep is not None else None

        return jsonify({
            "task_id":      task_id,
            "name":         name,
            "status":       status,
            "progress_pct": int(progress),
            "done":         status == "Done",
            "report_id":    report_id,
        })

    except Exception as e:
        logger.error(f"Error scan_status: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/reports", methods=["GET"])
def get_reports():
    task_filter = request.args.get("task_id")
    try:
        resp = gmp_cmd("<get_reports filter='sort-reverse=date rows=20 min_qod=70'/>")
        reports = []

        for rep in resp.findall(".//report[@id]"):
            rep_id  = rep.get("id")
            fecha   = rep.findtext(".//scan_end") or rep.findtext(".//scan_start") or ""
            task_el = rep.find(".//task")
            t_id    = task_el.get("id")        if task_el is not None else ""
            t_name  = task_el.findtext("name") if task_el is not None else ""

            if task_filter and t_id != task_filter:
                continue

            rc     = rep.find(".//result_count")
            high   = int(rc.findtext("hole")    or 0) if rc is not None else 0
            medium = int(rc.findtext("warning") or 0) if rc is not None else 0
            low    = int(rc.findtext("info")    or 0) if rc is not None else 0

            reports.append({
                "report_id": rep_id,
                "task_id":   t_id,
                "task_name": t_name,
                "fecha":     fecha,
                "severidad": {
                    "high": high, "medium": medium,
                    "low":  low,  "total":  high + medium + low,
                },
            })

        return jsonify({"total": len(reports), "reports": reports})

    except Exception as e:
        logger.error(f"Error get_reports: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/reports/<report_id>", methods=["GET"])
def get_report_detail(report_id):
    try:
        resp = gmp_cmd(
            f"<get_reports report_id='{report_id}' details='1' "
            f"filter='min_qod=70 rows=200'/>"
        )
        resultados = []

        for result in resp.findall(".//result"):
            nombre   = result.findtext("name") or ""
            host     = result.findtext(".//host") or ""
            port     = result.findtext("port") or ""
            severity = result.findtext("severity") or "0"
            desc     = result.findtext("description") or ""
            cves     = [
                ref.get("id", "")
                for ref in result.findall(".//ref[@type='cve']")
            ]

            try:
                sev_float = float(severity)
            except ValueError:
                sev_float = 0.0

            if sev_float >= 7.0:   nivel = "HIGH"
            elif sev_float >= 4.0: nivel = "MEDIUM"
            elif sev_float > 0:    nivel = "LOW"
            else:                  nivel = "INFO"

            resultados.append({
                "nombre":          nombre,
                "host":            host,
                "puerto":          port,
                "severidad_cvss":  sev_float,
                "severidad_label": nivel,
                "cves":            cves,
                "descripcion":     (
                    desc[:300] + "..." if len(desc) > 300 else desc
                ),
            })

        resultados.sort(key=lambda x: x["severidad_cvss"], reverse=True)
        resumen = {
            "high":   sum(1 for r in resultados if r["severidad_label"] == "HIGH"),
            "medium": sum(1 for r in resultados if r["severidad_label"] == "MEDIUM"),
            "low":    sum(1 for r in resultados if r["severidad_label"] == "LOW"),
            "info":   sum(1 for r in resultados if r["severidad_label"] == "INFO"),
        }

        return jsonify({
            "report_id":        report_id,
            "total_resultados": len(resultados),
            "resumen":          resumen,
            "resultados":       resultados,
        })

    except Exception as e:
        logger.error(f"Error get_report_detail: {e}")
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=False)
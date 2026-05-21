#!/usr/bin/env python3

from flask import Flask, request, jsonify
import subprocess
import xml.etree.ElementTree as ET
import shlex
import re

app = Flask(__name__)

# Whitelist de IPs/rangos permitidos para escanear (tu lab)
ALLOWED_NETWORKS = [
    "192.168.100.",  # Red del laboratorio
]

def is_target_allowed(target: str) -> bool:
    """Valida que el target esté dentro de la red de laboratorio."""
    return any(target.startswith(net) for net in ALLOWED_NETWORKS)

def parse_nmap_xml(xml_output: str) -> list:
    """Parsea la salida XML de Nmap y retorna estructura de datos limpia."""
    hosts = []
    try:
        root = ET.fromstring(xml_output)
        for host in root.findall("host"):
            # Estado del host
            status = host.find("status")
            if status is None or status.get("state") != "up":
                continue

            host_data = {
                "status": "up",
                "ip": None,
                "hostname": None,
                "os": None,
                "ports": [],
            }

            # IP y hostname
            for addr in host.findall("address"):
                if addr.get("addrtype") == "ipv4":
                    host_data["ip"] = addr.get("addr")

            hostnames = host.find("hostnames")
            if hostnames is not None:
                hn = hostnames.find("hostname")
                if hn is not None:
                    host_data["hostname"] = hn.get("name")

            # Sistema operativo
            os_elem = host.find("os")
            if os_elem is not None:
                osmatch = os_elem.find("osmatch")
                if osmatch is not None:
                    host_data["os"] = {
                        "name": osmatch.get("name"),
                        "accuracy": osmatch.get("accuracy"),
                    }

            # Puertos y servicios
            ports_elem = host.find("ports")
            if ports_elem is not None:
                for port in ports_elem.findall("port"):
                    port_state = port.find("state")
                    if port_state is None:
                        continue

                    port_data = {
                        "port": int(port.get("portid")),
                        "protocol": port.get("protocol"),
                        "state": port_state.get("state"),
                        "service": None,
                        "version": None,
                    }

                    service = port.find("service")
                    if service is not None:
                        port_data["service"] = service.get("name")
                        version_parts = [
                            service.get("product", ""),
                            service.get("version", ""),
                            service.get("extrainfo", ""),
                        ]
                        version_str = " ".join(p for p in version_parts if p).strip()
                        if version_str:
                            port_data["version"] = version_str

                    port_data["open"] = port_data["state"] == "open"
                    host_data["ports"].append(port_data)

            host_data["open_ports_count"] = sum(
                1 for p in host_data["ports"] if p.get("open")
            )
            hosts.append(host_data)

    except ET.ParseError as e:
        raise ValueError(f"Error parseando XML de Nmap: {e}")

    return hosts


# ─────────────────────────────────────────────
# ENDPOINTS
# ─────────────────────────────────────────────

@app.route("/health", methods=["GET"])
def health():
    """Healthcheck para N8N y docker-compose."""
    result = subprocess.run(["nmap", "--version"], capture_output=True, text=True)
    version = result.stdout.split("\n")[0] if result.returncode == 0 else "unknown"
    return jsonify({"status": "ok", "nmap_version": version})


@app.route("/scan/quick", methods=["POST"])
def scan_quick():
    """
    Escaneo rápido: descubrimiento de hosts y puertos TOP 100.
    Body JSON: { "target": "192.168.100.10" }
    Usado en N8N como primer paso del workflow.
    """
    data = request.get_json()
    target = data.get("target", "").strip()

    if not target:
        return jsonify({"error": "Campo 'target' requerido"}), 400
    if not is_target_allowed(target):
        return jsonify({"error": f"Target '{target}' no está en la red de laboratorio permitida"}), 403

    cmd = ["nmap", "-sV", "--top-ports", "100", "-T4", "-oX", "-", target]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if result.returncode != 0:
            return jsonify({"error": "Nmap falló", "stderr": result.stderr}), 500
        hosts = parse_nmap_xml(result.stdout)
        return jsonify({
            "scan_type": "quick",
            "target": target,
            "command": " ".join(cmd),
            "hosts": hosts,
            "total_hosts_up": len(hosts),
        })
    except subprocess.TimeoutExpired:
        return jsonify({"error": "Timeout: escaneo superó 120 segundos"}), 504


@app.route("/scan/full", methods=["POST"])
def scan_full():
    """
    Escaneo completo: todos los puertos + detección OS + scripts básicos.
    Body JSON: { "target": "192.168.100.11" }
    Usado para análisis más profundo de hosts específicos.
    """
    data = request.get_json()
    target = data.get("target", "").strip()

    if not target:
        return jsonify({"error": "Campo 'target' requerido"}), 400
    if not is_target_allowed(target):
        return jsonify({"error": f"Target '{target}' no está en la red de laboratorio permitida"}), 403

    cmd = ["nmap", "-sV", "-sC", "-O", "-p-", "-T4", "-oX", "-", target]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        if result.returncode != 0:
            return jsonify({"error": "Nmap falló", "stderr": result.stderr}), 500
        hosts = parse_nmap_xml(result.stdout)
        return jsonify({
            "scan_type": "full",
            "target": target,
            "command": " ".join(cmd),
            "hosts": hosts,
            "total_hosts_up": len(hosts),
        })
    except subprocess.TimeoutExpired:
        return jsonify({"error": "Timeout: escaneo superó 600 segundos"}), 504


@app.route("/scan/discovery", methods=["POST"])
def scan_discovery():
    """
    Descubrimiento de red: qué hosts están UP en un rango.
    Body JSON: { "target": "192.168.100.0/24" }
    Usado para mapear la red antes de escanear hosts específicos.
    """
    data = request.get_json()
    target = data.get("target", "192.168.100.0/24").strip()

    if not is_target_allowed(target):
        return jsonify({"error": f"Target '{target}' no está en la red de laboratorio permitida"}), 403

    cmd = ["nmap", "-sn", "-T4", "-oX", "-", target]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if result.returncode != 0:
            return jsonify({"error": "Nmap falló", "stderr": result.stderr}), 500
        hosts = parse_nmap_xml(result.stdout)
        return jsonify({
            "scan_type": "discovery",
            "target": target,
            "command": " ".join(cmd),
            "hosts_up": [h["ip"] for h in hosts],
            "total_hosts_up": len(hosts),
        })
    except subprocess.TimeoutExpired:
        return jsonify({"error": "Timeout"}), 504


@app.route("/scan/vuln", methods=["POST"])
def scan_vuln():
    """
    Escaneo con scripts NSE de vulnerabilidades (vuln category).
    Body JSON: { "target": "192.168.100.11" }
    Complementa los resultados de OpenVAS.
    """
    data = request.get_json()
    target = data.get("target", "").strip()

    if not target:
        return jsonify({"error": "Campo 'target' requerido"}), 400
    if not is_target_allowed(target):
        return jsonify({"error": f"Target '{target}' no está en la red de laboratorio permitida"}), 403

    cmd = ["nmap", "--script", "vuln", "-sV", "-T4", "-oX", "-", target]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if result.returncode != 0:
            return jsonify({"error": "Nmap falló", "stderr": result.stderr}), 500

        # Para el scan vuln también extraemos el output normal para más detalle
        hosts = parse_nmap_xml(result.stdout)

        # Extraer script outputs crudos para análisis adicional
        script_outputs = []
        try:
            root = ET.fromstring(result.stdout)
            for host in root.findall("host"):
                for port in host.findall(".//port"):
                    for script in port.findall("script"):
                        script_outputs.append({
                            "port": port.get("portid"),
                            "script_id": script.get("id"),
                            "output": script.get("output", "")[:500],  # limitar output
                        })
        except Exception:
            pass

        return jsonify({
            "scan_type": "vuln",
            "target": target,
            "command": " ".join(cmd),
            "hosts": hosts,
            "script_results": script_outputs,
            "total_hosts_up": len(hosts),
        })
    except subprocess.TimeoutExpired:
        return jsonify({"error": "Timeout: escaneo superó 300 segundos"}), 504


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
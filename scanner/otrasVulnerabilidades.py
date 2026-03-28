import subprocess

import requests


def analizar_vulnerabilidades_nmap(host):
    scripts = "ssl-heartbleed,ssl-poodle,ssl-robot"
    cmd = ["nmap", "-p", "443", f"--script={scripts}", host]
    try:
        resultado = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        output = resultado.stdout
        return {
            "heartbleed": "VULNERABLE" in output and "ssl-heartbleed" in output,
            "poodle": "VULNERABLE" in output and "ssl-poodle" in output,
            "robot": "VULNERABLE" in output and "ssl-robot" in output,
        }
    except Exception:
        return {"error": "No se pudo ejecutar el escaneo de vulnerabilidades"}


def analizar_cabeceras_http(host):
    try:
        url = f"https://{host}"
        response = requests.get(url, timeout=5, verify=False)
        hsts = response.headers.get("Strict-Transport-Security")
        return {
            "hsts_activo": hsts is not None,
            "hsts_valor": hsts if hsts else "No configurado",
        }
    except Exception:
        return {"hsts_activo": False, "error": "No se pudo conectar al servidor"}


def analizar_detalles_protocolo(host):
    vulnerabilidades = analizar_vulnerabilidades_nmap(host)
    cabeceras = analizar_cabeceras_http(host)
    return {
        "vulnerabilidades": vulnerabilidades,
        "configuracion_seguridad": cabeceras,
    }

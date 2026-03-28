import sys
from pathlib import Path

from flask import Flask, jsonify, render_template, request

_ROOT = Path(__file__).resolve().parent.parent
_SCANNER = _ROOT / "scanner"
if str(_SCANNER) not in sys.path:
    sys.path.insert(0, str(_SCANNER))

from backend1 import generar_reporte_unificado  # noqa: E402
from validator import is_valid_target, normalize_target  # noqa: E402

app = Flask(__name__)


def _recolectar_errores(reporte: dict) -> list:
    out = []
    res = reporte.get("resultados") or {}
    for clave in ("protocolos", "certificado", "ciphers"):
        bloque = res.get(clave)
        if isinstance(bloque, dict) and bloque.get("error"):
            out.append(f"{clave}: {bloque['error']}")
    vul = (res.get("vulnerabilidades_y_config") or {}).get("vulnerabilidades") or {}
    if isinstance(vul, dict) and vul.get("error"):
        out.append(f"vulnerabilidades: {vul['error']}")
    return out


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/scan", methods=["POST"])
def scan():
    data = request.json or {}
    domain = (data.get("domain") or "").strip()

    if not domain:
        return jsonify({"error": "No has proporcionado un dominio"}), 400

    target = normalize_target(domain)
    if not is_valid_target(target):
        return jsonify({"error": "Dominio o IP inválido"}), 400

    try:
        reporte = generar_reporte_unificado(target)
    except Exception as e:
        return jsonify({"error": f"Error en el escaneo: {e}"}), 500

    reporte["errors"] = _recolectar_errores(reporte)
    return jsonify(reporte)


if __name__ == "__main__":
    app.run(debug=True, port=5000)

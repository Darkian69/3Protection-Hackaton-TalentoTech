import json
from datetime import datetime
from pathlib import Path

from motortls import escanear_protocolos
from certificado import analizar_certificado_nmap
from ciphers import AnalizadorCiphers
from otrasVulnerabilidades import analizar_detalles_protocolo
from risk_scorer import enriquecer_reporte

_REPO_ROOT = Path(__file__).resolve().parent.parent
_CSV_IANA = _REPO_ROOT / "data" / "iana_ciphers_limpios.csv"


def generar_reporte_unificado(dominio, ruta_csv=None):
    print(f"[*] Iniciando auditoria completa para: {dominio}")

    print("[+] Analizando versiones de protocolo...")
    data_protocolos = escanear_protocolos(dominio)

    print("[+] Analizando certificado digital...")
    data_certificado = analizar_certificado_nmap(dominio)

    print("[+] Analizando suites de cifrado (Ciphers)...")
    archivo_csv = ruta_csv or str(_CSV_IANA)
    ciphers = AnalizadorCiphers(archivo_csv)
    data_ciphers = ciphers.escanear_servidor(dominio)

    print("[+] Escaneando vulnerabilidades y configuraciones avanzadas...")
    data_vulnerabilidades = analizar_detalles_protocolo(dominio)

    reporte_final = {
        "target": dominio,
        "fecha_escaneo": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "resultados": {
            "protocolos": data_protocolos,
            "certificado": data_certificado,
            "ciphers": data_ciphers,
            "vulnerabilidades_y_config": data_vulnerabilidades,
        },
    }

    return enriquecer_reporte(reporte_final)


if __name__ == "__main__":
    target = "example.com"
    try:
        json_final = generar_reporte_unificado(target)
        out_path = _REPO_ROOT / "resultado_escaneo.json"
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(json_final, f, indent=4, ensure_ascii=False)
        print(f"\n[!] Reporte: {out_path}")
    except Exception as e:
        print(f"[-] Error: {e}")

from __future__ import annotations

import copy
from typing import Any, Dict, List, Tuple

_PROTO_CRITICOS = frozenset({"SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"})
_PROTO_BUENOS = frozenset({"TLSv1.2", "TLSv1.3"})


def _norm_status(val: Any) -> str:
    if val is None:
        return ""
    return str(val).strip().upper()


def _is_habilitado(val: Any) -> bool:
    return _norm_status(val) == "HABILITADO"


def _hallazgo(
    prioridad: int,
    categoria: str,
    descripcion: str,
    severidad: str,
) -> Dict[str, Any]:
    return {
        "prioridad": prioridad,
        "categoria": categoria,
        "descripcion": descripcion,
        "severidad": severidad,
    }


def _puntaje_a_calificacion(puntaje: int) -> str:
    if puntaje >= 90:
        return "A"
    if puntaje >= 80:
        return "B"
    if puntaje >= 70:
        return "C"
    if puntaje >= 60:
        return "D"
    return "F"


def _severidad_desde_puntaje(p: int) -> str:
    if p >= 80:
        return "Baja"
    if p >= 60:
        return "Media"
    if p >= 40:
        return "Alta"
    return "Crítica"


def _tono_protocolo(nombre: str, habilitado: bool, status_raw: str) -> str:
    s = _norm_status(status_raw)
    if s in ("NO_SOPORTADO_CLIENTE", "ERROR_CONEXION") or (
        not habilitado and s not in ("HABILITADO", "DESHABILITADO", "NO EVALUADO")
    ):
        return "gris"
    if s == "NO EVALUADO" or s == "":
        return "gris"
    if not habilitado:
        return "gris"
    if nombre in _PROTO_CRITICOS:
        return "rojo"
    if nombre in _PROTO_BUENOS:
        return "verde"
    return "amarillo"


def _evaluar_ciphers(ciphers_block: Any) -> Tuple[int, List[Dict[str, Any]], int]:
    hallazgos: List[Dict[str, Any]] = []
    if not isinstance(ciphers_block, dict):
        return 0, hallazgos, 0
    if "error" in ciphers_block:
        hallazgos.append(
            _hallazgo(5, "Ciphers", str(ciphers_block["error"]), "media")
        )
        return 8, hallazgos, 0

    count_n = 0
    for _ver, suites in ciphers_block.items():
        if not isinstance(suites, list):
            continue
        for item in suites:
            if not isinstance(item, dict):
                continue
            rec = str(item.get("iana_recommendation", "")).strip().upper()
            if rec == "N":
                count_n += 1

    penal = 0
    if count_n > 0:
        penal = min(5 + (count_n * 2), 28)
        nivel = "alta" if count_n >= 8 else "media"
        hallazgos.append(
            _hallazgo(
                4,
                "Ciphers",
                f"Se detectaron {count_n} suite(s) con recomendación IANA 'N' (no recomendado). "
                "Priorizar suites con 'Y' y deshabilitar las obsoletas.",
                nivel,
            )
        )
    return penal, hallazgos, count_n


def evaluar_riesgo(reporte: Dict[str, Any]) -> Dict[str, Any]:
    res = reporte.get("resultados") or {}
    protocolos = res.get("protocolos") or {}
    cert = res.get("certificado") or {}
    ciphers_block = res.get("ciphers")
    vuln_block = res.get("vulnerabilidades_y_config") or {}
    vulns = vuln_block.get("vulnerabilidades") or {}

    hallazgos: List[Dict[str, Any]] = []
    fortalezas: List[str] = []
    debilidades: List[str] = []
    recomendaciones: List[str] = []

    puntaje = 100
    falla_inmediata = False

    for nombre, etiqueta in (
        ("heartbleed", "Heartbleed"),
        ("poodle", "POODLE"),
        ("robot", "ROBOT"),
    ):
        val = vulns.get(nombre)
        if val is True:
            falla_inmediata = True
            hallazgos.append(
                _hallazgo(
                    1,
                    "Vulnerabilidad",
                    f"Detección positiva o indicio crítico de {etiqueta}. "
                    "Tratar como falla inmediata: parchear, rotar claves y reconfigurar.",
                    "critica",
                )
            )
            debilidades.append(f"Vulnerabilidad crítica: {etiqueta}")
    if isinstance(vulns, dict) and vulns.get("error"):
        hallazgos.append(
            _hallazgo(
                6,
                "Vulnerabilidades",
                f"No se pudo evaluar vulnerabilidades: {vulns['error']}",
                "media",
            )
        )
        puntaje -= 5

    if isinstance(protocolos, dict) and protocolos.get("error"):
        hallazgos.append(
            _hallazgo(2, "Protocolos", str(protocolos["error"]), "alta")
        )
        debilidades.append("No se pudieron evaluar protocolos TLS.")
        puntaje -= 25
        ui_protocolos: List[Dict[str, str]] = []
    else:
        ui_protocolos = []
        for nombre in (
            "SSLv2",
            "SSLv3",
            "TLSv1.0",
            "TLSv1.1",
            "TLSv1.2",
            "TLSv1.3",
        ):
            raw = protocolos.get(nombre) if isinstance(protocolos, dict) else None
            texto = str(raw) if raw is not None else "NO EVALUADO"
            hab = _is_habilitado(raw)
            tono = _tono_protocolo(nombre, hab, texto)
            ui_protocolos.append(
                {"nombre": nombre, "estado_texto": texto, "tono": tono}
            )
            if hab and nombre in _PROTO_CRITICOS:
                hallazgos.append(
                    _hallazgo(
                        2,
                        "Protocolo",
                        f"{nombre} habilitado: superficie crítica; deshabilitar de inmediato.",
                        "critica",
                    )
                )
                debilidades.append(f"Protocolo inseguro habilitado: {nombre}")
                puntaje -= 14
            elif hab and nombre == "TLSv1.2":
                fortalezas.append(
                    "TLS 1.2 habilitado (postura aceptable si no hay protocolos legacy)."
                )
            elif hab and nombre == "TLSv1.3":
                fortalezas.append("TLS 1.3 habilitado (excelente).")

        tls13 = (
            _is_habilitado(protocolos.get("TLSv1.3"))
            if isinstance(protocolos, dict)
            else False
        )
        tls12 = (
            _is_habilitado(protocolos.get("TLSv1.2"))
            if isinstance(protocolos, dict)
            else False
        )
        legacy_on = any(
            _is_habilitado(protocolos.get(p))
            for p in _PROTO_CRITICOS
            if isinstance(protocolos, dict)
        )
        if tls13 and not legacy_on:
            recomendaciones.append(
                "Mantener TLS 1.3 como preferido y eliminar protocolos antiguos si aún aparecen habilitados en otros balanceadores."
            )
        elif tls12 and not legacy_on and not tls13:
            recomendaciones.append(
                "Habilitar TLS 1.3 cuando el stack lo permita; mantener TLS 1.2 como mínimo sin SSLv3/TLS 1.0/1.1."
            )
        elif tls12 and legacy_on:
            recomendaciones.append(
                "Deshabilitar SSL 2/3 y TLS 1.0/1.1 en todos los puntos de terminación TLS."
            )

    if isinstance(cert, dict) and cert.get("error"):
        hallazgos.append(
            _hallazgo(2, "Certificado", str(cert["error"]), "alta")
        )
        debilidades.append("Certificado no analizado correctamente.")
        puntaje -= 20
        ui_cert = {
            "tono": "amarillo",
            "badge_etiqueta": "No evaluado",
            "alertas": [str(cert["error"])],
        }
    else:
        alertas_cert: List[str] = []
        tono_cert = "verde"
        badge = "Seguro / Confiable"

        if isinstance(cert, dict) and cert.get("is_expired"):
            hallazgos.append(
                _hallazgo(
                    2,
                    "Certificado",
                    "Certificado expirado: impacto crítico en confianza y disponibilidad.",
                    "critica",
                )
            )
            debilidades.append("Certificado expirado.")
            puntaje -= 45
            tono_cert = "rojo"
            badge = "Crítico"
            alertas_cert.append("El certificado está expirado.")

        if isinstance(cert, dict) and cert.get("is_self_signed"):
            hallazgos.append(
                _hallazgo(
                    3,
                    "Certificado",
                    "Certificado autofirmado: no apto para confianza pública.",
                    "critica",
                )
            )
            debilidades.append("Certificado autofirmado.")
            puntaje -= 35
            if tono_cert != "rojo":
                tono_cert = "amarillo"
            badge = "No confiable / Autofirmado"
            alertas_cert.append(
                "Certificado autofirmado (no confiable en cadena pública)."
            )

        ki = cert.get("key_info") if isinstance(cert, dict) else None
        if isinstance(ki, dict):
            alg = str(ki.get("algorithm", "")).upper()
            size = int(ki.get("size") or 0)
            if ki.get("is_weak") or (
                alg == "RSA" and size > 0 and size < 2048
            ) or (alg == "ECDSA" and size > 0 and size < 256):
                hallazgos.append(
                    _hallazgo(
                        3,
                        "Certificado",
                        f"Clave débil o subdimensionada ({alg} {size} bits). Mínimo recomendado: RSA ≥2048 o curva equivalente.",
                        "alta",
                    )
                )
                debilidades.append("Tamaño o tipo de clave insuficiente.")
                puntaje -= 22
                if tono_cert == "verde":
                    tono_cert = "amarillo"
                if badge == "Seguro / Confiable":
                    badge = "Advertencia"
                alertas_cert.append(
                    "La clave criptográfica se considera débil (<2048 RSA o curva insuficiente)."
                )

        ui_cert = {
            "tono": tono_cert,
            "badge_etiqueta": badge,
            "alertas": alertas_cert,
        }

        if tono_cert == "verde" and not alertas_cert:
            fortalezas.append(
                "Certificado vigente y cadena coherente según el análisis."
            )

    pen_cipher, hall_cipher, count_n = _evaluar_ciphers(ciphers_block)
    hallazgos.extend(hall_cipher)
    puntaje -= pen_cipher
    if count_n:
        debilidades.append(f"{count_n} suite(s) marcadas como 'N' en IANA.")

    if falla_inmediata:
        puntaje = 0

    puntaje = max(0, min(100, int(round(puntaje))))
    calificacion = _puntaje_a_calificacion(puntaje)
    if falla_inmediata:
        calificacion = "F"

    severidad = _severidad_desde_puntaje(puntaje)
    if falla_inmediata:
        severidad = "Crítica"

    if falla_inmediata:
        estado_postura = "Comprometida / requiere acción inmediata"
    elif calificacion in ("A", "B"):
        estado_postura = "Alineada con buenas prácticas"
    elif calificacion == "C":
        estado_postura = "Mejora recomendada"
    else:
        estado_postura = "Deficiente — priorizar remediación"

    hallazgos.sort(key=lambda x: x["prioridad"])

    def _unicos(seq: List[str]) -> List[str]:
        seen = set()
        out: List[str] = []
        for x in seq:
            if x not in seen:
                seen.add(x)
                out.append(x)
        return out

    fortalezas = _unicos(fortalezas)
    debilidades = _unicos(debilidades)

    if not recomendaciones:
        if calificacion in ("A", "B"):
            recomendaciones.append(
                "Mantener parches, revisiones periódicas y pruebas tras cada cambio de terminación TLS."
            )
        else:
            recomendaciones.append(
                "Elaborar plan de remediación priorizando hallazgos críticos y validar en staging antes de producción."
            )

    tono_global = "verde"
    if calificacion in ("D", "F") or falla_inmediata:
        tono_global = "rojo"
    elif calificacion == "C":
        tono_global = "amarillo"
    elif calificacion == "B":
        tono_global = "verde"

    return {
        "calificacion_final": calificacion,
        "puntaje": puntaje,
        "severidad_general": severidad,
        "estado_postura": estado_postura,
        "hallazgos_prioritarios": hallazgos,
        "fortalezas": fortalezas,
        "debilidades": debilidades,
        "recomendaciones": recomendaciones,
        "ui": {
            "tono_calificacion": tono_global,
            "protocolos": ui_protocolos,
            "certificado": ui_cert,
            "ciphers": {"suites_con_recomendacion_n": count_n},
        },
    }


def enriquecer_reporte(reporte: Dict[str, Any]) -> Dict[str, Any]:
    out = copy.deepcopy(reporte)
    out["scoring_y_recomendaciones"] = evaluar_riesgo(out)
    return out

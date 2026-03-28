import re
import socket
import ssl
import warnings

warnings.filterwarnings("ignore", category=DeprecationWarning)


def validar_host(host):
    patron_dominio = r"^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$"
    patron_ip = r"^\d{1,3}(\.\d{1,3}){3}$"
    return bool(re.match(patron_dominio, host)) or bool(re.match(patron_ip, host))


def verificar_puerto_abierto(host, puerto=443):
    try:
        with socket.create_connection((host, puerto), timeout=3):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def obtener_contexto_permisivo(version_enum=None, protocolo_legacy=None):
    try:
        if protocolo_legacy is not None:
            contexto = ssl.SSLContext(protocolo_legacy)
        else:
            contexto = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            if version_enum:
                contexto.minimum_version = version_enum
                contexto.maximum_version = version_enum
        contexto.set_ciphers("DEFAULT@SECLEVEL=0")
        contexto.check_hostname = False
        contexto.verify_mode = ssl.CERT_NONE
        return contexto
    except (AttributeError, ValueError):
        return None


def escanear_protocolos(host):
    if not validar_host(host):
        return {"error": "Formato de dominio o IP inválido"}

    if not verificar_puerto_abierto(host):
        return {"error": "Puerto 443 cerrado o host inalcanzable"}

    protocolos = {
        "SSLv2": {"legacy": getattr(ssl, "PROTOCOL_SSLv2", None)},
        "SSLv3": {"legacy": getattr(ssl, "PROTOCOL_SSLv3", None)},
        "TLSv1.0": {"enum": getattr(ssl.TLSVersion, "TLSv1", None)},
        "TLSv1.1": {"enum": getattr(ssl.TLSVersion, "TLSv1_1", None)},
        "TLSv1.2": {"enum": getattr(ssl.TLSVersion, "TLSv1_2", None)},
        "TLSv1.3": {"enum": getattr(ssl.TLSVersion, "TLSv1_3", None)},
    }

    resultados = {}

    for nombre, config in protocolos.items():
        ctx = obtener_contexto_permisivo(
            version_enum=config.get("enum"),
            protocolo_legacy=config.get("legacy"),
        )
        if ctx is None:
            resultados[nombre] = "NO_SOPORTADO_CLIENTE"
            continue
        try:
            with socket.create_connection((host, 443), timeout=3) as sock:
                with ctx.wrap_socket(sock, server_hostname=host):
                    resultados[nombre] = "HABILITADO"
        except (ssl.SSLError, ssl.SSLEOFError):
            resultados[nombre] = "DESHABILITADO"
        except Exception:
            resultados[nombre] = "ERROR_CONEXION"

    return resultados

import socket
import ssl
import re
import warnings

# Silenciamos advertencias de protocolos obsoletos
warnings.filterwarnings("ignore", category=DeprecationWarning)

def validar_host(host):
    """Verifica si la entrada es un dominio o IP válida."""
    patron_dominio = r'^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$'
    patron_ip = r'^\d{1,3}(\.\d{1,3}){3}$'
    return bool(re.match(patron_dominio, host)) or bool(re.match(patron_ip, host))

def verificar_puerto_abierto(host, puerto=443):
    """Comprueba si el puerto 443 responde antes de intentar el handshake."""
    try:
        with socket.create_connection((host, puerto), timeout=3):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False

def obtener_contexto_permisivo(version_enum=None, protocolo_legacy=None):
    """Configura un contexto SSL que permite detectar configuraciones inseguras."""
    try:
        # Para protocolos muy antiguos (SSLv2/v3) usamos el constructor directo si existe
        if protocolo_legacy is not None:
            contexto = ssl.SSLContext(protocolo_legacy)
        else:
            contexto = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            if version_enum:
                contexto.minimum_version = version_enum
                contexto.maximum_version = version_enum

        contexto.set_ciphers('DEFAULT@SECLEVEL=0') # Baja defensas del cliente para auditar
        contexto.check_hostname = False
        contexto.verify_mode = ssl.CERT_NONE
        return contexto
    except (AttributeError, ValueError):
        return None # El sistema local no soporta siquiera intentar este protocolo

def escanear_protocolos(host):
    """Ejecuta el análisis completo y retorna un diccionario estructurado."""
    
    # 1. Validaciones iniciales
    if not validar_host(host):
        return {"error": "Formato de dominio o IP inválido"}
    
    if not verificar_puerto_abierto(host):
        return {"error": "Puerto 443 cerrado o host inalcanzable"}

    # 2. Definición de protocolos a probar
    # Intentamos obtener constantes de SSL antiguas de forma segura
    protocolos = {
        "SSLv2": {"legacy": getattr(ssl, "PROTOCOL_SSLv2", None)},
        "SSLv3": {"legacy": getattr(ssl, "PROTOCOL_SSLv3", None)},
        "TLSv1.0": {"enum": getattr(ssl.TLSVersion, "TLSv1", None)},
        "TLSv1.1": {"enum": getattr(ssl.TLSVersion, "TLSv1_1", None)},
        "TLSv1.2": {"enum": getattr(ssl.TLSVersion, "TLSv1_2", None)},
        "TLSv1.3": {"enum": getattr(ssl.TLSVersion, "TLSv1_3", None)},
    }

    resultados = {}

    # 3. Ciclo de escaneo
    for nombre, config in protocolos.items():
        ctx = obtener_contexto_permisivo(
            version_enum=config.get("enum"), 
            protocolo_legacy=config.get("legacy")
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

# --- EJECUCIÓN ---
if __name__ == "__main__":
    target = "34.45.64.235" 
    data = escanear_protocolos(target)
    print(data)
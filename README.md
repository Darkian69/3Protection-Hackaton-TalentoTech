# TLS Risk Analyzer

Auditoría TLS desde consola o con interfaz web. Usa **nmap** y **openssl** del sistema; en Python solo hace falta lo del `requirements.txt`.

## Estructura

```
scanner/     # Orquestador (backend1), protocolos, cert, ciphers, vulnerabilidades, scoring
web/         # Flask: app, plantilla, estáticos (aquí va el logo ico.jpg)
data/        # iana_ciphers_limpios.csv para etiquetar suites
```

## Instalación

```bash
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

Asegúrate de tener **nmap** instalado y accesible en el PATH.

## Web

```bash
cd web
python app.py
```

Abre http://127.0.0.1:5000, escribe un dominio y escanea.

El logo del header debe estar en `web/static/ico.jpg` (si falta, copia tu imagen ahí).

## Solo JSON (CLI)

Desde la raíz del proyecto:

```bash
python scanner/backend1.py
```

El dominio por defecto está en `scanner/backend1.py`. La salida es `resultado_escaneo.json` en la raíz del repo.

## Notas

- Los escaneos pueden tardar (nmap, varias conexiones SSL).
- El scoring viene en la clave `scoring_y_recomendaciones` del JSON de salida.

import csv
import re
import subprocess


class AnalizadorCiphers:
    def __init__(self, csv_path):
        self.iana_db = {}
        self._cargar_iana_csv(csv_path)

    def _cargar_iana_csv(self, path):
        try:
            with open(path, mode="r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    nombre = row["Description"].strip()
                    rec = row["Recommended"].strip()
                    self.iana_db[nombre] = rec
        except Exception as e:
            print(f"Error al cargar base de datos IANA: {e}")

    def escanear_servidor(self, host):
        cmd = ["nmap", "-p", "443", "--script", "ssl-enum-ciphers", host]
        try:
            resultado_nmap = subprocess.run(
                cmd, capture_output=True, text=True, timeout=60
            )
            output = resultado_nmap.stdout
        except Exception as e:
            return {"error": f"Error ejecutando Nmap: {e}"}

        if "ssl-enum-ciphers" not in output:
            return {"error": "No se encontraron ciphers. ¿El puerto 443 está abierto?"}

        reporte_final = {}
        bloques = re.split(r"\|\s+(TLSv[\d\.]+):\s*", output)

        for i in range(1, len(bloques), 2):
            version_tls = bloques[i]
            contenido_bloque = bloques[i + 1]
            reporte_final[version_tls] = []
            nombres_encontrados = re.findall(r"\|\s+([A-Z0-9_]+)", contenido_bloque)
            for nombre in nombres_encontrados:
                if nombre in self.iana_db:
                    reporte_final[version_tls].append(
                        {
                            "cipher": nombre,
                            "iana_recommendation": self.iana_db[nombre],
                        }
                    )
        return reporte_final

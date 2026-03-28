import subprocess
import re
import csv
import json

class AnalizadorCiphers:
    def __init__(self, csv_path):
        #Carga y lee el csv
        self.iana_db = {}  #Donde se guardara el csv
        self._cargar_iana_csv(csv_path)

    def _cargar_iana_csv(self, path):
        try:
            with open(path, mode='r', encoding='utf-8') as f:
                # DictReader usa la primera fila como llaves del diccionario
                reader = csv.DictReader(f)
                for row in reader:
                    nombre = row['Description'].strip()
                    rec = row['Recommended'].strip()
                    self.iana_db[nombre] = rec
        except Exception as e:
            print(f"Error al cargar base de datos IANA: {e}")

    def escanear_servidor(self, host):

        # Comando para enumerar ciphers
        cmd = ["nmap", "-p", "443", "--script", "ssl-enum-ciphers", host]
        
        try:
            resultado_nmap = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            output = resultado_nmap.stdout
        except Exception as e:
            return {"error": f"Error ejecutando Nmap: {e}"}

        if "ssl-enum-ciphers" not in output:
            return {"error": "No se encontraron ciphers. ¿El puerto 443 está abierto?"}

        
        reporte_final = {} #Repuesta nmap

        #Procesar respuesta nmap
        bloques = re.split(r"\|\s+(TLSv[\d\.]+):\s*", output)

        for i in range(1, len(bloques), 2):
            version_tls = bloques[i]
            contenido_bloque = bloques[i+1]
            
            reporte_final[version_tls] = []

            nombres_encontrados = re.findall(r"\|\s+([A-Z0-9_]+)", contenido_bloque)

            for nombre in nombres_encontrados:
                if nombre in self.iana_db: #verifica si el cipher esta en  los ciphers de iana
                    recomendacion_iana = self.iana_db[nombre]

                    reporte_final[version_tls].append({
                        "cipher": nombre,
                        "iana_recommendation": recomendacion_iana
                    })

        return reporte_final #Resultado cipher con categorizacion

# --- EJEMPLO DE INTEGRACIÓN ---

if __name__ == "__main__":
    # 1. Especifica la ruta de tu archivo CSV
    archivo_csv = "iana_ciphers_limpios.csv" 
    
    # 2. Crear instancia del motor
    motor = AnalizadorCiphers(archivo_csv)

    # 3. Definir el dominio a probar
    dominio_prueba = "34.45.64.235"  # "34.45.64.235"
    
    print(f"Analizando ciphers de {dominio_prueba} con base de datos IANA...\n")
    
    # 4. Obtener el diccionario de resultados
    resultados = motor.escanear_servidor(dominio_prueba)

    # 5. Mostrar ejemplo de salida limpia
    print(json.dumps(resultados, indent=4))
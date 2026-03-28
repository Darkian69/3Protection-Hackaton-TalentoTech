import re
import subprocess
from datetime import datetime


def analizar_certificado_nmap(host):
    cmd = ["nmap", "-p", "443", "--script", "ssl-cert", host]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    output = proc.stdout

    if "ssl-cert" not in output:
        return {"error": "No se pudo extraer el certificado o el puerto 443 está cerrado"}

    subject_match = re.search(r"Subject:\s*(?:[\w]+=)?([^/\n,]+)", output)
    issuer_match = re.search(r"Issuer:\s*(?:[\w]+=)?([^/\n,]+)", output)
    subject = subject_match.group(1).strip() if subject_match else "Unknown"
    issuer = issuer_match.group(1).strip() if issuer_match else "Unknown"

    exp_match = re.search(r"Not valid after:\s+(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})", output)
    is_expired = True
    days_to_expire = 0

    if exp_match:
        fecha_exp = datetime.fromisoformat(exp_match.group(1))
        days_to_expire = (fecha_exp - datetime.now()).days
        is_expired = days_to_expire < 0

    key_type_match = re.search(r"Public Key type:\s*(\w+)", output)
    key_bits_match = re.search(r"Public Key bits:\s*(\d+)", output)
    key_alg = key_type_match.group(1).upper() if key_type_match else "Unknown"
    key_size = int(key_bits_match.group(1)) if key_bits_match else 0

    is_weak = False
    if key_alg == "RSA" and key_size < 2048:
        is_weak = True
    elif key_alg == "ECDSA" and key_size < 256:
        is_weak = True

    sig_algo_match = re.search(r"Signature Algorithm:\s*(.*?)\n", output)
    signature_algorithm = sig_algo_match.group(1).strip() if sig_algo_match else "Unknown"

    subject_line = re.search(r"Subject: (.*?)\n", output)
    issuer_line = re.search(r"Issuer: (.*?)\n", output)
    is_self_signed = False
    if subject_line and issuer_line:
        is_self_signed = subject_line.group(1).strip() == issuer_line.group(1).strip()

    trust_chain = "Untrusted (Self-Signed)" if is_self_signed else "Valid"

    return {
        "subject": subject,
        "issuer": issuer,
        "is_expired": is_expired,
        "days_to_expire": days_to_expire,
        "key_info": {
            "algorithm": key_alg,
            "size": key_size,
            "is_weak": is_weak,
        },
        "signature_algorithm": signature_algorithm,
        "is_self_signed": is_self_signed,
        "trust_chain": trust_chain,
    }

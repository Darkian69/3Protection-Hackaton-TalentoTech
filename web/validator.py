import ipaddress
import re
from typing import List


def is_valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def is_valid_domain(value: str) -> bool:
    domain_regex = re.compile(
        r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)" r"(\.[A-Za-z]{2,63})+$"
    )
    return bool(domain_regex.match(value))


def is_valid_target(value: str) -> bool:
    value = value.strip()
    return is_valid_ip(value) or is_valid_domain(value)


def normalize_target(value: str) -> str:
    return value.strip().lower()


def load_targets_from_file(file_path: str) -> List[str]:
    targets = []
    seen = set()
    with open(file_path, "r", encoding="utf-8") as file:
        for line in file:
            cleaned = normalize_target(line)
            if cleaned and cleaned not in seen:
                targets.append(cleaned)
                seen.add(cleaned)
    return targets

import re
from core.rules import WAF_STATE
from core.normalizer import normalize_payload


def analyze_payload(payload: str, path: str = None, method: str = None) -> str | None:
    if not payload:
        return None

    clean_payload = normalize_payload(payload)

    disabled = WAF_STATE.get("DISABLED_RULES", [])
    rules = WAF_STATE.get("RULES", {})

    # =========================
    # 1. GLOBAL RULES
    # =========================
    global_rules = rules.get("global_rules", {})

    for attack_type, pattern in global_rules.items():
        if attack_type in disabled:
            continue

        try:
            if re.search(pattern, clean_payload, re.IGNORECASE):
                return attack_type
        except re.error as e:
            print(f"[!] Regex lỗi ở global rule '{attack_type}': {e}")

    # =========================
    # 2. ROUTE RULES
    # =========================
    if path and method:
        route_rules = rules.get("route_rules", {})
        route_config = route_rules.get(path, {})
        method_rules = route_config.get(method.upper(), {})

        for attack_type, pattern in method_rules.items():
            if attack_type in disabled:
                continue

            try:
                if re.search(pattern, clean_payload, re.IGNORECASE):
                    return attack_type
            except re.error as e:
                print(f"[!] Regex lỗi ở route rule '{attack_type}' ({path} {method}): {e}")

    return None
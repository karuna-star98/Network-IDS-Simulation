"""
Signature / rule-based detection.

A rule match means "this flow looks like a known suspicious pattern - investigate".
It does NOT prove malicious activity (a backup job or a load test can match too).
Thresholds are configurable (stored in the RULES table, editable via the API).
"""

DEFAULT_RULES = [
    {"rule_id": "IDS-001", "rule_name": "High Connection Rate", "severity": "HIGH", "threshold": 25,
     "description": "Connection rate (connections/second) exceeded the configured baseline.", "enabled": 1},
    {"rule_id": "IDS-002", "rule_name": "Repeated Failed Connections", "severity": "HIGH", "threshold": 10,
     "description": "Many failed connection attempts with a high failure ratio.", "enabled": 1},
    {"rule_id": "IDS-003", "rule_name": "Multi-Port Probing-Like Pattern", "severity": "HIGH", "threshold": 20,
     "description": "One source contacted an unusually large number of destination ports.", "enabled": 1},
    {"rule_id": "IDS-004", "rule_name": "SYN-Heavy Behavior", "severity": "HIGH", "threshold": 100,
     "description": "Flow dominated by SYN packets (handshake starts) with little real data.", "enabled": 1},
    {"rule_id": "IDS-005", "rule_name": "Unusual Service-Port Activity", "severity": "MEDIUM", "threshold": 0,
     "description": "Traffic to a port outside the expected service list.", "enabled": 1},
    {"rule_id": "IDS-006", "rule_name": "Abnormally High Traffic Volume", "severity": "MEDIUM", "threshold": 50_000_000,
     "description": "Total bytes in one flow exceeded the configured volume (bytes).", "enabled": 1},
]

UNUSUAL_PORTS = {4444, 6667, 31337, 1337, 12345, 2323, 9001}
SEVERITY_BASE = {"INFO": 10, "LOW": 30, "MEDIUM": 50, "HIGH": 70, "CRITICAL": 90}
SEVERITY_ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


def _check(rule_id, f, flow, t):
    """Return (matched, evidence_text) for one rule."""
    if rule_id == "IDS-001":
        return f["connection_rate"] > t, f"connection_rate={f['connection_rate']:.1f}/s (threshold {t})"
    if rule_id == "IDS-002":
        ok = f["failed_connection_count"] >= t and f["failure_ratio"] >= 0.6
        return ok, f"failed={f['failed_connection_count']}, failure_ratio={f['failure_ratio']:.2f} (threshold {t} & 0.60)"
    if rule_id == "IDS-003":
        return f["unique_destination_ports"] >= t, f"unique_destination_ports={f['unique_destination_ports']} (threshold {t})"
    if rule_id == "IDS-004":
        ok = f["syn_count"] >= t and f["syn_ratio"] >= 0.6
        return ok, f"syn_count={f['syn_count']}, syn_ratio={f['syn_ratio']:.2f} (threshold {t} & 0.60)"
    if rule_id == "IDS-005":
        port = (flow or {}).get("destination_port")
        return port in UNUSUAL_PORTS, f"destination_port={port} is not an expected service port"
    if rule_id == "IDS-006":
        return f["byte_count"] >= t, f"byte_count={f['byte_count']:,} (threshold {int(t):,})"
    return False, ""


def analyze_flow(features, flow=None, rules=None):
    """Run every enabled rule; return a list of matches (highest severity first)."""
    matches = []
    for r in (rules if rules is not None else DEFAULT_RULES):
        if not r.get("enabled", 1):
            continue
        hit, evidence = _check(r["rule_id"], features, flow, r.get("threshold") or 0)
        if hit:
            matches.append({"rule_id": r["rule_id"], "name": r["rule_name"], "severity": r["severity"],
                            "description": r["description"], "evidence": evidence})
    matches.sort(key=lambda m: -SEVERITY_ORDER.index(m["severity"]))
    return matches


def signature_risk(matches):
    """0-100 risk from rule matches: strongest severity + 8 points per extra rule."""
    if not matches:
        return 0.0
    top = max(SEVERITY_BASE[m["severity"]] for m in matches)
    return float(min(100, top + 8 * (len(matches) - 1)))

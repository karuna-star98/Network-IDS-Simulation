"""IDS core: feature extraction, signature rules, anomaly scoring, hybrid risk, alerts, correlation."""
import ipaddress, math, statistics, itertools
from datetime import datetime

VALID_PROTOCOLS = {"TCP", "UDP", "ICMP"}
COMMON_PORTS = {20, 21, 22, 25, 53, 80, 110, 123, 143, 443, 465, 587, 993, 995, 3306, 5432, 8080, 8443}

class ValidationError(ValueError):
    pass

def _num(v, default=0.0):
    try:
        v = float(v)
        return default if math.isnan(v) or math.isinf(v) else v
    except (TypeError, ValueError):
        return default

def extract_network_features(flow):
    """Validate a raw flow dict and return engineered features (safe against /0, NaN, bad IP/port/protocol)."""
    for k in ("source_ip", "destination_ip"):
        try: ipaddress.ip_address(str(flow.get(k)))
        except ValueError: raise ValidationError(f"Invalid {k}")
    for k in ("source_port", "destination_port"):
        p = flow.get(k)
        if not isinstance(p, int) or isinstance(p, bool) or not 0 <= p <= 65535: raise ValidationError(f"Invalid {k}")
    proto = str(flow.get("protocol", "")).upper()
    if proto not in VALID_PROTOCOLS: raise ValidationError("Unsupported protocol")
    if flow.get("packet_count") is None: raise ValidationError("Missing packet_count")
    pk, by = max(_num(flow["packet_count"]), 0), max(_num(flow.get("byte_count")), 0)
    dur = max(_num(flow.get("duration_seconds")), 0.001)  # avoid division by zero
    conn, fail = max(_num(flow.get("connection_count")), 0), max(_num(flow.get("failed_connection_count")), 0)
    syn, rst = max(_num(flow.get("syn_count")), 0), max(_num(flow.get("rst_count")), 0)
    return {"packet_count": pk, "byte_count": by, "duration": dur, "bytes_per_second": by / dur, "packets_per_second": pk / dur,
            "average_packet_size": by / pk if pk else 0.0, "connection_count": conn, "failed_connection_count": fail,
            "failure_ratio": fail / conn if conn else 0.0, "syn_count": syn, "rst_count": rst, "syn_ratio": syn / pk if pk else 0.0,
            "unique_destination_ports": max(_num(flow.get("unique_destination_ports"), 1), 1),
            "unique_destination_ips": max(_num(flow.get("unique_destination_ips"), 1), 1),
            "connection_rate": conn / dur, "destination_port": flow["destination_port"], "protocol": proto}

# ---------- Signature rules (thresholds configurable) ----------
DEFAULT_RULES = [
    {"rule_id": "IDS-001", "name": "High Connection Rate", "severity": "HIGH", "description": "Connection rate exceeded configured baseline.", "feature": "connection_rate", "threshold": 20, "enabled": 1},
    {"rule_id": "IDS-002", "name": "Repeated Failed Connections", "severity": "HIGH", "description": "Many failed connections with a high failure ratio.", "feature": "failed_connection_count", "threshold": 20, "enabled": 1},
    {"rule_id": "IDS-003", "name": "Many Destination Ports", "severity": "HIGH", "description": "One source contacted an unusually large number of ports (probing-like pattern).", "feature": "unique_destination_ports", "threshold": 15, "enabled": 1},
    {"rule_id": "IDS-004", "name": "SYN-Heavy Behavior", "severity": "MEDIUM", "description": "SYN ratio and count unusually high.", "feature": "syn_count", "threshold": 100, "enabled": 1},
    {"rule_id": "IDS-005", "name": "Unusual Service Port", "severity": "MEDIUM", "description": "Activity on an uncommon service port.", "feature": "destination_port", "threshold": 0, "enabled": 1},
    {"rule_id": "IDS-006", "name": "High Traffic Volume", "severity": "CRITICAL", "description": "Abnormally high byte volume in one flow.", "feature": "byte_count", "threshold": 50_000_000, "enabled": 1}]
SEV_POINTS = {"INFO": 20, "LOW": 35, "MEDIUM": 55, "HIGH": 75, "CRITICAL": 95}

def analyze_flow(feat, rules=DEFAULT_RULES):
    """Return list of matched rules. A match = 'investigate', NOT proof of malice."""
    hits = []
    for r in rules:
        if not r.get("enabled", 1): continue
        v, t, rid = feat.get(r["feature"], 0), r["threshold"], r["rule_id"]
        if rid == "IDS-002": m = v >= t and feat["failure_ratio"] >= 0.5
        elif rid == "IDS-004": m = v >= t and feat["syn_ratio"] >= 0.5
        elif rid == "IDS-005": m = feat["destination_port"] not in COMMON_PORTS and feat["destination_port"] < 49152
        else: m = v >= t
        if m: hits.append(r)
    return hits

def rule_risk(hits):
    return min(100, max((SEV_POINTS[h["severity"]] for h in hits), default=0) + 5 * (len(hits) - 1) if hits else 0)

# ---------- Anomaly detection ----------
BASELINE_FEATURES = ["packets_per_second", "bytes_per_second", "connection_rate", "failure_ratio", "unique_destination_ports"]

def build_baseline(feature_rows):
    """Mean/std/IQR per feature computed from NORMAL traffic."""
    base = {}
    for f in BASELINE_FEATURES:
        vals = sorted(r[f] for r in feature_rows)
        q = statistics.quantiles(vals, n=4) if len(vals) >= 2 else [0, 0, 0]
        base[f] = {"mean": statistics.fmean(vals) if vals else 0, "std": statistics.pstdev(vals) if len(vals) > 1 else 1, "q1": q[0], "q3": q[2]}
    return base

def calculate_anomaly_score(feat, baseline):
    """0-100. Uses z-score and IQR fence per feature; the strongest deviation drives the score."""
    if not baseline: return 0.0
    scores = []
    for f in BASELINE_FEATURES:
        b = baseline[f]; z = abs(feat[f] - b["mean"]) / (b["std"] or 1)
        iqr = (b["q3"] - b["q1"]) or 1; out = max(0, feat[f] - b["q3"]) / (1.5 * iqr)
        scores.append(min(100, max(z / 6, out / 6) * 100))  # z=6 or 6 fences out => 100
    return round(min(100, 0.7 * max(scores) + 0.3 * statistics.fmean(scores)), 1)

# ---------- Hybrid risk ----------
def calculate_risk_score(sig, anom, ml=None, weights=None):
    """Weighted blend. With ML: 40/30/30. Without ML: 60/40. Weights configurable."""
    if ml is None:
        w = weights or {"rule": 0.6, "anomaly": 0.4}; s = w["rule"] * sig + w["anomaly"] * anom
    else:
        w = weights or {"rule": 0.4, "anomaly": 0.3, "ml": 0.3}; s = w["rule"] * sig + w["anomaly"] * anom + w["ml"] * ml
    return round(min(100, max(s, 0)), 1)

def classify(score):
    """Thresholds are project assumptions - calibrate in a real SOC."""
    return ("NORMAL" if score <= 20 else "LOW RISK" if score <= 40 else "SUSPICIOUS" if score <= 60
            else "HIGH RISK" if score <= 80 else "CRITICAL INVESTIGATION")

def severity_from_risk(score, hits=()):
    base = "INFO" if score <= 20 else "LOW" if score <= 40 else "MEDIUM" if score <= 60 else "HIGH" if score <= 80 else "CRITICAL"
    order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    top = max((h["severity"] for h in hits), key=order.index, default="INFO")
    return max(base, top, key=order.index) if hits else base

_ids = itertools.count(10001)
def generate_alert(flow, feat, hits, anomaly, risk, ml=None):
    top = hits[0] if hits else None
    reason = "; ".join(h["description"] for h in hits) or f"Statistical deviation from baseline (anomaly {anomaly})."
    return {"alert_id": f"ALT-{next(_ids)}", "timestamp": flow.get("timestamp") or datetime.now().isoformat(timespec="seconds"),
            "source_ip": flow["source_ip"], "destination_ip": flow["destination_ip"], "protocol": feat["protocol"],
            "source_port": flow["source_port"], "destination_port": flow["destination_port"],
            "rule_id": top["rule_id"] if top else "ANOMALY", "alert_type": top["name"] if top else "Statistical Anomaly",
            "severity": severity_from_risk(risk, hits), "risk_score": risk, "description": reason, "status": "NEW"}

def correlate_alerts(alerts, window_seconds=60):
    """Group alerts by (source_ip, alert_type) inside a time window -> incidents."""
    incidents, open_ = [], {}
    for a in sorted(alerts, key=lambda x: x["timestamp"]):
        t = datetime.fromisoformat(a["timestamp"]); key = (a["source_ip"], a["alert_type"]); inc = open_.get(key)
        if inc and (t - inc["last_seen"]).total_seconds() <= window_seconds:
            inc["alert_ids"].append(a["alert_id"]); inc["last_seen"] = t; inc["max_risk"] = max(inc["max_risk"], a["risk_score"])
        else:
            inc = {"source_ip": a["source_ip"], "alert_type": a["alert_type"], "alert_ids": [a["alert_id"]], "first_seen": t, "last_seen": t, "max_risk": a["risk_score"]}
            open_[key] = inc; incidents.append(inc)
    return incidents

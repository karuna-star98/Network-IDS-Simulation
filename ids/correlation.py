"""
Alert correlation.

EVENT    = one observation (a flow record)
ALERT    = a detection that needs attention
INCIDENT = a group of related alerts (same source IP + alert type within a time window)
"""
from datetime import datetime
from ids.rule_engine import SEVERITY_ORDER


def _ts(s):
    return datetime.fromisoformat(s)


def correlate_alerts(alerts, window_seconds=60):
    """Group alerts that share (source_ip, alert_type) and are less than `window_seconds`
    apart from the previous alert in the group. Returns incidents, newest first."""
    groups = {}
    for a in sorted(alerts, key=lambda a: a["created_at"]):
        groups.setdefault((a["source_ip"], a["alert_type"]), []).append(a)
    incidents = []
    for (src, atype), items in groups.items():
        current = []
        for a in items:
            if current and (_ts(a["created_at"]) - _ts(current[-1]["created_at"])).total_seconds() > window_seconds:
                incidents.append(_build(src, atype, current))
                current = []
            current.append(a)
        if current:
            incidents.append(_build(src, atype, current))
    incidents.sort(key=lambda i: i["last_seen"], reverse=True)
    for n, inc in enumerate(reversed(incidents), 1):
        inc["incident_id"] = f"INC-{n:04d}"
    return incidents


def _build(src, atype, items):
    return {
        "source_ip": src, "alert_type": atype, "alert_count": len(items),
        "first_seen": items[0]["created_at"], "last_seen": items[-1]["created_at"],
        "max_risk": max(a["risk_score"] for a in items),
        "max_severity": max((a["severity"] for a in items), key=SEVERITY_ORDER.index),
        "alert_ids": [a["alert_id"] for a in items],
        "open": any(a["status"] in ("NEW", "INVESTIGATING") for a in items),
    }

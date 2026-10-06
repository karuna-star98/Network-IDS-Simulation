"""Alert generation. One alert per flow that needs analyst attention."""
from ids import config
from ids.risk_engine import severity_from_risk
from ids.rule_engine import SEVERITY_ORDER

STATUSES = ["NEW", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"]

RECOMMENDATIONS = {
    "IDS-001": ["Check whether the source is a known scanner, load test, or monitoring tool.",
                "Compare the connection rate with this source's historical baseline.",
                "Review firewall/proxy records for the same source around this time."],
    "IDS-002": ["Review authentication logs on the destination for repeated failures.",
                "Check whether the account/service is expected to be used from this source.",
                "Consider whether a misconfigured client or expired credential explains the failures."],
    "IDS-003": ["Look for other flows from this source touching additional ports/hosts.",
                "Confirm whether an authorized vulnerability scan was scheduled.",
                "Review firewall logs for denied connections from this source."],
    "IDS-004": ["Check destination service health (half-open connection backlog).",
                "Review firewall records for the same source and time window.",
                "Determine whether a network device or client is retrying aggressively."],
    "IDS-005": ["Identify which application/service uses this port and whether it is approved.",
                "Check endpoint telemetry on the internal host where authorized.",
                "Compare with the asset inventory and change records."],
    "IDS-006": ["Ask the system owner whether a backup/migration/update explains the volume.",
                "Check the destination - internal, known partner, or unfamiliar?",
                "Compare with the historical transfer pattern for this host."],
    "IDS-ANOM": ["Compare the flow against the historical baseline for the source and destination.",
                 "Look for related activity in other logs before drawing conclusions.",
                 "Determine whether the activity is expected (maintenance, release, campaign)."],
}
GENERAL_STEPS = ["Determine whether the activity is expected before escalating.",
                 "Document findings and set the status (INVESTIGATING / RESOLVED / FALSE_POSITIVE)."]


def should_alert(risk_score, matches):
    return bool(matches) or risk_score >= config.ALERT_RISK_THRESHOLD


def recommended_steps(rule_id):
    return RECOMMENDATIONS.get(rule_id, RECOMMENDATIONS["IDS-ANOM"]) + GENERAL_STEPS


def generate_alert(flow, matches, risk, sequence, created_at=None):
    """Build an alert dict. `flow` is the clean flow, `risk` the dict from calculate_risk_score."""
    if matches:
        primary = matches[0]
        rule_id, alert_type = primary["rule_id"], primary["name"]
        reason = "; ".join(m["evidence"] for m in matches)
    else:
        rule_id, alert_type = "IDS-ANOM", "Statistical / ML Anomaly"
        c = risk["components"]
        reason = (f"No signature matched, but anomaly score {c['anomaly_score']:.0f} / "
                  f"ML probability {c['ml_probability'] if c['ml_probability'] is not None else 'n/a'} "
                  f"indicate unusual behavior.")
    severity = severity_from_risk(risk["risk_level"])
    if matches and SEVERITY_ORDER.index(primary["severity"]) > SEVERITY_ORDER.index(severity):
        severity = primary["severity"]       # a rule severity is never downgraded by the blended score
    return {
        "alert_id": f"ALT-{sequence}",
        "flow_id": flow["flow_id"],
        "created_at": created_at or flow.get("timestamp"),
        "source_ip": flow["source_ip"], "destination_ip": flow["destination_ip"],
        "protocol": flow["protocol"], "source_port": flow["source_port"],
        "destination_port": flow["destination_port"],
        "rule_id": rule_id, "alert_type": alert_type, "severity": severity,
        "risk_score": risk["risk_score"],
        "description": f"{alert_type}: {reason}",
        "status": "NEW",
        "detail": {"matched_rules": matches, **risk["components"], "risk_level": risk["risk_level"]},
    }

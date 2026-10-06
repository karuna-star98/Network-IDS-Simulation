"""Plain-text (Markdown) incident report for one alert."""
from ids.alert_engine import recommended_steps


def build_report(alert, flow, notes, timeline):
    d = alert["detail"]
    lines = [
        f"# Incident Report - {alert['alert_id']}", "",
        f"**Type:** {alert['alert_type']}  |  **Severity:** {alert['severity']}  |  **Risk:** {alert['risk_score']}/100  |  **Status:** {alert['status']}",
        "", "## Summary", alert["description"], "",
        "## Network Details",
        f"- Time (UTC): {alert['created_at']}",
        f"- Source: {alert['source_ip']}:{alert['source_port']}",
        f"- Destination: {alert['destination_ip']}:{alert['destination_port']} ({alert['protocol']})",
        f"- Packets: {flow['packet_count']:,}, Bytes: {flow['byte_count']:,}, Duration: {flow['duration']}s",
        f"- Connections: {flow['connection_count']} (failed: {flow['failed_connection_count']}), SYN: {flow['syn_count']}, RST: {flow['rst_count']}",
        "", "## Detection Evidence",
        f"- Signature risk: {d.get('signature_risk')}  |  Anomaly score: {d.get('anomaly_score')}  |  ML probability: {d.get('ml_probability')}",
    ]
    lines += [f"- Rule {m['rule_id']} ({m['name']}): {m['evidence']}" for m in d.get("matched_rules", [])]
    lines += ["", "## Recommended Investigation Steps"] + [f"{i}. {s}" for i, s in enumerate(recommended_steps(alert["rule_id"]), 1)]
    lines += ["", "## Timeline"] + [f"- {e['created_at']} [{e['event_type']}] {e['detail']}" for e in timeline]
    lines += ["", "## Analyst Notes"] + ([f"- {n['created_at']} ({n['author']}): {n['note']}" for n in notes] or ["- (none)"])
    lines += ["", "> A detection is a lead for investigation, not proof of malicious activity.", ""]
    return "\n".join(lines)

"""Flask backend: ingest flows -> IDS pipeline -> SQLite -> REST API + SOC dashboard (polling)."""
import os, sqlite3, json, pandas as pd
from datetime import datetime
from flask import Flask, jsonify, request, g, send_from_directory
from ids.core import (extract_network_features, analyze_flow, rule_risk, build_baseline, calculate_anomaly_score,
                      calculate_risk_score, classify, generate_alert, correlate_alerts, DEFAULT_RULES, ValidationError)
from ml.predict import ml_score

STATUSES = {"NEW", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"}
SCHEMA = """
CREATE TABLE IF NOT EXISTS network_flows(flow_id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, source_ip TEXT, destination_ip TEXT,
  source_port INT, destination_port INT, protocol TEXT, packet_count REAL, byte_count REAL, duration REAL, risk_score REAL, classification TEXT,
  anomaly_score REAL, ml_score REAL, features TEXT);
CREATE TABLE IF NOT EXISTS alerts(alert_id TEXT PRIMARY KEY, flow_id INT REFERENCES network_flows(flow_id), rule_id TEXT, alert_type TEXT, severity TEXT,
  source_ip TEXT, destination_ip TEXT, protocol TEXT, description TEXT, risk_score REAL, status TEXT, created_at TEXT, updated_at TEXT);
CREATE TABLE IF NOT EXISTS rules(rule_id TEXT PRIMARY KEY, rule_name TEXT, description TEXT, severity TEXT, feature TEXT, threshold REAL, enabled INT);
CREATE TABLE IF NOT EXISTS incident_notes(note_id INTEGER PRIMARY KEY AUTOINCREMENT, alert_id TEXT REFERENCES alerts(alert_id), note TEXT, created_at TEXT);
CREATE INDEX IF NOT EXISTS idx_alert_status ON alerts(status); CREATE INDEX IF NOT EXISTS idx_alert_src ON alerts(source_ip);
CREATE INDEX IF NOT EXISTS idx_flow_ts ON network_flows(timestamp);"""

def create_app(db_path=None, csv="data/network_traffic.csv"):
    app = Flask(__name__, static_folder=os.path.join(os.path.dirname(__file__), "static"))
    app.config["DB"] = db_path or os.environ.get("IDS_DB", "ids.db")
    with sqlite3.connect(app.config["DB"]) as c:
        c.executescript(SCHEMA)
        if not c.execute("SELECT 1 FROM rules").fetchone():
            c.executemany("INSERT INTO rules VALUES(?,?,?,?,?,?,?)", [(r["rule_id"], r["name"], r["description"], r["severity"], r["feature"], r["threshold"], r["enabled"]) for r in DEFAULT_RULES])
    # Baseline learned from NORMAL synthetic traffic
    if not os.path.exists(csv):
        from simulator.generate_dataset import generate; os.makedirs(os.path.dirname(csv) or ".", exist_ok=True); generate().to_csv(csv, index=False)
    normal = pd.read_csv(csv).query("label == 'NORMAL'").head(2000)
    app.config["BASELINE"] = build_baseline([extract_network_features(r) for r in normal.to_dict("records")])

    def db():
        if "db" not in g: g.db = sqlite3.connect(app.config["DB"]); g.db.row_factory = sqlite3.Row
        return g.db
    @app.teardown_appcontext
    def close(_):
        d = g.pop("db", None)
        if d: d.close()
    def rules():
        return [{"rule_id": r["rule_id"], "name": r["rule_name"], "description": r["description"], "severity": r["severity"], "feature": r["feature"], "threshold": r["threshold"], "enabled": r["enabled"]} for r in db().execute("SELECT * FROM rules")]
    def err(msg, code=400): return jsonify({"error": msg}), code

    @app.get("/")
    def index(): return send_from_directory(app.static_folder, "dashboard.html")

    @app.post("/api/flows")
    def post_flow():
        flow = request.get_json(silent=True)
        if not isinstance(flow, dict): return err("JSON body required")
        try: feat = extract_network_features(flow)
        except ValidationError as e: return err(str(e), 422)
        hits = analyze_flow(feat, rules()); sig = rule_risk(hits)
        anom = calculate_anomaly_score(feat, app.config["BASELINE"]); ml = ml_score(feat)
        risk = calculate_risk_score(sig, anom, ml); cls = classify(risk)
        ts = flow.get("timestamp") or datetime.now().isoformat(timespec="seconds")
        cur = db().execute("INSERT INTO network_flows(timestamp,source_ip,destination_ip,source_port,destination_port,protocol,packet_count,byte_count,duration,risk_score,classification,anomaly_score,ml_score,features) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                           (ts, flow["source_ip"], flow["destination_ip"], flow["source_port"], flow["destination_port"], feat["protocol"], feat["packet_count"], feat["byte_count"], feat["duration"], risk, cls, anom, ml, json.dumps(feat)))
        fid = cur.lastrowid; alert = None
        if hits or risk > 40:  # alert on any rule hit or notable risk
            flow["timestamp"] = ts; alert = generate_alert(flow, feat, hits, anom, risk, ml)
            alert["alert_id"] = f"ALT-{10000 + fid}"  # unique + stable across restarts
            now = datetime.now().isoformat(timespec="seconds")
            db().execute("INSERT INTO alerts VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)", (alert["alert_id"], fid, alert["rule_id"], alert["alert_type"], alert["severity"], alert["source_ip"], alert["destination_ip"], alert["protocol"], alert["description"], risk, "NEW", now, now))
        db().commit()
        return jsonify({"flow_id": fid, "classification": cls, "risk_score": risk, "anomaly_score": anom, "ml_score": ml, "alert": alert}), 201

    @app.get("/api/flows")
    def list_flows():
        lim = min(int(request.args.get("limit", 100)), 1000)
        return jsonify([dict(r) for r in db().execute("SELECT flow_id,timestamp,source_ip,destination_ip,protocol,destination_port,risk_score,classification FROM network_flows ORDER BY flow_id DESC LIMIT ?", (lim,))])

    @app.get("/api/flows/<int:fid>")
    def get_flow(fid):
        r = db().execute("SELECT * FROM network_flows WHERE flow_id=?", (fid,)).fetchone()
        return jsonify(dict(r)) if r else err("Flow not found", 404)

    @app.get("/api/alerts")
    def list_alerts():
        q, p = "SELECT * FROM alerts WHERE 1=1", []
        for k in ("severity", "status", "protocol", "alert_type"):
            if request.args.get(k): q += f" AND {k}=?"; p.append(request.args[k])
        return jsonify([dict(r) for r in db().execute(q + " ORDER BY created_at DESC, alert_id DESC LIMIT 200", p)])

    @app.get("/api/alerts/<aid>")
    def get_alert(aid):
        a = db().execute("SELECT * FROM alerts WHERE alert_id=?", (aid,)).fetchone()
        if not a: return err("Alert not found", 404)
        f = db().execute("SELECT * FROM network_flows WHERE flow_id=?", (a["flow_id"],)).fetchone()
        notes = [dict(n) for n in db().execute("SELECT note,created_at FROM incident_notes WHERE alert_id=? ORDER BY note_id", (aid,))]
        steps = ["Review related logs for this source IP", "Check whether the source is a known/authorized host", "Compare with the historical baseline",
                 "Check authentication logs and firewall records", "Review endpoint telemetry where authorized", "Decide whether the activity is expected (backup, scan by IT, etc.)"]
        return jsonify({"alert": dict(a), "flow": dict(f) if f else None, "notes": notes, "recommended_steps": steps})

    @app.put("/api/alerts/<aid>/status")
    def set_status(aid):
        s = (request.get_json(silent=True) or {}).get("status")
        if s not in STATUSES: return err(f"status must be one of {sorted(STATUSES)}", 422)
        cur = db().execute("UPDATE alerts SET status=?, updated_at=? WHERE alert_id=?", (s, datetime.now().isoformat(timespec="seconds"), aid)); db().commit()
        return jsonify({"alert_id": aid, "status": s}) if cur.rowcount else err("Alert not found", 404)

    @app.post("/api/alerts/<aid>/notes")
    def add_note(aid):
        n = str((request.get_json(silent=True) or {}).get("note", "")).strip()
        if not n or len(n) > 2000: return err("note must be 1-2000 characters", 422)
        if not db().execute("SELECT 1 FROM alerts WHERE alert_id=?", (aid,)).fetchone(): return err("Alert not found", 404)
        db().execute("INSERT INTO incident_notes(alert_id,note,created_at) VALUES(?,?,?)", (aid, n, datetime.now().isoformat(timespec="seconds"))); db().commit()
        return jsonify({"alert_id": aid, "note": n}), 201

    @app.get("/api/dashboard/stats")
    def stats():
        d = db(); one = lambda q: d.execute(q).fetchone()[0] or 0
        return jsonify({"total_flows": one("SELECT COUNT(*) FROM network_flows"), "normal": one("SELECT COUNT(*) FROM network_flows WHERE classification='NORMAL'"),
                        "suspicious": one("SELECT COUNT(*) FROM network_flows WHERE classification!='NORMAL'"),
                        "open_alerts": one("SELECT COUNT(*) FROM alerts WHERE status IN ('NEW','INVESTIGATING')"),
                        "critical_alerts": one("SELECT COUNT(*) FROM alerts WHERE severity='CRITICAL'"),
                        "avg_risk": round(one("SELECT AVG(risk_score) FROM network_flows"), 1), "incidents": len(correlate_alerts([dict(r) | {"timestamp": r["created_at"]} for r in d.execute("SELECT * FROM alerts")]))})

    @app.get("/api/dashboard/traffic")
    def traffic():
        d = db(); grp = lambda c: {r[0]: r[1] for r in d.execute(f"SELECT {c}, COUNT(*) FROM network_flows GROUP BY 1")}
        return jsonify({"protocols": grp("protocol"), "ports": {str(r[0]): r[1] for r in d.execute("SELECT destination_port, COUNT(*) c FROM network_flows GROUP BY 1 ORDER BY c DESC LIMIT 8")},
                        "recent_risk": [r[0] for r in d.execute("SELECT risk_score FROM network_flows ORDER BY flow_id DESC LIMIT 60")][::-1]})

    @app.get("/api/dashboard/alerts")
    def alert_stats():
        d = db(); grp = lambda c, extra="": {r[0]: r[1] for r in d.execute(f"SELECT {c}, COUNT(*) n FROM alerts GROUP BY 1 {extra}")}
        return jsonify({"by_severity": grp("severity"), "by_type": grp("alert_type", "ORDER BY n DESC LIMIT 6"), "top_sources": grp("source_ip", "ORDER BY n DESC LIMIT 5")})

    @app.get("/api/rules")
    def get_rules(): return jsonify(rules())

    @app.put("/api/rules/<rid>")
    def put_rule(rid):
        b = request.get_json(silent=True) or {}
        try: th = float(b["threshold"]) if "threshold" in b else None
        except (TypeError, ValueError): return err("threshold must be numeric", 422)
        if "enabled" in b: db().execute("UPDATE rules SET enabled=? WHERE rule_id=?", (int(bool(b["enabled"])), rid))
        if th is not None: db().execute("UPDATE rules SET threshold=? WHERE rule_id=?", (th, rid))
        db().commit()
        r = [x for x in rules() if x["rule_id"] == rid]
        return jsonify(r[0]) if r else err("Rule not found", 404)
    return app

if __name__ == "__main__":
    create_app().run(host="127.0.0.1", port=5000, debug=False)  # bound to localhost on purpose

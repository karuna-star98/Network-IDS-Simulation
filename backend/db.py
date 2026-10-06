"""SQLite storage layer (parameterised queries only - no string-built SQL with user input)."""
import json
import os
import sqlite3
import threading
from datetime import datetime, timezone

from ids.rule_engine import DEFAULT_RULES

SCHEMA = """
CREATE TABLE IF NOT EXISTS network_flows (
  flow_id TEXT PRIMARY KEY, timestamp TEXT NOT NULL,
  source_ip TEXT NOT NULL, destination_ip TEXT NOT NULL,
  source_port INTEGER, destination_port INTEGER, protocol TEXT NOT NULL,
  packet_count INTEGER, byte_count INTEGER, duration REAL,
  connection_count INTEGER, failed_connection_count INTEGER, syn_count INTEGER, rst_count INTEGER,
  signature_risk REAL, anomaly_score REAL, ml_probability REAL,
  risk_score REAL, risk_level TEXT, classification TEXT, scenario_type TEXT, label TEXT);
CREATE TABLE IF NOT EXISTS alerts (
  alert_id TEXT PRIMARY KEY, flow_id TEXT NOT NULL REFERENCES network_flows(flow_id),
  rule_id TEXT, alert_type TEXT, severity TEXT, description TEXT, risk_score REAL,
  status TEXT NOT NULL DEFAULT 'NEW', created_at TEXT NOT NULL, updated_at TEXT, detail_json TEXT);
CREATE TABLE IF NOT EXISTS rules (
  rule_id TEXT PRIMARY KEY, rule_name TEXT, description TEXT, severity TEXT,
  threshold REAL, enabled INTEGER NOT NULL DEFAULT 1);
CREATE TABLE IF NOT EXISTS incident_notes (
  note_id INTEGER PRIMARY KEY AUTOINCREMENT, alert_id TEXT NOT NULL REFERENCES alerts(alert_id),
  note TEXT NOT NULL, author TEXT, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS alert_events (          -- incident timeline / audit trail
  event_id INTEGER PRIMARY KEY AUTOINCREMENT, alert_id TEXT NOT NULL REFERENCES alerts(alert_id),
  event_type TEXT NOT NULL, detail TEXT, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS model_results (
  result_id INTEGER PRIMARY KEY AUTOINCREMENT, flow_id TEXT NOT NULL REFERENCES network_flows(flow_id),
  model_name TEXT, prediction INTEGER, score REAL);
CREATE INDEX IF NOT EXISTS idx_flows_ts ON network_flows(timestamp);
CREATE INDEX IF NOT EXISTS idx_flows_src ON network_flows(source_ip);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_sev ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_flow ON alerts(flow_id);
CREATE INDEX IF NOT EXISTS idx_alerts_created ON alerts(created_at);
CREATE INDEX IF NOT EXISTS idx_notes_alert ON incident_notes(alert_id);
CREATE INDEX IF NOT EXISTS idx_events_alert ON alert_events(alert_id);
CREATE INDEX IF NOT EXISTS idx_model_flow ON model_results(flow_id);
"""


def now_iso():
    return datetime.now(timezone.utc).replace(tzinfo=None).isoformat(timespec="seconds")


class Database:
    def __init__(self, path):
        if path != ":memory:":
            os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.lock = threading.RLock()
        with self.lock:
            self.conn.executescript(SCHEMA)
            if not self.conn.execute("SELECT 1 FROM rules LIMIT 1").fetchone():
                self.conn.executemany(
                    "INSERT INTO rules VALUES (:rule_id,:rule_name,:description,:severity,:threshold,:enabled)",
                    DEFAULT_RULES)
            self.conn.commit()

    # -- generic helpers ---------------------------------------------------
    def query(self, sql, params=()):
        with self.lock:
            return [dict(r) for r in self.conn.execute(sql, params).fetchall()]

    def one(self, sql, params=()):
        rows = self.query(sql, params)
        return rows[0] if rows else None

    def execute(self, sql, params=()):
        with self.lock:
            cur = self.conn.execute(sql, params)
            self.conn.commit()
            return cur

    # -- flows -------------------------------------------------------------
    def flow_exists(self, flow_id):
        return self.one("SELECT 1 AS x FROM network_flows WHERE flow_id=?", (flow_id,)) is not None

    def next_alert_number(self):
        row = self.one("SELECT MAX(CAST(SUBSTR(alert_id,5) AS INTEGER)) AS m FROM alerts")
        return (row["m"] or 10000) + 1

    def store_result(self, flow, scores, ml_results, alert):
        """Store flow (+ model results + alert) atomically. Returns False if the flow_id already exists."""
        with self.lock:
            try:
                self.conn.execute(
                    "INSERT INTO network_flows VALUES (:flow_id,:timestamp,:source_ip,:destination_ip,:source_port,"
                    ":destination_port,:protocol,:packet_count,:byte_count,:duration_seconds,:connection_count,"
                    ":failed_connection_count,:syn_count,:rst_count,:signature_risk,:anomaly_score,:ml_probability,"
                    ":risk_score,:risk_level,:classification,:scenario_type,:label)",
                    {**{k: flow.get(k) for k in ("scenario_type", "label")}, **flow, **scores})
                for name, r in (ml_results or {}).items():
                    self.conn.execute("INSERT INTO model_results(flow_id,model_name,prediction,score) VALUES (?,?,?,?)",
                                      (flow["flow_id"], name, r["prediction"], r["score"]))
                if alert:
                    self.conn.execute(
                        "INSERT INTO alerts VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                        (alert["alert_id"], alert["flow_id"], alert["rule_id"], alert["alert_type"], alert["severity"],
                         alert["description"], alert["risk_score"], "NEW", alert["created_at"], alert["created_at"],
                         json.dumps(alert["detail"])))
                    self.conn.execute("INSERT INTO alert_events(alert_id,event_type,detail,created_at) VALUES (?,?,?,?)",
                                      (alert["alert_id"], "CREATED", f"Alert created with severity {alert['severity']}",
                                       alert["created_at"]))
                self.conn.commit()
                return True
            except sqlite3.IntegrityError:
                self.conn.rollback()
                return False

    # -- rules / alerts ------------------------------------------------------
    def get_rules(self):
        return self.query("SELECT * FROM rules ORDER BY rule_id")

    def update_rule(self, rule_id, threshold=None, enabled=None):
        if not self.one("SELECT 1 AS x FROM rules WHERE rule_id=?", (rule_id,)):
            return None
        if threshold is not None:
            self.execute("UPDATE rules SET threshold=? WHERE rule_id=?", (threshold, rule_id))
        if enabled is not None:
            self.execute("UPDATE rules SET enabled=? WHERE rule_id=?", (1 if enabled else 0, rule_id))
        return self.one("SELECT * FROM rules WHERE rule_id=?", (rule_id,))

    def get_alert(self, alert_id):
        a = self.one("SELECT a.*, f.source_ip, f.destination_ip, f.protocol, f.source_port, f.destination_port "
                     "FROM alerts a JOIN network_flows f ON f.flow_id=a.flow_id WHERE a.alert_id=?", (alert_id,))
        if a:
            a["detail"] = json.loads(a.pop("detail_json") or "{}")
        return a

    def set_status(self, alert_id, status, note=None):
        old = self.one("SELECT status FROM alerts WHERE alert_id=?", (alert_id,))
        if not old:
            return None
        ts = now_iso()
        self.execute("UPDATE alerts SET status=?, updated_at=? WHERE alert_id=?", (status, ts, alert_id))
        self.execute("INSERT INTO alert_events(alert_id,event_type,detail,created_at) VALUES (?,?,?,?)",
                     (alert_id, "STATUS_CHANGE", f"{old['status']} -> {status}" + (f": {note}" if note else ""), ts))
        return old["status"]

    def add_note(self, alert_id, note, author):
        ts = now_iso()
        cur = self.execute("INSERT INTO incident_notes(alert_id,note,author,created_at) VALUES (?,?,?,?)",
                           (alert_id, note, author, ts))
        self.execute("INSERT INTO alert_events(alert_id,event_type,detail,created_at) VALUES (?,?,?,?)",
                     (alert_id, "NOTE_ADDED", f"{author}: {note[:80]}", ts))
        return {"note_id": cur.lastrowid, "alert_id": alert_id, "note": note, "author": author, "created_at": ts}

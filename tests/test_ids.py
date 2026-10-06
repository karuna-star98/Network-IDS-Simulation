import os, tempfile, unittest, pandas as pd
from ids.core import *
from simulator.generate_dataset import generate, make_flow
from backend.app import create_app

def flow(**kw):
    f = dict(source_ip="192.0.2.15", destination_ip="198.51.100.20", source_port=50000, destination_port=443, protocol="TCP",
             packet_count=18, byte_count=12400, duration_seconds=2.8, connection_count=3, failed_connection_count=0, syn_count=2, rst_count=0)
    f.update(kw); return f

class Core(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        df = generate(1500); cls.base = build_baseline([extract_network_features(r) for r in df[df.label == "NORMAL"].to_dict("records")])
    def score(self, f):
        ft = extract_network_features(f); h = analyze_flow(ft); an = calculate_anomaly_score(ft, self.base)
        return h, an, calculate_risk_score(rule_risk(h), an)
    def test_normal_https(self): h, _, r = self.score(flow()); self.assertEqual(h, []); self.assertEqual(classify(r), "NORMAL")
    def test_normal_udp_dns(self): h, _, r = self.score(flow(protocol="UDP", destination_port=53, packet_count=2, byte_count=180, duration_seconds=0.5, connection_count=1, syn_count=0)); self.assertEqual(h, [])
    def test_high_connection_rate(self): h, *_ = self.score(flow(connection_count=300, duration_seconds=2)); self.assertIn("IDS-001", [x["rule_id"] for x in h])
    def test_failed_connections(self): h, *_ = self.score(flow(connection_count=60, failed_connection_count=58)); self.assertIn("IDS-002", [x["rule_id"] for x in h])
    def test_multi_port(self): h, *_ = self.score(flow(unique_destination_ports=80)); self.assertIn("IDS-003", [x["rule_id"] for x in h])
    def test_syn_heavy(self): h, *_ = self.score(flow(syn_count=500, packet_count=600)); self.assertIn("IDS-004", [x["rule_id"] for x in h])
    def test_unusual_port(self): h, *_ = self.score(flow(destination_port=31337)); self.assertIn("IDS-005", [x["rule_id"] for x in h])
    def test_high_volume(self): h, *_ = self.score(flow(byte_count=200_000_000)); self.assertIn("IDS-006", [x["rule_id"] for x in h])
    def test_invalid_ips(self):
        for k in ("source_ip", "destination_ip"):
            with self.assertRaises(ValidationError): extract_network_features(flow(**{k: "999.1.1.1"}))
    def test_invalid_ports(self):
        for k in ("source_port", "destination_port"):
            for v in (-1, 70000, "80"):
                with self.assertRaises(ValidationError): extract_network_features(flow(**{k: v}))
    def test_bad_protocol(self):
        with self.assertRaises(ValidationError): extract_network_features(flow(protocol="XYZ"))
    def test_missing_packets(self):
        f = flow(); del f["packet_count"]
        with self.assertRaises(ValidationError): extract_network_features(f)
    def test_zero_duration(self): ft = extract_network_features(flow(duration_seconds=0)); self.assertTrue(ft["packets_per_second"] < 1e7)
    def test_zero_packets_and_conn(self): ft = extract_network_features(flow(packet_count=0, connection_count=0)); self.assertEqual(ft["failure_ratio"], 0)
    def test_features(self): ft = extract_network_features(flow()); self.assertAlmostEqual(ft["packets_per_second"], 18 / 2.8)
    def test_anomaly_range(self): _, an, _ = self.score(flow(byte_count=9e9, packet_count=9e6)); self.assertTrue(0 <= an <= 100); self.assertGreater(an, 50)
    def test_risk_weights(self): self.assertEqual(calculate_risk_score(70, 60, 78), round(.4 * 70 + .3 * 60 + .3 * 78, 1)); self.assertEqual(calculate_risk_score(70, 60), 66.0)
    def test_classify(self): self.assertEqual([classify(x) for x in (10, 30, 50, 70, 90)], ["NORMAL", "LOW RISK", "SUSPICIOUS", "HIGH RISK", "CRITICAL INVESTIGATION"])
    def test_alert_and_correlation(self):
        ft = extract_network_features(flow(connection_count=300, duration_seconds=2)); h = analyze_flow(ft)
        al = [generate_alert(dict(flow(), timestamp=f"2026-01-01T10:00:{s:02d}"), ft, h, 70, 80) for s in (1, 20, 40)]
        self.assertEqual(al[0]["status"], "NEW"); inc = correlate_alerts(al); self.assertEqual(len(inc), 1); self.assertEqual(len(inc[0]["alert_ids"]), 3)
        far = dict(al[0], timestamp="2026-01-01T12:00:00", alert_id="ALT-X"); self.assertEqual(len(correlate_alerts(al + [far])), 2)
    def test_dataset(self): df = generate(5000); self.assertEqual(len(df), 5000); self.assertEqual(set(df.label), {"NORMAL", "SUSPICIOUS"})
    def test_empty_baseline(self): self.assertEqual(calculate_anomaly_score(extract_network_features(flow()), {}), 0.0)

class Api(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(); self.c = create_app(os.path.join(self.d, "t.db")).test_client()
    def test_normal_flow_no_alert(self): r = self.c.post("/api/flows", json=flow()); self.assertEqual(r.status_code, 201); self.assertIsNone(r.json["alert"]); self.assertEqual(r.json["classification"], "NORMAL")
    def test_suspicious_alert_workflow(self):
        r = self.c.post("/api/flows", json=flow(unique_destination_ports=90, connection_count=100, failed_connection_count=80, syn_count=90)).json; aid = r["alert"]["alert_id"]
        self.assertNotEqual(r["classification"], "NORMAL")
        self.assertEqual(self.c.put(f"/api/alerts/{aid}/status", json={"status": "INVESTIGATING"}).status_code, 200)
        self.assertEqual(self.c.post(f"/api/alerts/{aid}/notes", json={"note": "Checking firewall logs"}).status_code, 201)
        self.assertEqual(self.c.put(f"/api/alerts/{aid}/status", json={"status": "FALSE_POSITIVE"}).status_code, 200)
        d = self.c.get(f"/api/alerts/{aid}").json; self.assertEqual(d["alert"]["status"], "FALSE_POSITIVE"); self.assertEqual(len(d["notes"]), 1)
    def test_validation(self):
        self.assertEqual(self.c.post("/api/flows", json=flow(destination_port=99999)).status_code, 422)
        self.assertEqual(self.c.post("/api/flows", data="x").status_code, 400)
        self.assertEqual(self.c.put("/api/alerts/ALT-0/status", json={"status": "BAD"}).status_code, 422)
        self.assertEqual(self.c.get("/api/alerts/NOPE").status_code, 404)
        self.assertEqual(self.c.get("/api/flows/999").status_code, 404)
    def test_empty_stats(self): s = self.c.get("/api/dashboard/stats").json; self.assertEqual((s["total_flows"], s["avg_risk"]), (0, 0))
    def test_stats_after_flows(self): [self.c.post("/api/flows", json=flow()) for _ in range(3)]; self.assertEqual(self.c.get("/api/dashboard/stats").json["total_flows"], 3)
    def test_rules_update(self): r = self.c.put("/api/rules/IDS-001", json={"threshold": 5, "enabled": False}).json; self.assertEqual((r["threshold"], r["enabled"]), (5, 0)); self.assertEqual(len(self.c.get("/api/rules").json), 6)
    def test_ml_prediction(self):
        from ml.predict import ml_score
        s = ml_score(extract_network_features(flow(byte_count=2e8, packet_count=2e5, duration_seconds=10)))
        self.assertTrue(s is None or 0 <= s <= 100)

if __name__ == "__main__":
    unittest.main()

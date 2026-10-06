"""
IDSPipeline: ties every stage together.

 raw flow -> validate -> features -> rules + anomaly + ML -> risk -> alert -> database
"""
import uuid

from ids import config
from ids.alert_engine import generate_alert, should_alert
from ids.anomaly_detector import AnomalyDetector
from ids.feature_extractor import FlowValidationError, extract_network_features, sanitize_flow
from ids.risk_engine import calculate_risk_score, verdict
from ids.rule_engine import analyze_flow, signature_risk


class IDSPipeline:
    def __init__(self, db, detector, predictor=None, ml_enabled=True, weights=None):
        self.db, self.detector, self.predictor = db, detector, predictor
        self.ml_enabled = ml_enabled and predictor is not None and predictor.available
        self.weights = weights
        self.reload_rules()

    def reload_rules(self):
        self.rules = self.db.get_rules()

    def process_flow(self, raw):
        return self.process_batch([raw])[0]

    def process_batch(self, raws):
        """Process many flows (ML is run once for the whole batch - much faster).
        Each result is a dict with status: 'processed' | 'duplicate' | 'invalid'."""
        prepared, results = [], [None] * len(raws)
        for i, raw in enumerate(raws):
            try:
                flow, warnings = sanitize_flow(raw)
                flow.setdefault("flow_id", f"FLW-{uuid.uuid4().hex[:10]}")
                flow.setdefault("timestamp", _now())
                if self.db.flow_exists(flow["flow_id"]):
                    results[i] = {"status": "duplicate", "flow_id": flow["flow_id"]}
                    continue
                prepared.append((i, flow, warnings, extract_network_features(flow)))
            except FlowValidationError as e:
                results[i] = {"status": "invalid", "errors": e.errors}
        ml_out = self.predictor.predict_many([p[3] for p in prepared]) if self.ml_enabled else [None] * len(prepared)

        for (i, flow, warnings, feats), ml in zip(prepared, ml_out):
            matches = analyze_flow(feats, flow, self.rules)
            s_risk = signature_risk(matches)
            anomaly, anomaly_detail = self.detector.calculate_anomaly_score(feats)
            ml_p = self.predictor.primary_probability(ml) if ml else None
            risk = calculate_risk_score(s_risk, anomaly, ml_p, self.weights)
            cls = verdict(risk["risk_level"], bool(matches))
            alert = None
            if should_alert(risk["risk_score"], matches):
                alert = generate_alert(flow, matches, risk, self.db.next_alert_number())
            scores = {"signature_risk": s_risk, "anomaly_score": anomaly, "ml_probability": ml_p,
                      "risk_score": risk["risk_score"], "risk_level": risk["risk_level"], "classification": cls}
            if not self.db.store_result(flow, scores, ml, alert):
                results[i] = {"status": "duplicate", "flow_id": flow["flow_id"]}
                continue
            if cls == "NORMAL":
                self.detector.update_baseline(feats)     # only normal-looking flows adapt the baseline
            results[i] = {"status": "processed", "flow_id": flow["flow_id"], "classification": cls,
                          "risk_score": risk["risk_score"], "risk_level": risk["risk_level"],
                          "signature_risk": s_risk, "anomaly_score": anomaly, "ml_probability": ml_p,
                          "matched_rules": matches, "alert": alert, "warnings": warnings,
                          "features": feats, "anomaly_detail": anomaly_detail}
        return results


def _now():
    from backend.db import now_iso
    return now_iso()


def build_pipeline(db, ml_enabled=None):
    """Create a pipeline: fit the baseline from NORMAL rows of the dataset and load the ML models."""
    import pandas as pd
    from ml.predict import MLPredictor
    if ml_enabled is None:
        ml_enabled = config.ML_ENABLED
    df = pd.read_csv(config.DATASET_PATH)
    normal = df[df["label"] == "NORMAL"].to_dict("records")
    detector = AnomalyDetector().fit(extract_network_features(r) for r in normal)
    return IDSPipeline(db, detector, MLPredictor.load(), ml_enabled)

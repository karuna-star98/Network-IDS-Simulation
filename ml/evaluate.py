"""
Evaluate and compare detection methods on the SAME held-out test split:
rules only, anomaly only, ML only, and the hybrid IDS.

    python -m ml.evaluate
"""
import json
import os

import numpy as np

from ids import config
from ids.anomaly_detector import AnomalyDetector
from ids.alert_engine import should_alert
from ids.risk_engine import calculate_risk_score
from ids.rule_engine import DEFAULT_RULES, analyze_flow, signature_risk
from ml.predict import MLPredictor
from ml.train_model import load_features, score_metrics, split_indices


def compare_methods(csv_path=None, predictor=None):
    feats, y, recs = load_features(csv_path or config.DATASET_PATH)
    tr, te = split_indices(y)
    detector = AnomalyDetector().fit([feats[i] for i in tr if y[i] == 0])
    predictor = predictor or MLPredictor.load()
    ml_out = predictor.predict_many([feats[i] for i in te]) if predictor.available else [None] * len(te)
    preds = {"rules_only": [], "anomaly_only": [], "ml_only": [], "hybrid": []}
    for k, i in enumerate(te):
        matches = analyze_flow(feats[i], recs[i], DEFAULT_RULES)
        s_risk, a_score = signature_risk(matches), detector.calculate_anomaly_score(feats[i])[0]
        p = predictor.primary_probability(ml_out[k]) if predictor.available else None
        risk = calculate_risk_score(s_risk, a_score, p)["risk_score"]
        preds["rules_only"].append(int(bool(matches)))
        preds["anomaly_only"].append(int(a_score >= config.ALERT_RISK_THRESHOLD))
        preds["ml_only"].append(int(p is not None and p >= 0.5))
        preds["hybrid"].append(int(should_alert(risk, matches)))
    y_te = y[te]
    result = {n: score_metrics(y_te, np.array(p)) for n, p in preds.items()}
    if not predictor.available:
        result.pop("ml_only")
    return result


def main():
    result = compare_methods()
    print(f"{'method':<14}{'accuracy':>9}{'precision':>10}{'recall':>8}{'f1':>7}   TN   FP   FN   TP")
    for name, m in result.items():
        c = m["confusion_matrix"]
        print(f"{name:<14}{m['accuracy']:>9.3f}{m['precision']:>10.3f}{m['recall']:>8.3f}{m['f1']:>7.3f}"
              f"  {c['tn']:>4} {c['fp']:>4} {c['fn']:>4} {c['tp']:>4}")
    out = os.path.join(config.BASE_DIR, "reports", "detection_comparison.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w") as f:
        json.dump(result, f, indent=2)
    print(f"Saved {out}")


if __name__ == "__main__":
    main()

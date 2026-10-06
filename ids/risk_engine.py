"""
Hybrid risk scoring: Signature risk + Anomaly score + (optional) ML probability -> 0-100.

The band thresholds and weights are PROJECT ASSUMPTIONS. A real SOC calibrates them
against its own traffic and analyst feedback.
"""
from ids import config

BANDS = [(20, "NORMAL"), (40, "LOW RISK"), (60, "SUSPICIOUS"), (80, "HIGH RISK"), (100, "CRITICAL INVESTIGATION")]
SEVERITY_BY_BAND = {"NORMAL": "INFO", "LOW RISK": "LOW", "SUSPICIOUS": "MEDIUM",
                    "HIGH RISK": "HIGH", "CRITICAL INVESTIGATION": "CRITICAL"}


def classify_risk(score):
    for upper, label in BANDS:
        if score <= upper:
            return label
    return BANDS[-1][1]


def _normalise(weights):
    total = sum(weights.values())
    if total <= 0 or any(v < 0 for v in weights.values()):
        raise ValueError("weights must be non-negative and sum to more than 0")
    return {k: v / total for k, v in weights.items()}


def calculate_risk_score(signature_risk, anomaly_score, ml_probability=None, weights=None):
    """ml_probability: 0-1, or None when ML is disabled/unavailable.
    Returns dict(risk_score, risk_level, weights_used, components)."""
    if ml_probability is None:
        w = _normalise(weights or config.WEIGHTS_WITHOUT_ML)
        score = w["rule"] * signature_risk + w["anomaly"] * anomaly_score
    else:
        w = _normalise(weights or config.WEIGHTS_WITH_ML)
        score = w["rule"] * signature_risk + w["anomaly"] * anomaly_score + w["ml"] * ml_probability * 100
    score = round(max(0.0, min(100.0, score)), 1)
    return {"risk_score": score, "risk_level": classify_risk(score), "weights_used": w,
            "components": {"signature_risk": signature_risk, "anomaly_score": anomaly_score,
                           "ml_probability": ml_probability}}


def verdict(risk_level, rule_matched):
    """Map to the three project classifications."""
    if risk_level in ("HIGH RISK", "CRITICAL INVESTIGATION"):
        return "POTENTIAL INTRUSION"
    if risk_level == "SUSPICIOUS" or rule_matched:
        return "SUSPICIOUS"
    return "NORMAL"


def severity_from_risk(risk_level):
    return SEVERITY_BY_BAND[risk_level]

"""
Statistical anomaly detection.

    Normal baseline -> observe new flow -> compare -> deviation -> anomaly score (0-100)

For each baseline metric we learn, from NORMAL traffic only:
  * mean and standard deviation  -> Z-score   (how many std-devs above normal?)
  * Q1, Q3, IQR                  -> IQR fence (how far past the usual upper range?)
  * an exponential moving average (EWMA) that slowly adapts as new normal flows arrive.
Heavy-tailed metrics (rates, port counts) are measured on a log scale so one big
legitimate flow doesn't ruin the baseline.

Anomaly detection can spot patterns no rule describes, but it flags anything *unusual*,
including harmless events (backups, launches), so it produces false positives.
"""
import math
import numpy as np

BASELINE_METRICS = ["packets_per_second", "bytes_per_second", "connection_rate",
                    "failure_ratio", "unique_destination_ports"]
LINEAR_METRICS = {"failure_ratio"}
Z_LOW, Z_HIGH = 2.0, 5.0       # z <= 2 -> 0 points, z >= 5 -> full points
STD_FLOOR = 0.1


def _t(metric, value):
    return float(value) if metric in LINEAR_METRICS else math.log1p(max(float(value), 0.0))


class AnomalyDetector:
    def __init__(self):
        self.baseline = {}

    @property
    def fitted(self):
        return bool(self.baseline)

    def fit(self, feature_rows):
        """feature_rows: iterable of feature dicts from NORMAL flows."""
        rows = list(feature_rows)
        if not rows:
            raise ValueError("Cannot build a baseline from an empty dataset")
        for m in BASELINE_METRICS:
            x = np.array([_t(m, r[m]) for r in rows])
            q1, q3 = np.percentile(x, [25, 75])
            self.baseline[m] = {"mean": float(x.mean()), "std": max(float(x.std()), STD_FLOOR),
                                "q1": float(q1), "q3": float(q3), "iqr": max(float(q3 - q1), STD_FLOOR),
                                "ewma": float(x.mean()), "n": len(rows)}
        return self

    def update_baseline(self, features, alpha=0.01):
        """Moving-average adaptation. Call ONLY with flows judged normal (else attackers can
        'teach' the baseline that abnormal is normal - known as baseline poisoning)."""
        for m, b in self.baseline.items():
            b["ewma"] = (1 - alpha) * b["ewma"] + alpha * _t(m, features[m])

    def metric_scores(self, features):
        out = {}
        for m, b in self.baseline.items():
            x = _t(m, features[m])
            z = (x - b["mean"]) / b["std"]
            z_pts = min(1.0, max(0.0, (z - Z_LOW) / (Z_HIGH - Z_LOW)))
            fence = b["q3"] + 1.5 * b["iqr"]
            far = b["q3"] + 6 * b["iqr"]
            iqr_pts = min(1.0, max(0.0, (x - fence) / (far - fence))) if x > fence else 0.0
            out[m] = {"z_score": round(z, 2), "score": round(100 * (0.5 * z_pts + 0.5 * iqr_pts), 1)}
        return out

    def calculate_anomaly_score(self, features):
        """Return (score 0-100, per-metric details). 70% strongest deviation + 30% average."""
        if not self.fitted:
            raise RuntimeError("AnomalyDetector must be fitted first")
        details = self.metric_scores(features)
        s = [d["score"] for d in details.values()]
        return round(min(100.0, 0.7 * max(s) + 0.3 * (sum(s) / len(s))), 1), details


def calculate_anomaly_score(features, detector):
    """Module-level convenience wrapper required by the project spec."""
    return detector.calculate_anomaly_score(features)[0]

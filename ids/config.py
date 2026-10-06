"""Central configuration. Values come from environment variables (see .env.example)."""
import os

def _bool(name, default):
    return os.getenv(name, str(default)).strip().lower() in ("1", "true", "yes", "on")

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DB_PATH = os.getenv("IDS_DB_PATH", os.path.join(BASE_DIR, "data", "ids.db"))
DATASET_PATH = os.path.join(BASE_DIR, "data", "network_traffic.csv")
MODEL_PATH = os.path.join(BASE_DIR, "models", "ids_model.joblib")
METRICS_PATH = os.path.join(BASE_DIR, "models", "metrics.json")

ML_ENABLED = _bool("IDS_ML_ENABLED", True)
ALERT_RISK_THRESHOLD = float(os.getenv("IDS_ALERT_RISK_THRESHOLD", 41))
CORRELATION_WINDOW_SECONDS = int(os.getenv("IDS_CORRELATION_WINDOW_SECONDS", 60))
SIM_INTERVAL_SECONDS = float(os.getenv("IDS_SIM_INTERVAL_SECONDS", 1.0))

AUTH_ENABLED = _bool("IDS_AUTH_ENABLED", False)
ANALYST_KEY = os.getenv("IDS_ANALYST_KEY", "change-me-analyst")
ADMIN_KEY = os.getenv("IDS_ADMIN_KEY", "change-me-admin")
RATE_LIMIT_PER_MINUTE = int(os.getenv("IDS_RATE_LIMIT_PER_MINUTE", 1200))

# Hybrid weights (must be positive; they are re-normalised to sum to 1).
WEIGHTS_WITH_ML = {"rule": 0.40, "anomaly": 0.30, "ml": 0.30}
WEIGHTS_WITHOUT_ML = {"rule": 0.60, "anomaly": 0.40}

"""Load the trained Random Forest and return P(suspicious) as 0-100 (None if model not trained)."""
import os, joblib, pandas as pd
from ml.train_model import FEATURES
_model = None
def ml_score(feat, path="models/rf_model.joblib"):
    global _model
    if _model is None:
        if not os.path.exists(path): return None
        _model = joblib.load(path)
    return round(float(_model.predict_proba(pd.DataFrame([{k: feat[k] for k in FEATURES}]))[0][1]) * 100, 1)

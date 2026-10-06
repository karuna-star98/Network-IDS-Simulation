"""Train + evaluate Logistic Regression, Random Forest (supervised) and Isolation Forest (unsupervised).
All metrics are computed from the generated dataset - nothing is hard-coded."""
import json, os, joblib, pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import make_pipeline
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

FEATURES = ["packet_count", "byte_count", "duration", "bytes_per_second", "packets_per_second", "connection_count",
            "failed_connection_count", "syn_count", "rst_count", "average_packet_size"]

def to_features(df):
    from ids.core import extract_network_features
    return pd.DataFrame([{k: extract_network_features(r)[k] for k in FEATURES} for r in df.to_dict("records")])

def metrics(y, p):
    tn, fp, fn, tp = confusion_matrix(y, p, labels=[0, 1]).ravel()
    return {"accuracy": accuracy_score(y, p), "precision": precision_score(y, p, zero_division=0), "recall": recall_score(y, p, zero_division=0),
            "f1": f1_score(y, p, zero_division=0), "confusion_matrix": {"TN": int(tn), "FP": int(fp), "FN": int(fn), "TP": int(tp)}}

def main(csv="data/network_traffic.csv"):
    df = pd.read_csv(csv); X = to_features(df); y = (df.label == "SUSPICIOUS").astype(int)
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.25, stratify=y, random_state=42)
    models = {"LogisticRegression": make_pipeline(StandardScaler(), LogisticRegression(max_iter=1000, class_weight="balanced")),
              "RandomForest": RandomForestClassifier(n_estimators=150, class_weight="balanced", random_state=42, n_jobs=-1)}
    res = {}
    for n, m in models.items():
        m.fit(Xtr, ytr); res[n] = metrics(yte, m.predict(Xte))
    iso = IsolationForest(contamination=0.2, random_state=42).fit(Xtr[ytr == 0])  # learns NORMAL only
    res["IsolationForest"] = metrics(yte, (iso.predict(Xte) == -1).astype(int))
    os.makedirs("models", exist_ok=True); joblib.dump(models["RandomForest"], "models/rf_model.joblib")
    json.dump(res, open("docs/ml_results.json", "w"), indent=2)
    for n, r in res.items():
        print(f"{n:<20} acc={r['accuracy']:.3f} prec={r['precision']:.3f} rec={r['recall']:.3f} f1={r['f1']:.3f} {r['confusion_matrix']}")

if __name__ == "__main__":
    main()

# Network Intrusion Detection System (IDS) Simulation

> This project is designed exclusively for defensive cybersecurity education. All suspicious network behavior is represented using synthetic data or authorized isolated lab environments.

A hybrid network IDS that analyzes **synthetic flow records** (RFC 5737 documentation IPs only), combining signature rules, statistical anomaly detection and optional ML into a 0-100 risk score, alerts, correlation, and a SOC dashboard with an investigation workflow. It never sends packets; the simulator only POSTs data to `localhost`.

## Architecture
```
Simulator -> POST /api/flows -> Feature Extractor -> [Rules | Anomaly | ML] -> Risk Engine -> Alert Engine -> SQLite -> SOC Dashboard -> Analyst
```
| Path | Purpose |
|---|---|
| `simulator/` | `generate_dataset.py` (5,000-flow CSV), `traffic_simulator.py` (live feed, localhost only) |
| `ids/core.py` | features, 6 configurable rules, z-score/IQR anomaly score, hybrid risk, alerts, correlation |
| `ml/` | `train_model.py` (LogReg, Random Forest, Isolation Forest), `predict.py` |
| `backend/` | Flask REST API + `static/dashboard.html` (polling every 3s) |
| `tests/` | 28 automated tests |

## Quick start
```bash
pip install -r requirements.txt
python -m simulator.generate_dataset      # data/network_traffic.csv
python -m ml.train_model                  # optional ML, writes docs/ml_results.json
python -m backend.app                     # terminal 1 -> http://127.0.0.1:5000
python -m simulator.traffic_simulator --mode mixed --speed slow   # terminal 2 (--mode normal for benign only)
python -m unittest discover -s tests -t .
```
Demo: open the dashboard -> click an alert -> **Investigating** -> add a note -> **Resolved** or **False Positive**.

## Detection
- **Rules** (`IDS-001..006`): connection rate, repeated failures, many destination ports, SYN-heavy, unusual port, high volume. Thresholds editable via `PUT /api/rules/{id}`. A match means *investigate*, not *proven malicious*.
- **Anomaly**: baseline (mean/std/IQR) from NORMAL traffic; z-score and IQR deviation -> 0-100.
- **Hybrid risk**: Rules 40% / Anomaly 30% / ML 30% (60/40 if ML disabled). Bands: 0-20 NORMAL, 21-40 LOW, 41-60 SUSPICIOUS, 61-80 HIGH, 81-100 CRITICAL. These thresholds are project assumptions; calibrate in a real SOC.
- **Correlation**: alerts grouped by source IP + alert type within 60s into incidents.

## ML results (computed on a 25% held-out test split of the synthetic data)
| Model | Accuracy | Precision | Recall | F1 | Confusion |
|---|---|---|---|---|---|
| LogisticRegression | 0.981 | 1.000 | 0.904 | 0.950 | TP 226 / FP 0 / FN 24 / TN 1000 |
| RandomForest | 0.998 | 1.000 | 0.992 | 0.996 | TP 248 / FP 0 / FN 2 / TN 1000 |
| IsolationForest | 0.777 | 0.460 | 0.668 | 0.545 | TP 167 / FP 196 / FN 83 / TN 804 |

Synthetic classes are cleanly separable, so supervised scores are optimistic; real traffic would score lower. Accuracy alone is misleading with imbalanced classes, so check recall and precision. Isolation Forest is unsupervised and trained on NORMAL only.

## API
`POST/GET /api/flows`, `GET /api/flows/{id}`, `GET /api/alerts` (filters: severity, status, protocol, alert_type), `GET /api/alerts/{id}`, `PUT /api/alerts/{id}/status`, `POST /api/alerts/{id}/notes`, `GET /api/dashboard/{stats|traffic|alerts}`, `GET /api/rules`, `PUT /api/rules/{id}`. Invalid input returns 400/422, missing items 404.

## Security notes and limitations
Binds to 127.0.0.1; no payloads stored; dashboard output is HTML-escaped; parameterized SQL. **Not implemented:** authentication, RBAC, rate limiting, audit log, TLS (required before any real deployment). Also: synthetic data only, single-flow detection (no per-source sliding windows), and no IPS/blocking by design.

## Future work
Zeek/Suricata ingestion, authorized PCAP, SIEM forwarding (JSON alerts), MITRE ATT&CK mapping with evidence, threat-intel enrichment, drift monitoring.

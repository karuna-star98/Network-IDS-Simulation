"""Continuously generates synthetic flow records and POSTs them to the local IDS backend.
It only creates DATA - no network scanning or attack traffic. Target is localhost only."""
import argparse, random, time, datetime as dt, json, urllib.request
from simulator.generate_dataset import make_flow, NORMAL, SUSPICIOUS

def next_flow(mode, rng=random):
    sus = mode == "mixed" and rng.random() < 0.2
    f = make_flow(rng.choice(SUSPICIOUS) if sus else rng.choice(list(NORMAL)), rng)
    f["timestamp"] = dt.datetime.now().isoformat(timespec="seconds")
    return f

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["normal", "mixed"], default="mixed")
    ap.add_argument("--speed", choices=["slow", "fast"], default="slow")
    ap.add_argument("--url", default="http://127.0.0.1:5000/api/flows")
    ap.add_argument("--count", type=int, default=0, help="0 = run forever")
    a = ap.parse_args()
    if not a.url.startswith(("http://127.0.0.1", "http://localhost")):
        raise SystemExit("Safety: simulator may only target localhost.")
    delay = 1.0 if a.speed == "slow" else 0.15; n = 0
    while a.count == 0 or n < a.count:
        f = next_flow(a.mode)
        req = urllib.request.Request(a.url, json.dumps(f).encode(), {"Content-Type": "application/json"})
        try:
            r = json.load(urllib.request.urlopen(req, timeout=5))
            print(f"{f['scenario_type']:<28} -> {r['classification']:<12} risk={r['risk_score']}")
        except Exception as e:
            print("Backend not reachable (start it first):", e); time.sleep(2)
        n += 1; time.sleep(delay)

if __name__ == "__main__":
    main()

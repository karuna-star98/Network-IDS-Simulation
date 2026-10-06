"""Load the synthetic dataset through the IDS pipeline so the dashboard has data.

    python -m backend.seed --limit 3000
Timestamps are shifted so the newest record is 'now' (the dashboard looks at recent time ranges).
"""
import argparse
from datetime import datetime, timedelta, timezone

import pandas as pd

from backend.db import Database
from ids import config
from ids.pipeline import build_pipeline

DROP = ("label", "scenario_type")   # the IDS never sees the answer key; labels are kept only in the CSV


def seed(pipeline, limit=3000, rebase=True):
    df = pd.read_csv(config.DATASET_PATH).tail(limit)
    if rebase:
        ts = pd.to_datetime(df["timestamp"])
        now = datetime.now(timezone.utc).replace(tzinfo=None, microsecond=0)
        df["timestamp"] = (ts + (now - ts.max())).dt.strftime("%Y-%m-%dT%H:%M:%S")
    rows = [{k: v for k, v in r.items() if k not in DROP} for r in df.to_dict("records")]
    done = dup = bad = 0
    for i in range(0, len(rows), 500):
        for res in pipeline.process_batch(rows[i:i + 500]):
            done += res["status"] == "processed"
            dup += res["status"] == "duplicate"
            bad += res["status"] == "invalid"
    return f"Seeded {done} flows ({dup} duplicates, {bad} invalid)."


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=3000)
    ap.add_argument("--no-rebase", action="store_true")
    a = ap.parse_args()
    db = Database(config.DB_PATH)
    print(seed(build_pipeline(db), a.limit, not a.no_rebase))

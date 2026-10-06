"""Synthetic flow generator. Produces DATA RECORDS only - no packets are ever sent.
All IPs come from RFC 5737 documentation ranges (192.0.2/24, 198.51.100/24, 203.0.113/24)."""
import random, argparse, datetime as dt
import pandas as pd

CLIENTS = [f"192.0.2.{i}" for i in range(10, 60)]
SERVERS = [f"198.51.100.{i}" for i in range(10, 30)]
EXTERNAL = [f"203.0.113.{i}" for i in range(5, 40)]

NORMAL = {  # scenario -> (dst_port, proto)
    "NORMAL_WEB": (443, "TCP"), "NORMAL_DNS": (53, "UDP"), "NORMAL_SSH": (22, "TCP"),
    "NORMAL_EMAIL": (587, "TCP"), "NORMAL_DATABASE": (5432, "TCP")}
SUSPICIOUS = ["HIGH_CONNECTION_RATE", "REPEATED_FAILED_CONNECTIONS", "MULTI_PORT_PROBING_PATTERN",
              "SYN_HEAVY_PATTERN", "UNUSUAL_PORT_ACTIVITY", "HIGH_TRAFFIC_VOLUME"]

def make_flow(scenario, rng=random):
    """Return one flow dict (without id/timestamp) for a scenario."""
    if scenario in NORMAL:
        port, proto = NORMAL[scenario]
        dur = rng.uniform(0.2, 6); pk = rng.randint(4, 40); size = rng.randint(80, 900) if proto == "TCP" else rng.randint(60, 200)
        f = dict(source_ip=rng.choice(CLIENTS), destination_ip=rng.choice(SERVERS), destination_port=port,
                 protocol=proto, packet_count=pk, byte_count=pk * size, duration_seconds=round(dur, 2),
                 connection_count=rng.randint(1, 5), failed_connection_count=rng.choice([0, 0, 0, 1]),
                 syn_count=rng.randint(1, 3) if proto == "TCP" else 0, rst_count=rng.choice([0, 0, 0, 1]),
                 unique_destination_ports=1, unique_destination_ips=1, label="NORMAL")
    else:
        f = make_flow("NORMAL_WEB", rng); f["label"] = "SUSPICIOUS"; f["source_ip"] = rng.choice(EXTERNAL)
        if scenario == "HIGH_CONNECTION_RATE":
            f.update(connection_count=rng.randint(150, 400), duration_seconds=round(rng.uniform(1, 5), 2), syn_count=rng.randint(100, 300))
        elif scenario == "REPEATED_FAILED_CONNECTIONS":
            n = rng.randint(30, 90); f.update(destination_port=22, connection_count=n, failed_connection_count=n - rng.randint(0, 3), rst_count=rng.randint(20, 60))
        elif scenario == "MULTI_PORT_PROBING_PATTERN":
            f.update(unique_destination_ports=rng.randint(25, 200), connection_count=rng.randint(30, 150),
                     failed_connection_count=rng.randint(20, 100), syn_count=rng.randint(30, 150), packet_count=rng.randint(30, 150), byte_count=rng.randint(2000, 9000))
        elif scenario == "SYN_HEAVY_PATTERN":
            f.update(syn_count=rng.randint(300, 900), packet_count=rng.randint(300, 900), byte_count=rng.randint(18000, 54000), duration_seconds=round(rng.uniform(0.5, 2), 2), rst_count=rng.randint(0, 5))
        elif scenario == "UNUSUAL_PORT_ACTIVITY":
            f.update(destination_port=rng.choice([4444, 6667, 31337, 12345]), connection_count=rng.randint(5, 20))
        elif scenario == "HIGH_TRAFFIC_VOLUME":
            f.update(byte_count=rng.randint(80_000_000, 400_000_000), packet_count=rng.randint(60000, 300000), duration_seconds=round(rng.uniform(5, 30), 2))
    f["source_port"] = rng.randint(49152, 65535)
    f["scenario_type"] = scenario
    f["average_packet_size"] = round(f["byte_count"] / max(f["packet_count"], 1), 2)
    return f

def generate(n=5000, seed=42, suspicious_ratio=0.2):
    rng = random.Random(seed); t0 = dt.datetime(2026, 1, 1, 9, 0, 0); rows = []
    for i in range(n):
        sc = rng.choice(SUSPICIOUS) if rng.random() < suspicious_ratio else rng.choice(list(NORMAL))
        f = make_flow(sc, rng); f["flow_id"] = i + 1
        f["timestamp"] = (t0 + dt.timedelta(seconds=i * 2)).isoformat(); rows.append(f)
    cols = ["flow_id", "timestamp", "source_ip", "destination_ip", "source_port", "destination_port", "protocol", "packet_count",
            "byte_count", "duration_seconds", "connection_count", "failed_connection_count", "syn_count", "rst_count",
            "average_packet_size", "unique_destination_ports", "unique_destination_ips", "label", "scenario_type"]
    return pd.DataFrame(rows)[cols]

if __name__ == "__main__":
    ap = argparse.ArgumentParser(); ap.add_argument("--rows", type=int, default=5000); ap.add_argument("--out", default="data/network_traffic.csv")
    a = ap.parse_args(); df = generate(a.rows); df.to_csv(a.out, index=False)
    print(f"Wrote {len(df)} synthetic flows to {a.out}\n{df.label.value_counts().to_string()}")

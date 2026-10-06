"""
Synthetic flow scenarios.

SAFETY: this module only builds Python dictionaries (data records). It never opens a
socket and never sends a packet. All IPs come from the RFC 5737 documentation ranges
(192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), which are reserved for examples and
are never routed on the public internet.
"""
import random
from datetime import datetime, timezone

CLIENTS = [f"192.0.2.{i}" for i in range(10, 60)]      # "internal" workstations
SERVERS = [f"198.51.100.{i}" for i in range(10, 40)]   # "internal" servers
EXTERNAL = [f"203.0.113.{i}" for i in range(10, 80)]   # "outside" sources
UNUSUAL_PORTS = [4444, 6667, 31337, 1337, 12345, 2323, 9001]

NORMAL_SCENARIOS = {  # name: relative frequency
    "NORMAL_WEB": 0.38, "NORMAL_DNS": 0.27, "NORMAL_SSH": 0.10,
    "NORMAL_EMAIL": 0.12, "NORMAL_DATABASE": 0.13,
}
SUSPICIOUS_SCENARIOS = [
    "HIGH_CONNECTION_RATE", "REPEATED_FAILED_CONNECTIONS", "MULTI_PORT_PROBING_PATTERN",
    "SYN_HEAVY_PATTERN", "UNUSUAL_PORT_ACTIVITY", "HIGH_TRAFFIC_VOLUME",
]
ALL_SCENARIOS = list(NORMAL_SCENARIOS) + SUSPICIOUS_SCENARIOS


def utc_now():
    return datetime.now(timezone.utc).replace(tzinfo=None, microsecond=0)


def _flow(rng, scenario, label, src, dst, dport, proto, packets, avg_size, duration,
          conn, failed, syn, rst, uports=1, uips=1, ts=None, flow_id=None):
    packets = max(1, int(packets))
    byte_count = int(packets * avg_size)
    conn = max(0, int(conn))
    failed = min(max(0, int(failed)), conn)
    return {
        "flow_id": flow_id or f"FLW-{rng.getrandbits(40):010x}",
        "timestamp": (ts or utc_now()).isoformat(timespec="seconds"),
        "source_ip": src, "destination_ip": dst,
        "source_port": rng.randint(49152, 65535), "destination_port": int(dport),
        "protocol": proto, "packet_count": packets, "byte_count": byte_count,
        "duration_seconds": round(duration, 3), "connection_count": conn,
        "failed_connection_count": failed, "syn_count": max(0, int(syn)),
        "rst_count": max(0, int(rst)), "average_packet_size": round(byte_count / packets, 2),
        "label": label, "scenario_type": scenario,
        "unique_destination_ports": max(1, int(uports)), "unique_destination_ips": max(1, int(uips)),
    }


def generate_flow(scenario, rng=None, timestamp=None, src_ip=None, flow_id=None):
    """Return one synthetic flow record for `scenario`."""
    rng = rng or random.Random()
    u = rng.uniform
    label = "NORMAL" if scenario in NORMAL_SCENARIOS else "SUSPICIOUS"
    client, server = rng.choice(CLIENTS), rng.choice(SERVERS)
    ext = rng.choice(EXTERNAL)
    mild = rng.random() < 0.08          # a few suspicious flows are deliberately subtle
    busy = rng.random() < 0.05          # a few normal flows are deliberately busy
    k = dict(ts=timestamp, flow_id=flow_id)
    S = lambda *a, **kw: _flow(rng, scenario, label, *a, **kw, **k)  # noqa: E731

    if scenario == "NORMAL_WEB":
        conn = rng.randint(8, 16) if busy else rng.randint(1, 4)
        return S(src_ip or client, server, rng.choice([443] * 8 + [80] * 2), "TCP",
                 rng.randint(8, 80) * (3 if busy else 1), u(350, 1100), u(2, 8) if busy else u(0.5, 12),
                 conn, 1 if rng.random() < 0.03 else 0, conn, rng.choice([0, 0, 1]))
    if scenario == "NORMAL_DNS":
        return S(src_ip or client, server, 53, "UDP", rng.randint(2, 6), u(70, 250), u(0.02, 1.5),
                 rng.randint(1, 3), 0, 0, 0)
    if scenario == "NORMAL_SSH":
        return S(src_ip or client, server, 22, "TCP", rng.randint(40, 600), u(80, 400), u(5, 900),
                 rng.randint(1, 2), 1 if rng.random() < 0.05 else 0, rng.randint(1, 2), 0)
    if scenario == "NORMAL_EMAIL":
        return S(src_ip or client, server, rng.choice([25, 587, 993, 465]), "TCP", rng.randint(10, 120),
                 u(300, 1000), u(1, 30), rng.randint(1, 3), 0, rng.randint(1, 3), 0)
    if scenario == "NORMAL_DATABASE":
        if rng.random() < 0.02:  # nightly backup: big but legitimate (a classic false-positive trap)
            return S(src_ip or client, server, 5432, "TCP", rng.randint(15000, 30000), u(1300, 1450),
                     u(60, 300), 1, 0, 1, 0)
        return S(src_ip or client, server, rng.choice([3306, 5432, 1433]), "TCP", rng.randint(20, 300),
                 u(150, 700), u(1, 120), rng.randint(1, 4), 0, rng.randint(1, 4), 0)

    src = src_ip or ext
    if scenario == "HIGH_CONNECTION_RATE":
        conn = rng.randint(120, 250) if mild else rng.randint(300, 1500)
        dur = u(5, 9) if mild else u(2, 10)
        failed = conn * u(0, 0.3)
        return S(src, server, rng.choice([443, 80, 22, 8080]), "TCP", conn * u(2, 6), u(60, 200), dur,
                 conn, failed, conn, failed * u(0, 0.5))
    if scenario == "REPEATED_FAILED_CONNECTIONS":
        conn = rng.randint(6, 10) if mild else rng.randint(15, 120)
        failed = conn * (u(0.5, 0.8) if mild else u(0.7, 1.0))
        return S(src, server, rng.choice([22, 3389, 445, 443, 21]), "TCP", conn * u(2, 4), u(60, 120),
                 u(5, 120), conn, failed, conn, failed * u(0.5, 1))
    if scenario == "MULTI_PORT_PROBING_PATTERN":
        ports = rng.randint(10, 18) if mild else rng.randint(25, 300)
        conn = ports
        failed = conn * u(0.5, 0.95)
        return S(src, server, rng.randint(1, 65535), "TCP", ports * u(1, 3), u(40, 70), u(3, 60),
                 conn, failed, conn, failed * u(0.3, 0.9), uports=ports)
    if scenario == "SYN_HEAVY_PATTERN":
        syn = rng.randint(60, 120) if mild else rng.randint(150, 2000)
        conn = rng.randint(5, 60)
        return S(src, server, rng.choice([443, 80, 22]), "TCP", syn * u(1.0, 1.3), u(40, 60), u(1, 20),
                 conn, conn * u(0.3, 0.9), syn, conn * u(0, 0.3))
    if scenario == "UNUSUAL_PORT_ACTIVITY":
        return S(src_ip or client, server, rng.choice(UNUSUAL_PORTS), "TCP", rng.randint(5, 200),
                 u(100, 900), u(1, 60), rng.randint(1, 3), rng.choice([0, 0, 1]), rng.randint(1, 3), 0)
    if scenario == "HIGH_TRAFFIC_VOLUME":
        packets = rng.randint(45000, 400000)
        size = u(1200, 1450) * (0.5 if mild else 1.0)
        return S(src_ip or client, ext, rng.choice([443, 80, 21, 8080]), "TCP", packets, size, u(20, 300),
                 rng.randint(1, 3), 0, rng.randint(1, 3), 0)
    raise ValueError(f"Unknown scenario: {scenario}")


def pick_normal_scenario(rng):
    names, weights = zip(*NORMAL_SCENARIOS.items())
    return rng.choices(names, weights)[0]

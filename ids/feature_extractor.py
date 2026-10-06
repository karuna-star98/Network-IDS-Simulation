"""
Flow validation + feature engineering.

A raw flow record (dict) is first validated/cleaned by sanitize_flow(), then
extract_network_features() turns it into numeric features the detectors understand.

Feature -> why a SOC analyst cares:
  packet_count / byte_count    size of the conversation; huge values hint at bulk transfer
  duration                     how long the flow lasted
  packets_per_second           packet rate; floods/scans are bursty
  bytes_per_second             bandwidth; exfiltration or volumetric abuse is high
  average_packet_size          tiny packets (~40-60 B) look like handshakes/probes, big ones like bulk data
  connection_count             how many connections the source opened
  connection_rate              connections/second; automated tools open many quickly
  failed_connection_count      refused/timed-out attempts
  failure_ratio                failed / total; guessing and probing fail a lot
  syn_count / rst_count        TCP handshake starts / resets
  syn_ratio                    syn / packets; near 1.0 = mostly handshake starts, no real data
  unique_destination_ports     port diversity; one source touching many ports looks like probing
  unique_destination_ips       how many hosts one source touched
"""
import ipaddress
import math

SUPPORTED_PROTOCOLS = {"TCP", "UDP", "ICMP"}
MIN_DURATION = 1.0   # rates use at least a 1-second window so 20 ms DNS flows don't create fake spikes

REQUIRED_FIELDS = ["source_ip", "destination_ip", "source_port", "destination_port", "protocol"]
INT_FIELDS = ["packet_count", "byte_count", "connection_count", "failed_connection_count",
              "syn_count", "rst_count"]

FEATURE_NAMES = ["packet_count", "byte_count", "duration", "bytes_per_second", "packets_per_second",
                 "average_packet_size", "connection_count", "failed_connection_count", "failure_ratio",
                 "syn_count", "rst_count", "syn_ratio", "unique_destination_ports",
                 "unique_destination_ips", "connection_rate"]
# Subset used by the ML models (as requested in the project brief).
ML_FEATURES = ["packet_count", "byte_count", "duration", "bytes_per_second", "packets_per_second",
               "connection_count", "failed_connection_count", "syn_count", "rst_count",
               "average_packet_size"]


class FlowValidationError(ValueError):
    """Raised when a flow record is unusable. `.errors` lists every problem found."""
    def __init__(self, errors):
        self.errors = list(errors)
        super().__init__("; ".join(self.errors))


def _missing(v):
    return v is None or v == "" or (isinstance(v, float) and math.isnan(v))


def _to_number(v, name, errors, integer=True):
    try:
        x = float(v)
    except (TypeError, ValueError):
        errors.append(f"{name} must be numeric")
        return None
    if math.isnan(x) or math.isinf(x):
        errors.append(f"{name} must be a finite number")
        return None
    if integer and x != int(x):
        errors.append(f"{name} must be a whole number")
        return None
    if x < 0:
        errors.append(f"{name} must not be negative")
        return None
    return int(x) if integer else x


def _check_ip(v, name, errors):
    try:
        return str(ipaddress.ip_address(str(v).strip()))
    except ValueError:
        errors.append(f"{name} is not a valid IP address")
        return None


def sanitize_flow(raw):
    """Validate and normalise a raw flow. Returns (clean_flow, warnings).
    Raises FlowValidationError listing ALL problems if the flow is unusable."""
    if not isinstance(raw, dict):
        raise FlowValidationError(["flow must be a JSON object"])
    errors, warnings, clean = [], [], {}

    for f in REQUIRED_FIELDS:
        if _missing(raw.get(f)):
            errors.append(f"{f} is required")
    clean["source_ip"] = _check_ip(raw.get("source_ip"), "source_ip", errors) if not _missing(raw.get("source_ip")) else None
    clean["destination_ip"] = _check_ip(raw.get("destination_ip"), "destination_ip", errors) if not _missing(raw.get("destination_ip")) else None

    proto = str(raw.get("protocol", "")).strip().upper()
    if proto and proto not in SUPPORTED_PROTOCOLS:
        errors.append(f"protocol '{proto}' is unsupported (use {', '.join(sorted(SUPPORTED_PROTOCOLS))})")
    clean["protocol"] = proto

    for f in ("source_port", "destination_port"):
        if _missing(raw.get(f)):
            continue
        port = _to_number(raw.get(f), f, errors)
        if port is not None:
            low = 0 if proto == "ICMP" else 1
            if not low <= port <= 65535:
                errors.append(f"{f} must be between {low} and 65535")
            else:
                clean[f] = port

    for f in INT_FIELDS:
        if _missing(raw.get(f)):
            warnings.append(f"{f} missing, defaulted to 0")
            clean[f] = 0
        else:
            clean[f] = _to_number(raw.get(f), f, errors)
    if _missing(raw.get("duration_seconds")):
        warnings.append("duration_seconds missing, defaulted to 0")
        clean["duration_seconds"] = 0.0
    else:
        clean["duration_seconds"] = _to_number(raw.get("duration_seconds"), "duration_seconds", errors, integer=False)
    for f in ("unique_destination_ports", "unique_destination_ips"):
        clean[f] = 1 if _missing(raw.get(f)) else _to_number(raw.get(f), f, errors)

    if errors:
        raise FlowValidationError(errors)

    if clean["failed_connection_count"] > clean["connection_count"]:
        warnings.append("failed_connection_count exceeds connection_count; ratio capped at 1.0")
    for f in ("flow_id", "timestamp", "label", "scenario_type"):
        if not _missing(raw.get(f)):
            clean[f] = str(raw[f])[:64]
    return clean, warnings


def _div(a, b):
    return a / b if b else 0.0


def extract_network_features(flow):
    """Return the feature dict for a (raw or already-clean) flow. Safe against zero duration,
    zero packets and missing values; raises FlowValidationError for malformed IPs/ports/protocol."""
    c, _ = sanitize_flow(flow)
    window = max(c["duration_seconds"], MIN_DURATION)
    packets, conn = c["packet_count"], c["connection_count"]
    return {
        "packet_count": packets,
        "byte_count": c["byte_count"],
        "duration": c["duration_seconds"],
        "bytes_per_second": c["byte_count"] / window,
        "packets_per_second": packets / window,
        "average_packet_size": _div(c["byte_count"], packets),
        "connection_count": conn,
        "failed_connection_count": c["failed_connection_count"],
        "failure_ratio": min(1.0, _div(c["failed_connection_count"], conn)),
        "syn_count": c["syn_count"],
        "rst_count": c["rst_count"],
        "syn_ratio": min(1.0, _div(c["syn_count"], packets)),
        "unique_destination_ports": c["unique_destination_ports"],
        "unique_destination_ips": c["unique_destination_ips"],
        "connection_rate": conn / window,
    }

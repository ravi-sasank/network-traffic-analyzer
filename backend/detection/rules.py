"""Detection rules as pure functions: flows in, findings out. No SQL, no
side effects, so each is unit-testable against known traffic.

Every finding carries a plain-English `reason` - this is what makes alerts
explainable rather than just 'ALERT: 1.2.3.4'."""
import math
from collections import defaultdict

# Defaults; calibrate.py overrides these from measured normal traffic
PORT_SCAN_MIN_PORTS = 15
PORT_SCAN_RST_RATIO = 0.5
BURST_MIN_ATTEMPTS = 60
DNS_NAME_LENGTH = 30
DNS_MIN_ENTROPY = 3.5
DNS_MIN_QUERIES = 10
ICMP_SWEEP_MIN_HOSTS = 10


def _flags(flow):
    return set((flow.get("tcp_flags") or "").split(","))


def shannon_entropy(s):
    """Higher = more random. Encoded/exfil data scores well above real names."""
    if not s:
        return 0.0
    counts = defaultdict(int)
    for ch in s:
        counts[ch] += 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def detect_port_scan(flows, thresholds=None):
    """One source, many distinct ports, mostly refused.

    Requires BOTH high port count AND high refusal ratio, so a browser opening
    parallel connections (few ports, mostly completed) does not trip it."""
    t = thresholds or {}
    min_ports = t.get("port_scan_min_ports", PORT_SCAN_MIN_PORTS)
    min_ratio = t.get("port_scan_rst_ratio", PORT_SCAN_RST_RATIO)

    by_src = defaultdict(lambda: {"ports": set(), "syn": 0, "rst": 0})
    for f in flows:
        if f["protocol"] != "TCP" or not f.get("dst_port"):
            continue
        fl = _flags(f)
        s = by_src[f["src_ip"]]
        s["ports"].add(f["dst_port"])
        if "SYN" in fl:
            s["syn"] += 1
        if "RST" in fl:
            s["rst"] += 1

    findings = []
    for src, s in by_src.items():
        n = len(s["ports"])
        if n < min_ports:
            continue
        ratio = s["rst"] / max(s["syn"], 1)
        if ratio < min_ratio:
            continue
        findings.append({
            "rule_name": "port_scan",
            "src_ip": src, "dst_ip": None,
            "reason": (src + " probed " + str(n) + " distinct ports with a "
                       + str(int(ratio * 100)) + "% refusal rate - "
                       "consistent with a TCP port scan"),
            "evidence": {"distinct_ports": n, "syn": s["syn"],
                         "rst": s["rst"], "rst_ratio": round(ratio, 2)},
        })
    return findings


def detect_connection_burst(flows, thresholds=None):
    """Many connection attempts to a single port - SYN-flood shape."""
    t = thresholds or {}
    min_attempts = t.get("burst_min_attempts", BURST_MIN_ATTEMPTS)

    by_pair = defaultdict(int)
    for f in flows:
        if f["protocol"] != "TCP" or not f.get("dst_port"):
            continue
        if "SYN" in _flags(f):
            by_pair[(f["src_ip"], f["dst_ip"], f["dst_port"])] += f["packet_count"]

    findings = []
    for (src, dst, port), n in by_pair.items():
        if n < min_attempts:
            continue
        findings.append({
            "rule_name": "connection_burst",
            "src_ip": src, "dst_ip": dst,
            "reason": (src + " opened " + str(n) + " connections to "
                       + str(dst) + ":" + str(port)
                       + " in the window - possible SYN flood"),
            "evidence": {"attempts": n, "dst_port": port},
        })
    return findings


def detect_dns_exfil(dns_rows, thresholds=None):
    """Long, high-entropy DNS names, or heavy volume to one domain."""
    t = thresholds or {}
    min_len = t.get("dns_name_length", DNS_NAME_LENGTH)
    min_ent = t.get("dns_min_entropy", DNS_MIN_ENTROPY)
    min_q = t.get("dns_min_queries", DNS_MIN_QUERIES)

    by_domain = defaultdict(lambda: {"count": 0, "suspicious": 0, "src": None})
    for r in dns_rows:
        qname = r.get("qname") or ""
        parts = qname.split(".")
        if len(parts) < 2:
            continue
        domain = ".".join(parts[-2:])
        label = parts[0]
        d = by_domain[domain]
        d["count"] += 1
        d["src"] = r.get("src_ip")
        if len(label) >= min_len and shannon_entropy(label) >= min_ent:
            d["suspicious"] += 1

    findings = []
    for domain, d in by_domain.items():
        if d["suspicious"] == 0:
            continue
        findings.append({
            "rule_name": "dns_exfil",
            "src_ip": d["src"], "dst_ip": None,
            "reason": (str(d["suspicious"]) + " long high-entropy DNS queries to "
                       + domain + " - possible DNS tunnelling/exfiltration"),
            "evidence": {"domain": domain, "suspicious_queries": d["suspicious"],
                         "total_queries": d["count"]},
        })
    return findings


def detect_icmp_sweep(flows, thresholds=None):
    """One source pinging many hosts - network reconnaissance."""
    t = thresholds or {}
    min_hosts = t.get("icmp_sweep_min_hosts", ICMP_SWEEP_MIN_HOSTS)

    by_src = defaultdict(set)
    for f in flows:
        if f["protocol"] in ("ICMP", "ICMPv6"):
            by_src[f["src_ip"]].add(f["dst_ip"])

    findings = []
    for src, hosts in by_src.items():
        if len(hosts) < min_hosts:
            continue
        findings.append({
            "rule_name": "icmp_sweep",
            "src_ip": src, "dst_ip": None,
            "reason": (src + " sent ICMP to " + str(len(hosts))
                       + " distinct hosts - network sweep / host discovery"),
            "evidence": {"distinct_hosts": len(hosts)},
        })
    return findings


ALL_RULES = [detect_port_scan, detect_connection_burst, detect_icmp_sweep]

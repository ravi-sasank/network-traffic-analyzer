"""Derive detection thresholds from observed normal traffic.

Reads flows/DNS from the DB, computes per-minute distributions of each
metric a rule uses, and writes thresholds at a high percentile above
observed normal. This replaces guessed numbers with measured ones - so
every threshold has a defensible answer to 'why that value?'.

Run AFTER capturing a block of clean traffic with NO simulator running:
    python tools/calibrate.py
"""
import json
import statistics
from collections import defaultdict

from backend.storage.db import get_connection
from backend.config import BASE_DIR

PERCENTILE = 99
OUTPUT = BASE_DIR / "backend" / "detection" / "thresholds.json"


def percentile(values, pct):
    if not values:
        return None
    values = sorted(values)
    k = (len(values) - 1) * (pct / 100)
    lo = int(k)
    hi = min(lo + 1, len(values) - 1)
    return values[lo] + (values[hi] - values[lo]) * (k - lo)


def load_flows(conn):
    rows = conn.execute("SELECT * FROM flows ORDER BY bucket_ts").fetchall()
    return [dict(r) for r in rows]


def load_dns(conn):
    rows = conn.execute("SELECT * FROM dns_queries ORDER BY ts").fetchall()
    return [dict(r) for r in rows]


def per_minute_buckets(flows):
    buckets = defaultdict(list)
    for f in flows:
        minute = f["bucket_ts"] // 60
        buckets[minute].append(f)
    return buckets


def analyze(flows, dns):
    minutes = per_minute_buckets(flows)
    if not minutes:
        return None

    ports_per_src = []
    syns_per_pair = []
    icmp_hosts = []
    dns_label_lens = []

    for minute, mflows in minutes.items():
        by_src_ports = defaultdict(set)
        by_pair_syn = defaultdict(int)
        by_src_icmp = defaultdict(set)
        for f in mflows:
            fl = set((f.get("tcp_flags") or "").split(","))
            if f["protocol"] == "TCP" and f.get("dst_port"):
                by_src_ports[f["src_ip"]].add(f["dst_port"])
                if "SYN" in fl:
                    by_pair_syn[(f["src_ip"], f["dst_ip"], f["dst_port"])] += f["packet_count"]
            if f["protocol"] in ("ICMP", "ICMPv6"):
                by_src_icmp[f["src_ip"]].add(f["dst_ip"])
        ports_per_src.extend(len(p) for p in by_src_ports.values())
        syns_per_pair.extend(by_pair_syn.values())
        icmp_hosts.extend(len(h) for h in by_src_icmp.values())

    for r in dns:
        qname = r.get("qname") or ""
        parts = qname.split(".")
        if parts:
            dns_label_lens.append(len(parts[0]))

    def summ(vals):
        vals = [v for v in vals if v is not None]
        if not vals:
            return {"n": 0}
        return {
            "n": len(vals),
            "max": max(vals),
            "mean": round(statistics.mean(vals), 2),
            "p" + str(PERCENTILE): round(percentile(vals, PERCENTILE), 2),
        }

    return {
        "distinct_ports_per_src_per_min": summ(ports_per_src),
        "syns_per_pair_per_min": summ(syns_per_pair),
        "icmp_hosts_per_min": summ(icmp_hosts),
        "dns_label_length": summ(dns_label_lens),
    }


def derive_thresholds(stats):
    pk = "p" + str(PERCENTILE)

    def above(metric, floor, mult=1.5):
        s = stats.get(metric, {})
        observed = s.get(pk) or 0
        return max(floor, int(observed * mult) + 1)

    return {
        "port_scan_min_ports": above("distinct_ports_per_src_per_min", 15),
        "port_scan_rst_ratio": 0.5,
        "burst_min_attempts": above("syns_per_pair_per_min", 60, mult=2.0),
        "icmp_sweep_min_hosts": above("icmp_hosts_per_min", 10),
        "dns_name_length": 30,
        "dns_min_entropy": 3.5,
        "dns_min_queries": 10,
    }


def main():
    conn = get_connection()
    flows = load_flows(conn)
    dns = load_dns(conn)
    conn.close()

    print("loaded " + str(len(flows)) + " flows, " + str(len(dns)) + " DNS queries")
    if len(flows) < 50:
        print("WARNING: very little data. Capture more normal traffic first.")

    stats = analyze(flows, dns)
    if stats is None:
        print("no data to calibrate on")
        return

    print("\n=== observed normal traffic ===")
    print(json.dumps(stats, indent=2))

    thresholds = derive_thresholds(stats)
    print("\n=== derived thresholds ===")
    print(json.dumps(thresholds, indent=2))

    payload = {"thresholds": thresholds, "observed": stats,
               "percentile": PERCENTILE}
    OUTPUT.write_text(json.dumps(payload, indent=2))
    print("\nwritten to " + str(OUTPUT))


if __name__ == "__main__":
    main()

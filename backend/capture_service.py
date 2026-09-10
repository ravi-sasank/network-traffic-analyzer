"""Entrypoint for the capture process."""
import signal
import sys
from scapy.all import sniff

from backend.config import INTERFACE, BPF_FILTER, PROMISCUOUS
from backend.storage.db import init_db
from backend.storage import queries as q
from backend.capture.parser import parse, set_local_addresses
from backend.capture.local_addrs import get_local_addresses
from backend.capture.aggregator import FlowAggregator
from backend.detection.engine import DetectionEngine

conn = init_db()
agg = FlowAggregator()
engine = DetectionEngine(conn)
packet_buffer, dns_buffer, device_buffer = [], [], []
MAX_BUFFER = 20000   # hard cap per buffer between flushes
FLOW_RETENTION_SECONDS = 6 * 3600   # keep 6h of flows on disk
stats = {"packets": 0, "flows": 0}


def _maintenance():
    import time as _t
    cutoff = int(_t.time()) - FLOW_RETENTION_SECONDS
    try:
        conn.execute("DELETE FROM flows WHERE bucket_ts < ?", (cutoff,))
        conn.execute("DELETE FROM dns_queries WHERE ts < ?", (cutoff,))
        conn.commit()
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE);")
        print("  [maint] checkpoint + pruned flows older than 6h", flush=True)
    except Exception as e:
        print("  [maint] skipped: " + str(e), flush=True)


def persist(flow_rows):
    global packet_buffer, dns_buffer, device_buffer
    q.insert_flows(conn, flow_rows)
    q.insert_recent_packets(conn, packet_buffer)
    q.insert_dns(conn, dns_buffer)
    q.upsert_devices(conn, device_buffer)
    stats["flows"] += len(flow_rows)

    # periodic maintenance: checkpoint WAL, prune old flows
    stats["flushes"] = stats.get("flushes", 0) + 1
    if stats["flushes"] % 30 == 0:      # roughly every 5 min at 10s buckets
        _maintenance()

    # run detection on this batch
    dns_batch = list(dns_buffer)
    alerts = engine.process(flow_rows, dns_batch)
    for a in alerts:
        stats["alerts"] = stats.get("alerts", 0) + 1
        print("  [ALERT] " + a["severity"].upper() + " - "
              + a["reason"], flush=True)

    print("  flushed " + str(len(flow_rows)) + " flows | "
          + str(stats["packets"]) + " packets | "
          + str(stats.get("alerts", 0)) + " alerts", flush=True)
    packet_buffer, dns_buffer, device_buffer = [], [], []


def handle(pkt):
    try:
        _handle(pkt)
    except Exception as e:
        stats["errors"] = stats.get("errors", 0) + 1
        # log first few, then stay quiet to avoid flooding
        if stats["errors"] <= 5:
            print("  [warn] skipped malformed packet: " + str(e), flush=True)


def _handle(pkt):
    rec = parse(pkt)
    if rec is None:
        return
    stats["packets"] += 1

    if len(packet_buffer) < MAX_BUFFER:
        packet_buffer.append({
            "ts": rec["ts"], "src_ip": rec["src_ip"], "dst_ip": rec["dst_ip"],
            "src_port": rec["src_port"], "dst_port": rec["dst_port"],
            "protocol": rec["protocol"], "length": rec["length"], "info": rec["info"],
        })
    else:
        stats["dropped"] = stats.get("dropped", 0) + 1

    if rec["dns"]:
        dns_buffer.append({
            "ts": rec["ts"], "src_ip": rec["src_ip"],
            "qname": rec["dns"]["qname"], "qtype": rec["dns"]["qtype"],
            "resolved": None,
        })

    if rec["src_mac"]:
        device_buffer.append({
            "mac": rec["src_mac"], "ip": rec["src_ip"],
            "ts": int(rec["ts"]), "bytes": rec["length"],
        })

    completed = agg.add(rec)
    if completed:
        persist(completed)


def shutdown(signum, frame):
    print("\nstopping - flushing final bucket...")
    persist(agg.flush())
    print("total: " + str(stats["packets"]) + " packets, "
          + str(stats["flows"]) + " flow rows")
    conn.close()
    sys.exit(0)


if __name__ == "__main__":
    signal.signal(signal.SIGINT, shutdown)
    local = get_local_addresses(INTERFACE)
    set_local_addresses(local)
    print("local addresses: " + ", ".join(sorted(local)))
    print("capturing on " + INTERFACE + " | filter: " + BPF_FILTER)
    print("Ctrl+C to stop\n")
    sniff(iface=INTERFACE, filter=BPF_FILTER, prn=handle,
          store=False, promisc=PROMISCUOUS)

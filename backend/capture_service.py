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

conn = init_db()
agg = FlowAggregator()
packet_buffer, dns_buffer, device_buffer = [], [], []
stats = {"packets": 0, "flows": 0}


def persist(flow_rows):
    global packet_buffer, dns_buffer, device_buffer
    q.insert_flows(conn, flow_rows)
    q.insert_recent_packets(conn, packet_buffer)
    q.insert_dns(conn, dns_buffer)
    q.upsert_devices(conn, device_buffer)
    stats["flows"] += len(flow_rows)
    print("  flushed " + str(len(flow_rows)) + " flows | "
          + str(stats["packets"]) + " packets seen", flush=True)
    packet_buffer, dns_buffer, device_buffer = [], [], []


def handle(pkt):
    rec = parse(pkt)
    if rec is None:
        return
    stats["packets"] += 1

    packet_buffer.append({
        "ts": rec["ts"], "src_ip": rec["src_ip"], "dst_ip": rec["dst_ip"],
        "src_port": rec["src_port"], "dst_port": rec["dst_port"],
        "protocol": rec["protocol"], "length": rec["length"], "info": rec["info"],
    })

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

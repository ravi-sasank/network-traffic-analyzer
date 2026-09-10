"""Generate detectable traffic patterns against loopback (127.0.0.1).

Everything here targets this machine only. No external hosts are touched.
Run the capture service on lo0 while this runs:

    NTA_IFACE=lo0 python -m backend.capture_service
"""
import argparse
import random
import socket
import string
import time

TARGET = "127.0.0.1"


def port_scan(ports=60, delay=0.02):
    """Hit many distinct ports quickly. Closed ports reply RST."""
    print("[port_scan] probing " + str(ports) + " ports on " + TARGET)
    hits = 0
    for port in random.sample(range(1024, 65535), ports):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.15)
        try:
            if s.connect_ex((TARGET, port)) == 0:
                hits += 1
        except OSError:
            pass
        finally:
            s.close()
        time.sleep(delay)
    print("[port_scan] done - " + str(hits) + " open")


def connection_burst(count=600, port=9, delay=0.002):
    """Many rapid connection attempts to one port - SYN flood shape."""
    print("[burst] " + str(count) + " connections to port " + str(port))
    for _ in range(count):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.05)
        try:
            s.connect_ex((TARGET, port))
        except OSError:
            pass
        finally:
            s.close()
        time.sleep(delay)
    print("[burst] done")


def dns_exfil(count=40, delay=0.05):
    """Long, high-entropy DNS queries - the data-exfiltration signature."""
    from scapy.all import IP, UDP, DNS, DNSQR, send
    print("[dns_exfil] " + str(count) + " encoded queries")
    for _ in range(count):
        label = "".join(random.choices(string.ascii_lowercase + string.digits, k=40))
        pkt = (IP(dst=TARGET) / UDP(sport=random.randint(30000, 60000), dport=53)
               / DNS(rd=1, qd=DNSQR(qname=label + ".exfil-test.local")))
        send(pkt, verbose=0)
        time.sleep(delay)
    print("[dns_exfil] done")


def data_spike(mb=4, port=9):
    """Sudden large outbound volume - traffic spike."""
    print("[spike] pushing ~" + str(mb) + "MB to port " + str(port))
    chunk = b"x" * 65535
    sent = 0
    for _ in range(mb * 16):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.05)
        try:
            s.connect_ex((TARGET, port))
            s.send(chunk)
            sent += len(chunk)
        except OSError:
            pass
        finally:
            s.close()
    print("[spike] done - " + str(sent // 1024) + "KB attempted")


SCENARIOS = {
    "scan": port_scan,
    "burst": connection_burst,
    "dns": dns_exfil,
    "spike": data_spike,
}

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Traffic generator for NTA testing")
    ap.add_argument("scenario", choices=list(SCENARIOS) + ["all"])
    args = ap.parse_args()

    print("target: " + TARGET + " (loopback only)\n")
    if args.scenario == "all":
        for name, fn in SCENARIOS.items():
            fn()
            time.sleep(2)
    else:
        SCENARIOS[args.scenario]()

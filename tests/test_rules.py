"""Detection rules tested against synthetic traffic with known answers.
Run with: pytest tests/ -v"""
from backend.detection import rules


def make_flow(src, dst, dport, proto="TCP", flags="ACK,PSH,SYN", pkts=1):
    return {"src_ip": src, "dst_ip": dst, "src_port": 55000,
            "dst_port": dport, "protocol": proto, "tcp_flags": flags,
            "packet_count": pkts, "byte_count": pkts * 64, "bucket_ts": 0}


# ---- port scan ----

def test_port_scan_fires_on_scan():
    """60 ports, all refused - must fire."""
    flows = []
    for port in range(1024, 1084):
        flows.append(make_flow("10.0.0.5", "10.0.0.1", port, flags="SYN"))
        flows.append(make_flow("10.0.0.5", "10.0.0.1", port, flags="ACK,RST"))
    found = rules.detect_port_scan(flows)
    assert len(found) == 1
    assert found[0]["src_ip"] == "10.0.0.5"
    assert found[0]["evidence"]["distinct_ports"] == 60


def test_port_scan_ignores_normal_browsing():
    """A few ports, all completed handshakes - must NOT fire."""
    flows = [
        make_flow("10.0.0.5", "93.184.216.34", 443, flags="ACK,PSH,SYN"),
        make_flow("10.0.0.5", "93.184.216.34", 80, flags="ACK,PSH,SYN"),
        make_flow("10.0.0.5", "1.1.1.1", 443, flags="ACK,PSH"),
    ]
    assert rules.detect_port_scan(flows) == []


def test_port_scan_ignores_high_ports_but_completed():
    """Many ports but low refusal ratio - not a scan (e.g. a busy client)."""
    flows = []
    for port in range(1024, 1044):
        flows.append(make_flow("10.0.0.5", "10.0.0.1", port, flags="ACK,PSH,SYN"))
    assert rules.detect_port_scan(flows) == []


# ---- connection burst ----

def test_burst_fires():
    # A flood is many distinct connection attempts to one port
    flows = [make_flow("10.0.0.9", "10.0.0.1", 80, flags="SYN")
             for _ in range(100)]
    found = rules.detect_connection_burst(flows)
    assert len(found) == 1
    assert found[0]["evidence"]["attempts"] == 100


def test_burst_ignores_normal():
    flows = [make_flow("10.0.0.9", "10.0.0.1", 80, flags="ACK,PSH,SYN", pkts=5)]
    assert rules.detect_connection_burst(flows) == []


# ---- dns exfil ----

def test_dns_exfil_fires_on_high_entropy():
    # Real exfil labels pack data to near the 63-char DNS limit
    dns = [{"src_ip": "10.0.0.5", "qname": lbl + ".exfil.com", "qtype": "1"}
           for lbl in ["a7f3k9d2m1x8q4w6r5t3y1u9j2h5g8f0d3s6a9z1",
                       "z8x7c6v5b4n3m2q1w9e8r7t6y5u4i3o2p1a0s9d8",
                       "p0o9i8u7y6t5r4e3w2q1a0s9d8f7g6h5j4k3l2m1",
                       "l1k2j3h4g5f6d7s8a9z0x1c2v3b4n5m6q7w8e9r0"]]
    found = rules.detect_dns_exfil(dns)
    assert len(found) == 1
    assert found[0]["evidence"]["suspicious_queries"] == 4


def test_dns_exfil_ignores_normal_names():
    dns = [{"src_ip": "10.0.0.5", "qname": q, "qtype": "1"}
           for q in ["www.google.com", "api.github.com", "cdn.spotify.com"]]
    assert rules.detect_dns_exfil(dns) == []


# ---- icmp sweep ----

def test_icmp_sweep_fires():
    flows = [make_flow("10.0.0.5", "10.0.0." + str(i), 0, proto="ICMP", flags="")
             for i in range(1, 15)]
    found = rules.detect_icmp_sweep(flows)
    assert len(found) == 1
    assert found[0]["evidence"]["distinct_hosts"] == 14


def test_icmp_sweep_ignores_few_hosts():
    flows = [make_flow("10.0.0.5", "10.0.0.1", 0, proto="ICMP", flags="")]
    assert rules.detect_icmp_sweep(flows) == []

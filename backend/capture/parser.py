"""Packet -> flat dict. Handles IPv4/IPv6, TCP flags, DNS names, TLS SNI."""
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet6 import ICMPv6ND_NS, ICMPv6ND_NA, ICMPv6ND_RA
from backend.config import PRIVATE_PREFIXES, PRIVATE_V6_PREFIXES

LOCAL_ADDRS = set()


def set_local_addresses(addrs):
    LOCAL_ADDRS.clear()
    LOCAL_ADDRS.update(a.lower() for a in addrs)

FLAG_MAP = {"F": "FIN", "S": "SYN", "R": "RST",
            "P": "PSH", "A": "ACK", "U": "URG"}


def is_local(ip, version):
    """Local = this machine's own address, or a private/link-local range."""
    if ip.lower() in LOCAL_ADDRS:
        return True
    if version == 4:
        return ip.startswith(PRIVATE_PREFIXES)
    low = ip.lower()
    return low.startswith(PRIVATE_V6_PREFIXES) or low.startswith("ff")


def classify_direction(src, dst, version):
    s, d = is_local(src, version), is_local(dst, version)
    if s and d:
        return "internal"
    if s:
        return "outbound"
    if d:
        return "inbound"
    return "external"


def extract_sni(payload):
    """Pull the hostname from a TLS ClientHello. None if not one."""
    try:
        if len(payload) < 45 or payload[0] != 0x16 or payload[5] != 0x01:
            return None
        i = 43
        i += 1 + payload[i]
        i += 2 + int.from_bytes(payload[i:i + 2], "big")
        i += 1 + payload[i]
        i += 2
        while i + 4 <= len(payload):
            ext_type = int.from_bytes(payload[i:i + 2], "big")
            ext_len = int.from_bytes(payload[i + 2:i + 4], "big")
            if ext_type == 0x0000:
                name_len = int.from_bytes(payload[i + 7:i + 9], "big")
                return payload[i + 9:i + 9 + name_len].decode("ascii", "ignore")
            i += 4 + ext_len
    except (IndexError, ValueError):
        pass
    return None


def parse(pkt):
    if IP in pkt:
        layer, version = pkt[IP], 4
    elif IPv6 in pkt:
        layer, version = pkt[IPv6], 6
    else:
        return None

    rec = {
        "ts": float(pkt.time),
        "src_mac": pkt[Ether].src if Ether in pkt else None,
        "src_ip": layer.src,
        "dst_ip": layer.dst,
        "ip_version": version,
        "src_port": None,
        "dst_port": None,
        "protocol": "OTHER",
        "length": len(pkt),
        "flags": "",
        "sni": None,
        "dns": None,
        "info": "",
    }

    if TCP in pkt:
        t = pkt[TCP]
        rec.update(protocol="TCP", src_port=int(t.sport), dst_port=int(t.dport))
        rec["flags"] = ",".join(FLAG_MAP[c] for c in str(t.flags) if c in FLAG_MAP)
        rec["info"] = "[" + rec["flags"] + "]"
        if t.dport == 443 and hasattr(t.payload, "load"):
            rec["sni"] = extract_sni(bytes(t.payload.load))
            if rec["sni"]:
                rec["info"] = "ClientHello " + rec["sni"]

    elif UDP in pkt:
        u = pkt[UDP]
        rec.update(protocol="UDP", src_port=int(u.sport), dst_port=int(u.dport))
        if u.dport == 443 or u.sport == 443:
            rec.update(protocol="QUIC", info="QUIC / HTTP3")
        if DNS in pkt and pkt[DNS].qr == 0 and pkt[DNS].qdcount > 0:
            q = pkt[DNSQR]
            rec["dns"] = {
                "qname": q.qname.decode("ascii", "ignore").rstrip("."),
                "qtype": str(q.qtype),
            }
            rec["info"] = "DNS query " + rec["dns"]["qname"]

    elif ICMP in pkt:
        rec.update(protocol="ICMP", info="ICMP type=" + str(pkt[ICMP].type))

    elif version == 6 and layer.nh == 58:
        rec["protocol"] = "ICMPv6"
        if ICMPv6ND_NS in pkt:
            rec["info"] = "Neighbor Solicitation"
        elif ICMPv6ND_NA in pkt:
            rec["info"] = "Neighbor Advertisement"
        elif ICMPv6ND_RA in pkt:
            rec["info"] = "Router Advertisement"
        else:
            rec["info"] = "ICMPv6"

    rec["direction"] = classify_direction(rec["src_ip"], rec["dst_ip"], version)
    return rec

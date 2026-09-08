"""Central configuration. Everything tunable lives here."""
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "data" / "traffic.db"

INTERFACE = "en0"
BPF_FILTER = "tcp or udp or icmp or icmp6"
PROMISCUOUS = True

BUCKET_SECONDS = 10
RECENT_PACKET_LIMIT = 2000

PRIVATE_PREFIXES = ("10.", "192.168.", "172.16.", "172.17.", "172.18.",
                    "172.19.", "172.20.", "172.21.", "172.22.", "172.23.",
                    "172.24.", "172.25.", "172.26.", "172.27.", "172.28.",
                    "172.29.", "172.30.", "172.31.", "127.", "169.254.")
# IPv6: link-local (fe80::), unique-local (fc00::/fd00::), loopback
PRIVATE_V6_PREFIXES = ("fe80:", "fc", "fd", "::1")

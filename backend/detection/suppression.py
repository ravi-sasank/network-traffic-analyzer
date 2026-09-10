"""Alert suppression: allowlists for known-good sources, and a cooldown so
one ongoing incident produces one alert instead of one per flush cycle.

Turns a noisy detector into a usable one. Without cooldown, a scan spanning
three 10s buckets fires three times; with it, once."""
import time
import ipaddress

# Sources we never alert on. Gateways, multicast, and link-local do bursty,
# scan-shaped things as normal behaviour.
ALLOWLIST_EXACT = set()          # filled at startup with the gateway IP

ALLOWLIST_PREFIXES = (
    "224.",        # IPv4 multicast
    "239.",        # IPv4 local multicast (mDNS, SSDP)
    "255.",        # broadcast
    "ff02:",       # IPv6 link-local multicast
    "ff0",         # IPv6 multicast range
    "169.254.",    # link-local
    "fe80:",       # IPv6 link-local
)

# Per (rule, source) minimum seconds between alerts for the same incident
COOLDOWN_SECONDS = 300


class Suppressor:
    def __init__(self, gateway_ip=None):
        self._last_alert = {}          # (rule, src) -> last emit time
        self._suppressed_count = {}     # (rule, src) -> repeats hidden
        if gateway_ip:
            ALLOWLIST_EXACT.add(gateway_ip)

    def is_allowlisted(self, ip):
        if ip is None:
            return False
        if ip in ALLOWLIST_EXACT:
            return True
        low = ip.lower()
        return low.startswith(ALLOWLIST_PREFIXES)

    def should_emit(self, rule_name, src_ip):
        """True if this finding should become an alert now.

        Returns False when the source is allowlisted, or when an identical
        (rule, source) alert fired within the cooldown window."""
        if self.is_allowlisted(src_ip):
            return False

        key = (rule_name, src_ip)
        now = time.time()
        last = self._last_alert.get(key)

        if last is not None and (now - last) < COOLDOWN_SECONDS:
            self._suppressed_count[key] = self._suppressed_count.get(key, 0) + 1
            return False

        self._last_alert[key] = now
        return True

    def suppressed_repeats(self, rule_name, src_ip):
        """How many repeats have been folded into the current alert."""
        return self._suppressed_count.get((rule_name, src_ip), 0)

    def reset_incident(self, rule_name, src_ip):
        """Call when an incident clears, so a fresh recurrence alerts again."""
        key = (rule_name, src_ip)
        self._last_alert.pop(key, None)
        self._suppressed_count.pop(key, None)


def detect_gateway():
    """Best-effort gateway IP from the routing table, for the allowlist."""
    import subprocess
    try:
        out = subprocess.run(["route", "-n", "get", "default"],
                             capture_output=True, text=True, timeout=5).stdout
        for line in out.splitlines():
            if "gateway:" in line:
                return line.split(":")[1].strip()
    except (subprocess.SubprocessError, OSError, IndexError):
        pass
    return None

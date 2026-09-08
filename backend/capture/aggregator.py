"""Aggregate packets into fixed time buckets keyed on the 5-tuple."""
from collections import defaultdict
from backend.config import BUCKET_SECONDS


class FlowAggregator:
    def __init__(self):
        self.buckets = defaultdict(lambda: {
            "packet_count": 0, "byte_count": 0, "flags": set(), "sni": None,
        })
        self.current_bucket = None

    @staticmethod
    def _align(ts):
        return int(ts // BUCKET_SECONDS) * BUCKET_SECONDS

    def add(self, rec):
        """Returns completed flow rows when the bucket rolls over."""
        bucket_ts = self._align(rec["ts"])
        completed = []

        if self.current_bucket is None:
            self.current_bucket = bucket_ts
        elif bucket_ts > self.current_bucket:
            completed = self.flush()
            self.current_bucket = bucket_ts

        key = (bucket_ts, rec["src_ip"], rec["dst_ip"], rec["src_port"],
               rec["dst_port"], rec["protocol"], rec["ip_version"],
               rec["direction"])

        b = self.buckets[key]
        b["packet_count"] += 1
        b["byte_count"] += rec["length"]
        if rec["flags"]:
            b["flags"].update(rec["flags"].split(","))
        if rec["sni"] and not b["sni"]:
            b["sni"] = rec["sni"]

        return completed

    def flush(self):
        rows = []
        for key, b in self.buckets.items():
            (bucket_ts, src_ip, dst_ip, sport, dport,
             proto, version, direction) = key
            rows.append({
                "bucket_ts": bucket_ts,
                "src_ip": src_ip, "dst_ip": dst_ip,
                "src_port": sport, "dst_port": dport,
                "protocol": proto, "ip_version": version,
                "packet_count": b["packet_count"],
                "byte_count": b["byte_count"],
                "tcp_flags": ",".join(sorted(b["flags"])) if b["flags"] else None,
                "sni": b["sni"], "direction": direction,
            })
        self.buckets.clear()
        return rows

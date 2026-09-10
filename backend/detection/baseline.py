"""Per-host statistical baseline. Learns each device's normal byte/connection
volume with an EWMA, then flags deviations by z-score.

Catches volume anomalies that signature rules can't express - a host suddenly
sending 10x its usual traffic - and every flag is explainable ('N sigma above
this host's average'), unlike a black-box model.

Warm-up gating: no flagging until a host has been observed enough times, so
the cold-start period doesn't fire on everything."""
import math
from collections import defaultdict

EWMA_ALPHA = 0.3          # weight on newest sample; higher = faster adaption
WARMUP_SAMPLES = 6         # minutes of observation before flagging (60s buckets)
Z_THRESHOLD = 3.5          # standard deviations to flag


class HostBaseline:
    """Running mean + variance for one metric on one host (Welford/EWMA hybrid)."""
    def __init__(self):
        self.mean = 0.0
        self.var = 0.0
        self.n = 0

    def update(self, x):
        self.n += 1
        if self.n == 1:
            self.mean = x
            return
        old_mean = self.mean
        self.mean += EWMA_ALPHA * (x - self.mean)
        # EWMA variance of residual
        self.var = (1 - EWMA_ALPHA) * (self.var + EWMA_ALPHA * (x - old_mean) ** 2)

    def zscore(self, x):
        if self.n < 2 or self.var <= 0:
            return 0.0
        return (x - self.mean) / math.sqrt(self.var)

    def warm(self):
        return self.n >= WARMUP_SAMPLES


class BaselineEngine:
    def __init__(self):
        self.bytes_bl = defaultdict(HostBaseline)
        self.conns_bl = defaultdict(HostBaseline)

    def observe_and_check(self, host, bytes_this_min, conns_this_min):
        """Feed one minute of a host's activity. Returns a finding if the
        host is warmed up and this minute deviates sharply, else None."""
        bb = self.bytes_bl[host]
        cb = self.conns_bl[host]

        z_bytes = bb.zscore(bytes_this_min) if bb.warm() else 0.0
        z_conns = cb.zscore(conns_this_min) if cb.warm() else 0.0

        # update AFTER scoring, so a spike is measured against prior normal
        bb.update(bytes_this_min)
        cb.update(conns_this_min)

        finding = None
        if z_bytes >= Z_THRESHOLD:
            finding = {
                "rule_name": "volume_anomaly",
                "src_ip": host, "dst_ip": None,
                "reason": (host + " transferred " + _human(bytes_this_min)
                           + " this minute - " + str(round(z_bytes, 1))
                           + " sigma above its own average of "
                           + _human(bb.mean)),
                "evidence": {"bytes": bytes_this_min, "z_score": round(z_bytes, 2),
                             "baseline_mean": round(bb.mean, 1)},
            }
        elif z_conns >= Z_THRESHOLD:
            finding = {
                "rule_name": "connection_anomaly",
                "src_ip": host, "dst_ip": None,
                "reason": (host + " opened " + str(conns_this_min)
                           + " connections this minute - " + str(round(z_conns, 1))
                           + " sigma above its average of "
                           + str(round(cb.mean, 1))),
                "evidence": {"connections": conns_this_min,
                             "z_score": round(z_conns, 2)},
            }
        return finding

    def warm_hosts(self):
        return sum(1 for b in self.bytes_bl.values() if b.warm())


def _human(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return str(round(n, 1)) + unit
        n /= 1024
    return str(round(n, 1)) + "TB"

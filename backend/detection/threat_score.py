"""Per-device threat scoring - the SOC risk board.

Each device carries a 0-100 score. Findings push it up (weighted by severity);
time pulls it down (exponential decay), so the board shows CURRENT risk, not a
permanent record. This is what turns a flat alert list into a live risk view."""
import time
import math

# Half-life: score halves every N seconds with no new activity
DECAY_HALFLIFE = 600          # 10 minutes
MAX_SCORE = 100

# Threat tiers for the dashboard
TIERS = [
    (80, "critical"),
    (55, "high"),
    (30, "elevated"),
    (10, "guarded"),
    (0,  "normal"),
]


class ThreatScorer:
    def __init__(self):
        # host -> {"score": float, "last_update": ts, "contributors": [...]}
        self._hosts = {}

    def _decay(self, host, now):
        """Apply time decay since the host's last update."""
        h = self._hosts[host]
        elapsed = now - h["last_update"]
        if elapsed > 0:
            factor = math.pow(0.5, elapsed / DECAY_HALFLIFE)
            h["score"] *= factor
            h["last_update"] = now

    def add_finding(self, finding):
        """Raise a host's score based on a scored finding."""
        host = finding.get("src_ip")
        if not host:
            return
        now = time.time()

        if host not in self._hosts:
            self._hosts[host] = {"score": 0.0, "last_update": now,
                                 "contributors": []}
        self._decay(host, now)

        h = self._hosts[host]
        # each finding contributes a fraction of its severity score
        h["score"] = min(MAX_SCORE, h["score"] + finding.get("score", 0) * 0.6)
        h["last_update"] = now
        h["contributors"].append({
            "rule": finding["rule_name"],
            "severity": finding.get("severity", "low"),
            "ts": now,
            "reason": finding.get("reason", ""),
        })
        # keep only the last 10 contributors per host
        h["contributors"] = h["contributors"][-10:]

    def current(self, host):
        """Decayed score for one host, right now."""
        if host not in self._hosts:
            return 0.0
        self._decay(host, time.time())
        return round(self._hosts[host]["score"], 1)

    def tier(self, score):
        for floor, name in TIERS:
            if score >= floor:
                return name
        return "normal"

    def board(self):
        """All hosts, decayed and sorted by current risk - what the UI renders."""
        now = time.time()
        rows = []
        for host in list(self._hosts):
            self._decay(host, now)
            score = round(self._hosts[host]["score"], 1)
            rows.append({
                "host": host,
                "score": score,
                "tier": self.tier(score),
                "recent": self._hosts[host]["contributors"][-3:],
            })
        rows.sort(key=lambda r: r["score"], reverse=True)
        return rows

"""Assign severity and a 0-100 score to each finding.

Base severity is per-rule (a port scan is inherently more serious than a
single anomaly), then escalated by how far the evidence exceeds the threshold.
The numeric score feeds the per-device threat board."""

# Base severity per rule: (level, base_score)
BASE = {
    "port_scan":          ("high",     60),
    "connection_burst":   ("high",     65),
    "dns_exfil":          ("critical", 80),
    "icmp_sweep":         ("medium",   45),
    "volume_anomaly":     ("medium",   40),
    "connection_anomaly": ("medium",   40),
}

LEVELS = ["low", "medium", "high", "critical"]
LEVEL_FLOOR = {"low": 20, "medium": 40, "high": 60, "critical": 80}


def _escalate(level, steps):
    """Bump a severity level up by `steps`, capped at critical."""
    i = min(len(LEVELS) - 1, LEVELS.index(level) + steps)
    return LEVELS[i]


def score_finding(finding):
    """Attach 'severity' and 'score' (0-100) to a finding in place.
    Returns the same dict for convenience."""
    rule = finding["rule_name"]
    level, base = BASE.get(rule, ("low", 20))
    ev = finding.get("evidence", {})
    bump = 0

    if rule == "port_scan":
        ports = ev.get("distinct_ports", 0)
        if ports >= 100:
            bump = 2
        elif ports >= 40:
            bump = 1
    elif rule == "connection_burst":
        if ev.get("attempts", 0) >= 500:
            bump = 1
    elif rule in ("volume_anomaly", "connection_anomaly"):
        z = ev.get("z_score", 0)
        if z >= 10:
            bump = 2
        elif z >= 6:
            bump = 1
    elif rule == "dns_exfil":
        if ev.get("suspicious_queries", 0) >= 20:
            bump = 1

    level = _escalate(level, bump)
    score = min(100, base + bump * 15)

    finding["severity"] = level
    finding["score"] = score
    return finding


def severity_color(level):
    """For the dashboard - semantic, not decorative."""
    return {"low": "#3b82f6", "medium": "#f59e0b",
            "high": "#f97316", "critical": "#ef4444"}.get(level, "#6b7280")

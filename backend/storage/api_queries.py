"""Read-only queries for the API layer. Separate from queries.py (which the
capture process uses to write) so the read and write paths stay clean."""
import json
import time
from collections import defaultdict


def _rows(cur):
    return [dict(r) for r in cur.fetchall()]


def get_stats(conn):
    """Top-line numbers for the dashboard header."""
    now = int(time.time())
    hour_ago = now - 3600
    flows = conn.execute("SELECT COUNT(*) c, COALESCE(SUM(byte_count),0) b, "
                         "COALESCE(SUM(packet_count),0) p FROM flows "
                         "WHERE bucket_ts >= ?", (hour_ago,)).fetchone()
    alerts = conn.execute("SELECT COUNT(*) c FROM alerts WHERE ts >= ?",
                         (hour_ago,)).fetchone()
    devices = conn.execute("SELECT COUNT(DISTINCT src_ip) c FROM flows "
                          "WHERE bucket_ts >= ?", (hour_ago,)).fetchone()
    return {
        "flows_last_hour": flows["c"],
        "bytes_last_hour": flows["b"],
        "packets_last_hour": flows["p"],
        "alerts_last_hour": alerts["c"],
        "active_devices": devices["c"],
    }


def get_alerts(conn, limit=100, severity=None):
    q = "SELECT * FROM alerts"
    params = []
    if severity:
        q += " WHERE severity = ?"
        params.append(severity)
    q += " ORDER BY id DESC LIMIT ?"
    params.append(limit)
    rows = _rows(conn.execute(q, params))
    for r in rows:
        if r.get("evidence"):
            try:
                r["evidence"] = json.loads(r["evidence"])
            except (ValueError, TypeError):
                pass
    return rows


def get_alerts_since(conn, since_id):
    """New alerts after a given id - for WebSocket incremental push."""
    rows = _rows(conn.execute(
        "SELECT * FROM alerts WHERE id > ? ORDER BY id ASC", (since_id,)))
    for r in rows:
        if r.get("evidence"):
            try:
                r["evidence"] = json.loads(r["evidence"])
            except (ValueError, TypeError):
                pass
    return rows


def get_protocol_breakdown(conn):
    """Traffic by protocol in the last hour - for the donut chart."""
    hour_ago = int(time.time()) - 3600
    return _rows(conn.execute(
        "SELECT protocol, COUNT(*) flows, SUM(byte_count) bytes "
        "FROM flows WHERE bucket_ts >= ? GROUP BY protocol "
        "ORDER BY bytes DESC", (hour_ago,)))


def get_traffic_timeline(conn, minutes=30):
    """Bytes per minute over the last N minutes - for the live line chart."""
    since = int(time.time()) - minutes * 60
    rows = _rows(conn.execute(
        "SELECT (bucket_ts/60)*60 minute, SUM(byte_count) bytes, "
        "SUM(packet_count) packets FROM flows WHERE bucket_ts >= ? "
        "GROUP BY minute ORDER BY minute", (since,)))
    return rows


def get_top_talkers(conn, limit=10):
    """Busiest hosts by bytes in the last hour - for the device table."""
    hour_ago = int(time.time()) - 3600
    return _rows(conn.execute(
        "SELECT src_ip, COUNT(*) flows, SUM(byte_count) bytes, "
        "COUNT(DISTINCT dst_ip) peers FROM flows WHERE bucket_ts >= ? "
        "GROUP BY src_ip ORDER BY bytes DESC LIMIT ?", (hour_ago, limit)))


def get_recent_packets(conn, limit=100):
    """Latest raw packets - for the packet inspector view."""
    return _rows(conn.execute(
        "SELECT * FROM packets_recent ORDER BY id DESC LIMIT ?", (limit,)))


def get_top_domains(conn, limit=15):
    """Most-queried DNS names - for the domain panel."""
    hour_ago = time.time() - 3600
    return _rows(conn.execute(
        "SELECT qname, COUNT(*) n FROM dns_queries WHERE ts >= ? "
        "GROUP BY qname ORDER BY n DESC LIMIT ?", (hour_ago, limit)))


# ---- threat board recomputed from stored alerts ----

DECAY_HALFLIFE = 600
SEVERITY_WEIGHT = {"low": 20, "medium": 40, "high": 60, "critical": 80}


def get_threat_board(conn):
    """Rebuild the per-device risk board from recent alerts, applying the
    same time-decay the live engine uses. Reading from the DB means the board
    survives a capture restart and can never show an alert that didn't fire."""
    import math
    now = time.time()
    since = now - 3600
    alerts = _rows(conn.execute(
        "SELECT ts, severity, src_ip, rule_name, reason FROM alerts "
        "WHERE ts >= ? AND src_ip IS NOT NULL ORDER BY ts ASC", (since,)))

    hosts = defaultdict(lambda: {"score": 0.0, "recent": []})
    for a in alerts:
        h = hosts[a["src_ip"]]
        weight = SEVERITY_WEIGHT.get(a["severity"], 20) * 0.6
        h["score"] = min(100, h["score"] + weight)
        h["recent"].append({"rule": a["rule_name"], "severity": a["severity"],
                            "reason": a["reason"], "ts": a["ts"]})

    board = []
    for host, h in hosts.items():
        # decay from the most recent alert to now
        last_ts = h["recent"][-1]["ts"]
        elapsed = now - last_ts
        score = h["score"] * math.pow(0.5, elapsed / DECAY_HALFLIFE)
        board.append({
            "host": host,
            "score": round(score, 1),
            "tier": _tier(score),
            "alert_count": len(h["recent"]),
            "recent": h["recent"][-3:],
        })
    board.sort(key=lambda r: r["score"], reverse=True)
    return board


def _tier(score):
    for floor, name in [(80, "critical"), (55, "high"),
                        (30, "elevated"), (10, "guarded"), (0, "normal")]:
        if score >= floor:
            return name
    return "normal"

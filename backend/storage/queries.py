"""All SQL lives here. Nothing else in the codebase writes a query."""
import json
from backend.config import RECENT_PACKET_LIMIT


def insert_flows(conn, rows):
    if not rows:
        return
    conn.executemany("""
        INSERT INTO flows (bucket_ts, src_ip, dst_ip, src_port, dst_port,
                           protocol, ip_version, packet_count, byte_count,
                           tcp_flags, sni, direction)
        VALUES (:bucket_ts, :src_ip, :dst_ip, :src_port, :dst_port,
                :protocol, :ip_version, :packet_count, :byte_count,
                :tcp_flags, :sni, :direction)
    """, rows)
    conn.commit()


def insert_recent_packets(conn, rows):
    if not rows:
        return
    conn.executemany("""
        INSERT INTO packets_recent (ts, src_ip, dst_ip, src_port,
                                    dst_port, protocol, length, info)
        VALUES (:ts, :src_ip, :dst_ip, :src_port, :dst_port,
                :protocol, :length, :info)
    """, rows)
    conn.execute("""
        DELETE FROM packets_recent WHERE id NOT IN (
            SELECT id FROM packets_recent ORDER BY id DESC LIMIT ?
        )
    """, (RECENT_PACKET_LIMIT,))
    conn.commit()


def insert_dns(conn, rows):
    if not rows:
        return
    conn.executemany("""
        INSERT INTO dns_queries (ts, src_ip, qname, qtype, resolved)
        VALUES (:ts, :src_ip, :qname, :qtype, :resolved)
    """, rows)
    conn.commit()


def upsert_devices(conn, rows):
    if not rows:
        return
    conn.executemany("""
        INSERT INTO devices (mac, ip, first_seen, last_seen, total_bytes)
        VALUES (:mac, :ip, :ts, :ts, :bytes)
        ON CONFLICT(mac) DO UPDATE SET
            ip = excluded.ip,
            last_seen = excluded.last_seen,
            total_bytes = total_bytes + excluded.total_bytes
    """, rows)
    conn.commit()


def insert_alert(conn, ts, rule_name, severity, src_ip, dst_ip, reason, evidence):
    conn.execute("""
        INSERT INTO alerts (ts, rule_name, severity, src_ip, dst_ip, reason, evidence)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (ts, rule_name, severity, src_ip, dst_ip, reason, json.dumps(evidence)))
    conn.commit()


def recent_flows(conn, since_ts):
    return conn.execute(
        "SELECT * FROM flows WHERE bucket_ts >= ? ORDER BY bucket_ts", (since_ts,)
    ).fetchall()

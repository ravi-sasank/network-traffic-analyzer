"""SQLite connection + schema. WAL lets the capture process write
while the API reads, without locking."""
import sqlite3
from backend.config import DB_PATH

SCHEMA = """
CREATE TABLE IF NOT EXISTS flows (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    bucket_ts    INTEGER NOT NULL,
    src_ip       TEXT NOT NULL,
    dst_ip       TEXT NOT NULL,
    src_port     INTEGER,
    dst_port     INTEGER,
    protocol     TEXT NOT NULL,
    ip_version   INTEGER,
    packet_count INTEGER NOT NULL,
    byte_count   INTEGER NOT NULL,
    tcp_flags    TEXT,
    sni          TEXT,
    direction    TEXT
);
CREATE INDEX IF NOT EXISTS idx_flows_ts  ON flows(bucket_ts);
CREATE INDEX IF NOT EXISTS idx_flows_src ON flows(src_ip);

CREATE TABLE IF NOT EXISTS alerts (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        INTEGER NOT NULL,
    rule_name TEXT NOT NULL,
    severity  TEXT NOT NULL,
    src_ip    TEXT,
    dst_ip    TEXT,
    reason    TEXT NOT NULL,
    evidence  TEXT
);
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts);

CREATE TABLE IF NOT EXISTS devices (
    mac         TEXT PRIMARY KEY,
    ip          TEXT,
    hostname    TEXT,
    vendor      TEXT,
    first_seen  INTEGER,
    last_seen   INTEGER,
    total_bytes INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS packets_recent (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    ts       REAL NOT NULL,
    src_ip   TEXT, dst_ip TEXT,
    src_port INTEGER, dst_port INTEGER,
    protocol TEXT, length INTEGER, info TEXT
);

CREATE TABLE IF NOT EXISTS dns_queries (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    ts       REAL NOT NULL,
    src_ip   TEXT,
    qname    TEXT,
    qtype    TEXT,
    resolved TEXT
);
"""


def get_connection():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=10, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    return conn


def init_db():
    conn = get_connection()
    conn.executescript(SCHEMA)
    conn.commit()
    return conn

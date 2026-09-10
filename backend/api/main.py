"""FastAPI app: REST endpoints for dashboard state + a WebSocket that pushes
live alerts and threat-board updates. Reads only from SQLite, so it runs
unprivileged and survives the capture process restarting."""
import asyncio
import json

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from backend.storage.db import get_connection
from backend.storage import api_queries as aq

app = FastAPI(title="Network Traffic Analyzer API", version="1.0")

# Allow the Vite dev server to call us during development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)


def db():
    return get_connection()


@app.get("/api/health")
def health():
    return {"status": "ok"}


@app.get("/api/stats")
def stats():
    conn = db()
    try:
        return aq.get_stats(conn)
    finally:
        conn.close()


@app.get("/api/alerts")
def alerts(limit: int = 100, severity: str = None):
    conn = db()
    try:
        return aq.get_alerts(conn, limit=limit, severity=severity)
    finally:
        conn.close()


@app.get("/api/threat-board")
def threat_board():
    conn = db()
    try:
        return aq.get_threat_board(conn)
    finally:
        conn.close()


@app.get("/api/protocols")
def protocols():
    conn = db()
    try:
        return aq.get_protocol_breakdown(conn)
    finally:
        conn.close()


@app.get("/api/timeline")
def timeline(minutes: int = 30):
    conn = db()
    try:
        return aq.get_traffic_timeline(conn, minutes=minutes)
    finally:
        conn.close()


@app.get("/api/top-talkers")
def top_talkers(limit: int = 10):
    conn = db()
    try:
        return aq.get_top_talkers(conn, limit=limit)
    finally:
        conn.close()


@app.get("/api/packets")
def packets(limit: int = 100):
    conn = db()
    try:
        return aq.get_recent_packets(conn, limit=limit)
    finally:
        conn.close()


@app.get("/api/domains")
def domains(limit: int = 15):
    conn = db()
    try:
        return aq.get_top_domains(conn, limit=limit)
    finally:
        conn.close()


@app.websocket("/ws/live")
async def ws_live(ws: WebSocket):
    """Push new alerts + refreshed threat board every 2s. The client sends
    nothing; it just receives a stream of updates."""
    await ws.accept()
    conn = db()
    last_alert_id = conn.execute(
        "SELECT COALESCE(MAX(id), 0) m FROM alerts").fetchone()["m"]
    try:
        while True:
            new_alerts = aq.get_alerts_since(conn, last_alert_id)
            if new_alerts:
                last_alert_id = new_alerts[-1]["id"]
            payload = {
                "new_alerts": new_alerts,
                "threat_board": aq.get_threat_board(conn),
                "stats": aq.get_stats(conn),
            }
            await ws.send_text(json.dumps(payload, default=str))
            await asyncio.sleep(2)
    except WebSocketDisconnect:
        pass
    finally:
        conn.close()

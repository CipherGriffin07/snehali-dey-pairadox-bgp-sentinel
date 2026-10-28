
import json
import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).parent / "data" / "sentinel.db"
DB_PATH.parent.mkdir(exist_ok=True)

def connect():
    return sqlite3.connect(DB_PATH)

def initialize():
    with connect() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS announcements (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                prefix TEXT NOT NULL,
                origin_asn INTEGER NOT NULL,
                timestamp TEXT NOT NULL
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                payload TEXT NOT NULL
            )
        """)

def save_announcement(prefix, origin_asn, timestamp):
    with connect() as db:
        db.execute(
            "INSERT INTO announcements(prefix, origin_asn, timestamp) VALUES (?, ?, ?)",
            (prefix, origin_asn, timestamp)
        )

def save_alert(alert):
    with connect() as db:
        db.execute(
            "INSERT INTO alerts(payload) VALUES (?)",
            (json.dumps(alert),)
        )

def load_announcements():
    with connect() as db:
        return db.execute(
            "SELECT prefix, origin_asn FROM announcements ORDER BY id"
        ).fetchall()

def load_alerts():
    with connect() as db:
        rows = db.execute(
            "SELECT payload FROM alerts ORDER BY id"
        ).fetchall()
        return [json.loads(row[0]) for row in rows]

def clear():
    with connect() as db:
        db.execute("DELETE FROM announcements")
        db.execute("DELETE FROM alerts")

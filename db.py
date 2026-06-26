import sqlite3
import json
from datetime import datetime
from detections.rules import Finding

DB_PATH = "tracex.db"


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = _connect()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS runs (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            source_file    TEXT NOT NULL,
            run_at         TEXT NOT NULL,
            total_events   INTEGER,
            total_findings INTEGER
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id          INTEGER NOT NULL REFERENCES runs(id),
            rule_name       TEXT NOT NULL,
            severity        TEXT NOT NULL,
            score           INTEGER NOT NULL,
            description     TEXT NOT NULL,
            event_ids       TEXT NOT NULL,
            mitre_technique TEXT,
            mitre_name      TEXT,
            run_at          TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()


def _finding_exists(conn, rule_name: str, description: str, source_file: str) -> bool:
    row = conn.execute(
        """SELECT 1 FROM findings f
           JOIN runs r ON f.run_id = r.id
           WHERE f.rule_name = ? AND f.description = ? AND r.source_file = ?""",
        (rule_name, description, source_file)
    ).fetchone()
    return row is not None


def save_run(source_file: str, total_events: int, scored_findings: list, mitre_map: dict) -> int:
    conn = _connect()
    run_at = datetime.utcnow().isoformat()

    cursor = conn.execute(
        "INSERT INTO runs (source_file, run_at, total_events, total_findings) VALUES (?, ?, ?, ?)",
        (source_file, run_at, total_events, len(scored_findings))
    )
    run_id = cursor.lastrowid

    for finding, score in scored_findings:
        if _finding_exists(conn, finding.rule_name, finding.description, source_file):
            continue
        mitre = mitre_map.get(finding.rule_name, {})
        conn.execute(
            """INSERT INTO findings
               (run_id, rule_name, severity, score, description, event_ids,
                mitre_technique, mitre_name, run_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                run_id,
                finding.rule_name,
                finding.severity,
                score,
                finding.description,
                json.dumps(finding.event_ids_involved),
                mitre.get("technique_id"),
                mitre.get("technique_name"),
                run_at,
            )
        )

    conn.commit()
    conn.close()
    return run_id


def load_findings(days: int = None) -> list:
    conn = _connect()
    if days is None:
        rows = conn.execute("SELECT * FROM findings ORDER BY run_at DESC").fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM findings WHERE run_at >= datetime('now', ?) ORDER BY run_at DESC",
            (f"-{days} days",)
        ).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def load_runs() -> list:
    conn = _connect()
    rows = conn.execute("SELECT * FROM runs ORDER BY run_at DESC").fetchall()
    conn.close()
    return [dict(row) for row in rows]
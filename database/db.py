"""
Database utility module for Digital Time Machine.
Provides connection management, schema initialization, and transactional queries.
"""

import sqlite3
import os
from pathlib import Path

SCHEMA_PATH = Path(__file__).parent / "schema.sql"

def get_db_connection(db_path: str) -> sqlite3.Connection:
    """Creates a connection to SQLite database with dictionary-like row access."""
    # Ensure parent directory exists
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn

def init_db(db_path: str):
    """Initializes the database using the schema.sql file."""
    conn = get_db_connection(db_path)
    with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
        schema_sql = f.read()
    conn.executescript(schema_sql)
    conn.commit()
    conn.close()

def query_all(conn: sqlite3.Connection, sql: str, params: tuple = ()) -> list[dict]:
    """Execute query and return list of dictionaries."""
    cur = conn.execute(sql, params)
    rows = cur.fetchall()
    return [dict(row) for row in rows]

def query_one(conn: sqlite3.Connection, sql: str, params: tuple = ()) -> dict | None:
    """Execute query and return single dictionary or None."""
    cur = conn.execute(sql, params)
    row = cur.fetchone()
    return dict(row) if row else None

def execute_write(conn: sqlite3.Connection, sql: str, params: tuple = ()) -> int:
    """Execute INSERT/UPDATE/DELETE and return lastrowid or affected rows."""
    cur = conn.execute(sql, params)
    conn.commit()
    return cur.lastrowid


"""
database.py - SQLite schema and CRUD operations for BountyLedger.

Tables:
- sinks: Tracks potential vulnerability surface areas
- tests: Tracks specific test attempts on sinks
"""

import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Optional
from enum import Enum


class RiskLevel(str, Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class TestStatus(str, Enum):
    PENDING = "PENDING"
    HIT = "HIT"
    CLOSED = "CLOSED"


class PayloadType(str, Enum):
    DIRECT = "Direct"
    REDIRECT_302 = "Redirect-302"
    REDIRECT_307 = "Redirect-307"
    DNS_REBIND = "DNS-Rebind"


# Default database path
DB_PATH = Path(__file__).parent.parent / "bountyledger.db"


def get_connection(db_path: Optional[Path] = None) -> sqlite3.Connection:
    """Get a database connection with Row factory enabled."""
    path = db_path or DB_PATH
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(db_path: Optional[Path] = None) -> None:
    """Initialize the database schema."""
    conn = get_connection(db_path)
    cursor = conn.cursor()
    
    # Create sinks table - tracks the attack surface
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS sinks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            surface_name TEXT NOT NULL,
            param_name TEXT NOT NULL,
            method TEXT DEFAULT 'GET' CHECK(method IN ('GET', 'POST', 'PUT', 'DELETE', 'PATCH')),
            risk_level TEXT DEFAULT 'Medium' CHECK(risk_level IN ('Low', 'Medium', 'High', 'Critical')),
            notes TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(surface_name, param_name, method)
        )
    """)
    
    # Create tests table - tracks test attempts
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS tests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sink_id INTEGER NOT NULL,
            canary_uuid TEXT NOT NULL UNIQUE,
            payload_type TEXT DEFAULT 'Direct' CHECK(payload_type IN ('Direct', 'Redirect-302', 'Redirect-307', 'DNS-Rebind')),
            target_url TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            status TEXT DEFAULT 'PENDING' CHECK(status IN ('PENDING', 'HIT', 'CLOSED')),
            hit_timestamp TIMESTAMP,
            notes TEXT,
            FOREIGN KEY (sink_id) REFERENCES sinks(id) ON DELETE CASCADE
        )
    """)
    
    # Create indexes for common queries
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_sinks_surface ON sinks(surface_name)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_tests_status ON tests(status)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_tests_uuid ON tests(canary_uuid)")
    
    conn.commit()
    conn.close()


# ============================================================================
# SINK CRUD Operations
# ============================================================================

def add_sink(
    surface_name: str,
    param_name: str,
    method: str = "GET",
    risk_level: str = "Medium",
    notes: Optional[str] = None,
    db_path: Optional[Path] = None
) -> int:
    """Add a new sink to the database. Returns the sink ID."""
    conn = get_connection(db_path)
    cursor = conn.cursor()
    
    cursor.execute("""
        INSERT INTO sinks (surface_name, param_name, method, risk_level, notes)
        VALUES (?, ?, ?, ?, ?)
    """, (surface_name, param_name, method.upper(), risk_level, notes))
    
    sink_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    return sink_id


def get_sink(sink_id: int, db_path: Optional[Path] = None) -> Optional[dict]:
    """Get a single sink by ID."""
    conn = get_connection(db_path)
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM sinks WHERE id = ?", (sink_id,))
    row = cursor.fetchone()
    conn.close()
    
    return dict(row) if row else None


def get_all_sinks(db_path: Optional[Path] = None) -> list[dict]:
    """Get all sinks ordered by creation date."""
    conn = get_connection(db_path)
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM sinks ORDER BY created_at DESC")
    rows = cursor.fetchall()
    conn.close()
    
    return [dict(row) for row in rows]


def delete_sink(sink_id: int, db_path: Optional[Path] = None) -> bool:
    """Delete a sink and its associated tests. Returns True if deleted."""
    conn = get_connection(db_path)
    cursor = conn.cursor()
    
    cursor.execute("DELETE FROM sinks WHERE id = ?", (sink_id,))
    deleted = cursor.rowcount > 0
    conn.commit()
    conn.close()
    
    return deleted


# ============================================================================
# TEST CRUD Operations
# ============================================================================

def add_test(
    sink_id: int,
    canary_uuid: str,
    payload_type: str = "Direct",
    target_url: Optional[str] = None,
    notes: Optional[str] = None,
    db_path: Optional[Path] = None
) -> int:
    """Add a new test for a sink. Returns the test ID."""
    conn = get_connection(db_path)
    cursor = conn.cursor()
    
    cursor.execute("""
        INSERT INTO tests (sink_id, canary_uuid, payload_type, target_url, notes)
        VALUES (?, ?, ?, ?, ?)
    """, (sink_id, canary_uuid, payload_type, target_url, notes))
    
    test_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    return test_id


def get_test(test_id: int, db_path: Optional[Path] = None) -> Optional[dict]:
    """Get a single test by ID with sink details."""
    conn = get_connection(db_path)
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT t.*, s.surface_name, s.param_name, s.method, s.risk_level
        FROM tests t
        JOIN sinks s ON t.sink_id = s.id
        WHERE t.id = ?
    """, (test_id,))
    row = cursor.fetchone()
    conn.close()
    
    return dict(row) if row else None


def get_tests_for_sink(sink_id: int, db_path: Optional[Path] = None) -> list[dict]:
    """Get all tests for a specific sink."""
    conn = get_connection(db_path)
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT * FROM tests WHERE sink_id = ? ORDER BY timestamp DESC
    """, (sink_id,))
    rows = cursor.fetchall()
    conn.close()
    
    return [dict(row) for row in rows]


def get_all_tests(db_path: Optional[Path] = None) -> list[dict]:
    """Get all tests with sink details."""
    conn = get_connection(db_path)
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT t.*, s.surface_name, s.param_name, s.method
        FROM tests t
        JOIN sinks s ON t.sink_id = s.id
        ORDER BY t.timestamp DESC
    """)
    rows = cursor.fetchall()
    conn.close()
    
    return [dict(row) for row in rows]


def update_test_status(
    test_id: int,
    status: str,
    notes: Optional[str] = None,
    db_path: Optional[Path] = None
) -> bool:
    """Update a test's status. Returns True if updated."""
    conn = get_connection(db_path)
    cursor = conn.cursor()
    
    hit_timestamp = datetime.now().isoformat() if status == "HIT" else None
    
    if notes:
        cursor.execute("""
            UPDATE tests SET status = ?, hit_timestamp = ?, notes = ? WHERE id = ?
        """, (status, hit_timestamp, notes, test_id))
    else:
        cursor.execute("""
            UPDATE tests SET status = ?, hit_timestamp = ? WHERE id = ?
        """, (status, hit_timestamp, test_id))
    
    updated = cursor.rowcount > 0
    conn.commit()
    conn.close()
    
    return updated


def get_test_by_uuid(canary_uuid: str, db_path: Optional[Path] = None) -> Optional[dict]:
    """Look up a test by its canary UUID."""
    conn = get_connection(db_path)
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT t.*, s.surface_name, s.param_name, s.method, s.risk_level
        FROM tests t
        JOIN sinks s ON t.sink_id = s.id
        WHERE t.canary_uuid = ?
    """, (canary_uuid,))
    row = cursor.fetchone()
    conn.close()
    
    return dict(row) if row else None


# ============================================================================
# Statistics
# ============================================================================

def get_stats(db_path: Optional[Path] = None) -> dict:
    """Get summary statistics."""
    conn = get_connection(db_path)
    cursor = conn.cursor()
    
    cursor.execute("SELECT COUNT(*) FROM sinks")
    total_sinks = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM tests")
    total_tests = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM tests WHERE status = 'PENDING'")
    pending_tests = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM tests WHERE status = 'HIT'")
    hit_tests = cursor.fetchone()[0]
    
    conn.close()
    
    return {
        "total_sinks": total_sinks,
        "total_tests": total_tests,
        "pending_tests": pending_tests,
        "hit_tests": hit_tests,
        "closed_tests": total_tests - pending_tests - hit_tests
    }

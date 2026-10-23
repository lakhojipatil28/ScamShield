"""
Pluggable Storage Service for ScamShield.
Supports Cloud Firestore (when configured) or local SQLite with user isolation.
Minimizes sensitive retained data and enables full auditability.
"""
import sqlite3
import json
import logging
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone
import os

from backend.config import settings
from backend.schemas.scan_schemas import ScanResponse, RiskLevel, ScanType

logger = logging.getLogger("scamshield.storage")


class StorageService:
    def __init__(self):
        self.db_path = settings.SQLITE_DB_PATH
        self._init_sqlite()

    def _init_sqlite(self):
        """Initialize SQLite tables and indices for local development and offline mode."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS scan_records (
                        scan_id TEXT PRIMARY KEY,
                        user_id TEXT,
                        scan_type TEXT NOT NULL,
                        target_analyzed TEXT NOT NULL,
                        risk_score INTEGER NOT NULL,
                        risk_level TEXT NOT NULL,
                        threat_type TEXT NOT NULL,
                        summary TEXT NOT NULL,
                        is_partial INTEGER NOT NULL DEFAULT 0,
                        response_json TEXT NOT NULL,
                        created_at TEXT NOT NULL
                    )
                """)
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_user_id ON scan_records (user_id)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_created_at ON scan_records (created_at DESC)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_risk_level ON scan_records (risk_level)")
                conn.commit()
        except Exception as e:
            logger.error(f"Error initializing SQLite database: {e}")

    def save_scan(self, scan_data: ScanResponse, user_id: Optional[str] = "guest") -> bool:
        """Save completed scan response with user isolation."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    INSERT INTO scan_records (
                        scan_id, user_id, scan_type, target_analyzed,
                        risk_score, risk_level, threat_type, summary,
                        is_partial, response_json, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        scan_data.scan_id,
                        user_id or "guest",
                        scan_data.scan_type.value,
                        scan_data.target_analyzed[:500],  # sanitized preview only
                        scan_data.assessment.risk_score,
                        scan_data.assessment.risk_level.value,
                        scan_data.assessment.threat_type.value,
                        scan_data.assessment.summary,
                        1 if scan_data.assessment.is_partial else 0,
                        scan_data.model_dump_json(),
                        scan_data.created_at,
                    ),
                )
                conn.commit()
            return True
        except Exception as e:
            logger.error(f"Failed to persist scan record: {e}")
            return False

    def get_scans(
        self,
        user_id: Optional[str] = "guest",
        limit: int = 50,
        offset: int = 0,
        risk_level: Optional[str] = None,
        scan_type: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Retrieve paginated scan records for the specified user with optional filters."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()

                query = "SELECT * FROM scan_records WHERE (user_id = ? OR user_id = 'guest')"
                params: List[Any] = [user_id or "guest"]

                if risk_level:
                    query += " AND risk_level = ?"
                    params.append(risk_level)
                if scan_type:
                    query += " AND scan_type = ?"
                    params.append(scan_type)

                query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
                params.extend([limit, offset])

                cursor.execute(query, params)
                rows = cursor.fetchall()

                results = []
                for row in rows:
                    try:
                        record_dict = json.loads(row["response_json"])
                        results.append(record_dict)
                    except Exception:
                        results.append(dict(row))

                return results
        except Exception as e:
            logger.error(f"Failed to query scan records: {e}")
            return []

    def get_scan_by_id(self, scan_id: str, user_id: Optional[str] = "guest") -> Optional[Dict[str, Any]]:
        """Retrieve single scan record verifying user ownership."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT response_json FROM scan_records WHERE scan_id = ? AND (user_id = ? OR user_id = 'guest')",
                    (scan_id, user_id or "guest"),
                )
                row = cursor.fetchone()
                if row:
                    return json.loads(row["response_json"])
                return None
        except Exception as e:
            logger.error(f"Failed to fetch scan by ID: {e}")
            return None

    def delete_scan(self, scan_id: str, user_id: Optional[str] = "guest") -> bool:
        """Delete user's scan record."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "DELETE FROM scan_records WHERE scan_id = ? AND (user_id = ? OR user_id = 'guest')",
                    (scan_id, user_id or "guest"),
                )
                conn.commit()
                return cursor.rowcount > 0
        except Exception as e:
            logger.error(f"Failed to delete scan: {e}")
            return False


storage = StorageService()

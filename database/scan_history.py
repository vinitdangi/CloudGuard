"""Safe persistence and retrieval for scan history and complete scan results."""

import json
from collections.abc import Mapping
from typing import Any

from database.db import get_connection
from cloudguard.utils.sanitization import sanitize_sensitive_data as sanitize_scan_data


SCAN_HISTORY_FIELDS = (
    "id",
    "username",
    "scan_timestamp",
    "aws_account_id",
    "aws_region",
    "security_score",
    "total_findings",
    "critical_count",
    "high_count",
    "medium_count",
    "low_count",
    "passed_count",
)


def save_scan_history(
    *,
    username: str,
    scan_timestamp: str,
    aws_account_id: str,
    aws_region: str,
    security_score: float,
    total_findings: int,
    critical_count: int,
    high_count: int,
    medium_count: int,
    low_count: int,
    passed_count: int,
    scan_result: Mapping[str, Any] | None = None,
    sensitive_values: tuple[str, ...] = (),
) -> int:
    """Insert a summary and optional sanitized full result without credentials."""
    values = (
        username,
        scan_timestamp,
        aws_account_id,
        aws_region,
        float(security_score),
        int(total_findings),
        int(critical_count),
        int(high_count),
        int(medium_count),
        int(low_count),
        int(passed_count),
    )
    with get_connection() as connection:
        cursor = connection.execute(
            """INSERT INTO scan_history (
                username, scan_timestamp, aws_account_id, aws_region,
                security_score, total_findings, critical_count, high_count,
                medium_count, low_count, passed_count
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING id""",
            values,
        )
        scan_history_id = int(cursor.fetchone()["id"])
        if scan_result is not None:
            safe_result = sanitize_scan_data(scan_result, sensitive_values)
            connection.execute(
                "INSERT INTO scan_results (scan_history_id, scan_result_json) VALUES (?, ?)",
                (scan_history_id, json.dumps(safe_result, ensure_ascii=True, separators=(",", ":"))),
            )
        return scan_history_id


def get_scan_history(username: str) -> list[dict[str, Any]]:
    """Return one user's scan summaries, newest timestamp first."""
    columns = ", ".join(SCAN_HISTORY_FIELDS)
    with get_connection() as connection:
        rows = connection.execute(
            f"SELECT {columns} FROM scan_history WHERE username = ? "
            "ORDER BY scan_timestamp DESC, id DESC",
            (username,),
        ).fetchall()
    return [dict(row) for row in rows]


def get_latest_scan_result(username: str) -> dict[str, Any] | None:
    """Return the latest complete result for one user, never another user's data."""
    with get_connection() as connection:
        row = connection.execute(
            """SELECT results.scan_result_json
               FROM scan_results AS results
               JOIN scan_history AS history ON history.id = results.scan_history_id
               WHERE history.username = ?
               ORDER BY history.scan_timestamp DESC, history.id DESC
               LIMIT 1""",
            (username,),
        ).fetchone()
    if row is None:
        return None
    result = json.loads(row["scan_result_json"])
    return result if isinstance(result, dict) else None

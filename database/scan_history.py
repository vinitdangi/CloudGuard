"""Safe persistence and retrieval for scan-history summaries."""

from typing import Any

from database.db import get_connection

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
) -> int:
    """Insert only the explicitly supported, non-credential scan fields."""
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
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            values,
        )
        return int(cursor.lastrowid)


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

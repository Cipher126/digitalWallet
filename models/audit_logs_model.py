import datetime
import json
from decimal import Decimal

from database.connection import conn
from error_handling.error_handler import logger
from error_handling.errors import NotFoundError
from utils.hashing import generate_id


def insert_audit_log(user_id, action, metadata=None):
    """Insert a new audit log entry."""
    try:
        metadata = {k: float(v) if isinstance(v, Decimal) else v for k, v in metadata.items()}
        log_id = generate_id(10)
        with conn:
            with conn.cursor() as cursor:
                cursor.execute("""
                    INSERT INTO audit_logs (log_id, user_id, action, metadata, created_at)
                    VALUES (%s, %s, %s, %s, %s)
                """, (log_id, user_id, action, json.dumps(metadata), datetime.datetime.now(datetime.timezone.utc)))

        return True
    except Exception as e:
        logger.error(f"Failed to insert audit log: {e}", exc_info=True)
        raise


def insert_user_audit_log(cursor, user_id, action, metadata=None):
    """Insert a new audit log entry."""
    try:
        log_id = generate_id(10)
        metadata = {k: float(v) if isinstance(v, Decimal) else v for k, v in metadata.items()}

        cursor.execute("""
                    INSERT INTO audit_logs (log_id, user_id, action, metadata, created_at)
                    VALUES (%s, %s, %s, %s, %s)
        """, (log_id, user_id, action, json.dumps(metadata), datetime.datetime.now(datetime.timezone.utc)))

        return True
    except Exception as e:
        logger.error(f"Failed to insert audit log: {e}", exc_info=True)
        raise


def get_user_audit_logs(user_id, limit=None):
    """Fetch recent audit logs for a specific user."""
    try:
        with conn:
            with conn.cursor() as cursor:
                if limit:
                    cursor.execute("""
                        SELECT log_id, user_id, action, metadata, created_at
                        FROM audit_logs
                        WHERE user_id = %s
                        ORDER BY created_at DESC
                        LIMIT %s
                    """, (user_id, limit))

                else:
                    cursor.execute("""
                        SELECT log_id, user_id, action, metadata, created_at
                        FROM audit_logs
                        WHERE user_id = %s
                        ORDER BY created_at DESC
                    """, (user_id, ))

                logs = cursor.fetchall()

            if not logs:
                raise NotFoundError("unable to get audit logs")

        logs_list = []

        for log in logs:
            logs_list.append({
                "log_id": log[0],
                "user_id": log[1],
                "action": log[2],
                "metadata": log[3],
                "timestamp": log[4]
            })

        return logs_list

    except Exception as e:
        logger.error(f"Failed to fetch audit logs: {e}", exc_info=True)
        raise


def get_audit_log(limit=None):
    try:
        with conn:
            with conn.cursor() as cursor:
                if limit:

                    cursor.execute("""
                        SELECT log_id, user_id, action, metadata, created_at
                        FROM audit_logs
                        ORDER BY created_at DESC
                        LIMIT %s
                    """, (limit, ))
                else:
                    cursor.execute("""
                        SELECT log_id, user_id, action, metadata, created_at
                        FROM audit_logs
                        ORDER BY created_at DESC
                    """)

                logs =  cursor.fetchall()

            if not logs:
                raise NotFoundError("unable to get audit logs")

        logs_list = []

        for log in logs:
            logs_list.append({
                "log_id": log[0],
                "user_id": log[1],
                "action": log[2],
                "metadata": log[3],
                "timestamp": log[4]
            })

        return logs_list

    except Exception as e:
        logger.error(f"Failed to fetch audit logs: {e}", exc_info=True)
        raise
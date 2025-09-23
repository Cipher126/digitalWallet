import datetime
from database.connection import conn
from error_handling.error_handler import logger
from utils.hashing import generate_id


def insert_audit_log(user_id, action, metadata=None):
    """Insert a new audit log entry."""
    try:
        log_id = generate_id(10)
        with conn:
            with conn.cursor() as cursor:
                cursor.execute("""
                    INSERT INTO audit_logs (log_id, user_id, action, metadata, created_at)
                    VALUES (%s, %s, %s, %s, %s)
                """, (log_id, user_id, action, metadata, datetime.datetime.now(datetime.timezone.utc)))
    except Exception as e:
        logger.error(f"Failed to insert audit log: {e}", exc_info=True)
        raise


def get_user_audit_logs(user_id, limit=50):
    """Fetch recent audit logs for a specific user."""
    try:
        with conn:
            with conn.cursor() as cursor:
                cursor.execute("""
                    SELECT log_id, user_id, action, metadata, created_at
                    FROM audit_logs
                    WHERE user_id = %s
                    ORDER BY created_at DESC
                    LIMIT %s
                """, (user_id, limit))
                return cursor.fetchall()
    except Exception as e:
        logger.error(f"Failed to fetch audit logs: {e}", exc_info=True)
        raise

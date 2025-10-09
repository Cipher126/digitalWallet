import datetime
import json
from decimal import Decimal

from database.connection import conn
from error_handling.error_handler import logger
from utils.hashing import generate_id


def insert_webhook_log(event_type, payload, status="pending"):
    """Insert a new webhook log entry."""
    try:
        payload = {k: str(v) if isinstance(v, Decimal) else v for k, v in payload.items()}
        webhook_id = generate_id(10)
        with conn:
            with conn.cursor() as cursor:
                cursor.execute("""
                    INSERT INTO webhook_logs (webhook_id, event_type, payload, status, attempts, created_at)
                    VALUES (%s, %s, %s, %s, %s, %s)
                """, (webhook_id, event_type, json.dumps(payload), status, 0, datetime.datetime.now(datetime.timezone.utc)))
    except Exception as e:
        logger.error(f"Failed to insert webhook log: {e}", exc_info=True)
        raise


def update_webhook_status(webhook_id, status, attempts, last_attempt_at=None):
    """Update webhook log status (delivered/failed) and attempts."""
    try:
        with conn:
            with conn.cursor() as cursor:
                cursor.execute("""
                    UPDATE webhook_logs
                    SET status = %s, attempts = %s, last_attempt_at = %s
                    WHERE webhook_id = %s
                """, (status, attempts, last_attempt_at or datetime.datetime.now(datetime.timezone.utc), webhook_id))
    except Exception as e:
        logger.error(f"Failed to update webhook log: {e}", exc_info=True)
        raise


def get_pending_webhooks(limit=20):
    """Fetch pending webhook logs (for retries)."""
    try:
        with conn:
            with conn.cursor() as cursor:
                cursor.execute("""
                    SELECT webhook_id, event_type, payload, status, attempts, last_attempt_at, created_at
                    FROM webhook_logs
                    WHERE status = 'pending'
                    ORDER BY created_at ASC
                    LIMIT %s
                """, (limit,))
                return cursor.fetchall()
    except Exception as e:
        logger.error(f"Failed to fetch pending webhooks: {e}", exc_info=True)
        raise

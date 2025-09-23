import datetime
from database.connection import conn
from error_handling.error_handler import logger
from error_handling.errors import NotFoundError
from models.audit_logs_model import insert_audit_log
from utils.hashing import generate_id


def insert_refresh_token(user_id, token, days_valid=7):
    """Save refresh token for session management."""
    try:
        exp = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=days_valid)
        token_id = generate_id(10)

        with conn:
            with conn.cursor() as cursor:
                cursor.execute("""
                    INSERT INTO tokens (token_id, user_id, token, expires_at, is_revoked)
                    VALUES (%s, %s, %s, %s, %s)
                """, (token_id, user_id, token, exp, False))

        insert_audit_log(user_id, "REFRESH_TOKEN_CREATED", {"token_id": token_id})

        return {"token_id": token_id, "expires_at": exp}

    except Exception as e:
        logger.error(f"Failed to insert refresh token: {e}", exc_info=True)
        raise


def get_refresh_token(user_id, token):
    """Fetch refresh token details and validate expiry/revocation."""
    try:
        with conn:
            with conn.cursor() as cursor:
                cursor.execute("""
                    SELECT token_id, user_id, token, is_revoked, expires_at 
                    FROM tokens WHERE user_id = %s AND token = %s
                """, (user_id, token))

                token_details = cursor.fetchone()

        if not token_details:
            raise NotFoundError("Token doesn't exist")

        token_data = {
            "token_id": token_details[0],
            "user_id": token_details[1],
            "token": token_details[2],
            "is_revoked": token_details[3],
            "exp": token_details[4]
        }

        if token_data["is_revoked"]:
            raise NotFoundError("Token revoked")

        if token_data["exp"] < datetime.datetime.now(datetime.timezone.utc):
            raise NotFoundError("Token expired")

        return token_data

    except Exception as e:
        logger.error(f"Exception occurred at get_refresh_token: {e}", exc_info=True)
        raise


def delete_token(user_id, token, soft=True):
    """Delete or revoke a single refresh token."""
    try:
        with conn:
            with conn.cursor() as cursor:
                if soft:
                    cursor.execute("""
                        UPDATE tokens SET is_revoked = TRUE WHERE user_id = %s AND token = %s
                    """, (user_id, token))
                else:
                    cursor.execute("""
                        DELETE FROM tokens WHERE user_id = %s AND token = %s
                    """, (user_id, token))

        insert_audit_log(user_id, "REFRESH_TOKEN_DELETED", {"token": token})

        return True
    except Exception as e:
        logger.error(f"Exception occurred in delete_token: {e}", exc_info=True)
        raise


def delete_all_token(user_id, soft=True):
    """Delete or revoke all tokens for a user."""
    try:
        with conn:
            with conn.cursor() as cursor:
                if soft:
                    cursor.execute("""
                        UPDATE tokens SET is_revoked = TRUE WHERE user_id = %s
                    """, (user_id,))
                else:
                    cursor.execute("""
                        DELETE FROM tokens WHERE user_id = %s
                    """, (user_id,))

        return True
    except Exception as e:
        logger.error(f"Exception occurred in delete_all_token: {e}", exc_info=True)
        raise

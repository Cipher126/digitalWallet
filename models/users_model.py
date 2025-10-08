import json

from error_handling.error_handler import logger
from error_handling.errors import (
    InsufficientDataError, NotFoundError,
    ValidationError, ConflictError, UnauthorizedError, InternalServerError
)
from models.audit_logs_model import insert_audit_log, insert_user_audit_log
from models.tokens_model import insert_refresh_token
from utils.hashing import (
    hash_password, generate_id,
    verify_password
)
from database.connection import conn
from utils.jwt_utils import create_access_token, create_refresh_token


def _insert_wallet(cursor, user_id):
    """Create wallet automatically for each user."""
    wallet_id = generate_id(20)
    cursor.execute("""
        INSERT INTO wallets (wallet_id, user_id)
        VALUES (%s, %s)
    """, (wallet_id, user_id))
    return wallet_id


def generate_tokens(user_id, role):
    """Generate and persist access + refresh tokens."""
    access_token = create_access_token(user_id, role)
    refresh_token = create_refresh_token(user_id)
    insert_refresh_token(user_id, refresh_token)
    return access_token, refresh_token


def create_user(email, username, full_name, phone=None, password=None,
                oauth_provider=None, oauth_id=None, is_oauth_only=False, role=None):
    """Create a user (normal signup or OAuth)."""
    user_id = generate_id(8)

    try:
        with conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    "SELECT 1 FROM users WHERE email = %s OR username = %s",
                    (email, username)
                )

                user = cursor.fetchone()
                if user:
                    raise ConflictError("Email or username already exists")

                user_role = role if role else ""

                if password and phone:
                    hashed_pw = str(hash_password(password))

                    cursor.execute("""
                        INSERT INTO users (user_id, username, full_name, email, phone, password, role)
                        VALUES (%s, %s, %s, %s, %s, %s, %s)
                        RETURNING role
                    """, (user_id, username, full_name, email, phone, hashed_pw, user_role))

                    saved_role = cursor.fetchone()[0]

                    insert_user_audit_log(cursor, user_id, "USER_CREATED", json.dumps({"method": "email"}))

                elif oauth_provider and oauth_id and is_oauth_only:
                    cursor.execute("""
                        INSERT INTO users (user_id, username, full_name, email,
                                           oauth_provider, oauth_id, is_oauth_only)
                        VALUES (%s, %s, %s, %s, %s, %s, %s)
                        RETURNING role
                    """, (user_id, username, full_name, email,
                          oauth_provider, oauth_id, is_oauth_only))

                    saved_role = cursor.fetchone()[0]

                    insert_user_audit_log(cursor, user_id, "USER_CREATED", json.dumps({"method": "OAUTH"}))

                else:
                    raise InsufficientDataError("Not enough signup data provided")

                wallet_id = _insert_wallet(cursor, user_id)
        access, refresh = generate_tokens(user_id, saved_role)

        return {
            "user_id": user_id,
            "wallet_id": wallet_id,
            "account_number": "",
            "tokens": {
                "refresh_token": refresh,
                "access_token": access
            }
        }

    except NotFoundError as e:
        raise e

    except Exception as e:
        logger.error(f"Error creating user: {e}", exc_info=True)
        raise


def search_user_with_params(username=None, email=None, user_id=None):
    """Search user by username, email, or ID."""
    try:
        with conn:
            with conn.cursor() as cursor:
                cursor.execute("""
                    SELECT * FROM users WHERE username = %s OR email = %s OR user_id = %s
                """, (username, email, user_id))
                user = cursor.fetchone()

        if user:
            return {
                "user_id": user[0],
                "username": user[1],
                "name": user[2],
                "email": user[3],
                "phone": user[4],
                "password": user[5],
                "is_active": user[11],
                "otp_secret": user[9],
                "two_fa_enabled": user[10],
                "role": user[13],
                "fcm_token": [15]
            }

        raise NotFoundError("User not found")

    except NotFoundError as e:
        raise e

    except Exception as e:
        logger.error(f"Error searching user: {e}", exc_info=True)
        raise


def authenticate_user_with_username(username, password):
    """Login via username."""
    user = search_user_with_params(username=username)
    try:
        if verify_password(password, user["password"]) and user["is_active"]:
            access_token, refresh_token = generate_tokens(user["user_id"], user["role"])

            return {
                "username": user["username"],
                "access_token": access_token,
                "refresh_token": refresh_token
            }

        if not user["is_active"]:
            raise UnauthorizedError("Your account has been temporarily lock contact admin")

        raise ValidationError("Invalid username or password")
    except Exception as e:
        logger.error(f"Error authenticating with username: {e}", exc_info=True)
        raise


def authenticate_user_with_email(email, password):
    """Login via email."""
    user = search_user_with_params(email=email)
    try:
        if verify_password(password, user["password"]) and user["is_active"]:
            access_token, refresh_token = generate_tokens(user["user_id"], user["role"])
            return {
                "username": user["username"],
                "access_token": access_token,
                "refresh_token": refresh_token
            }

        if not user["is_active"]:
            raise UnauthorizedError("Your account has been temporarily lock contact admin")

        raise ValidationError("Invalid email or password")
    except Exception as e:
        logger.error(f"Error authenticating with email: {e}", exc_info=True)
        raise


def get_user_by_oauth(provider, oauth_id):
    """Find user via OAuth provider + ID."""
    try:
        with conn:
            with conn.cursor() as cursor:
                cursor.execute("""
                    SELECT user_id, username, full_name, email, phone, is_active, role
                    FROM users WHERE oauth_provider = %s AND oauth_id = %s
                """, (provider, oauth_id))
                user = cursor.fetchone()

        if user:
            return {
                "user_id": user[0],
                "username": user[1],
                "full_name": user[2],
                "email": user[3],
                "phone": user[4],
                "is_active": user[5],
                "role": user[6]
            }
        raise NotFoundError("OAuth user not found")

    except Exception as e:
        logger.error(f"Error fetching OAuth user: {e}", exc_info=True)
        raise


def oauth_login(provider, oauth_id):
    """Fetch OAuth user if they exist."""
    try:
        user = get_user_by_oauth(provider, oauth_id)
        if not user:
            raise NotFoundError("OAuth user not found")
        if not user["is_active"]:
            raise ValidationError("User account is inactive")
        return user
    except NotFoundError:
        raise
    except Exception as e:
        logger.error(f"Error in OAuth login: {e}", exc_info=True)
        raise InternalServerError("Failed to fetch OAuth user")


def update_user_active_status(user_id, is_active: bool):
    try:
        with conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    "UPDATE users SET is_active = %s WHERE user_id = %s",
                    (is_active, user_id)
                )

        return True
    except Exception as e:
        logger.error(f"Error updating user active status: {e}", exc_info=True)
        raise


def verify_user(email, is_verified: bool):
    try:
        with conn:
            with conn.cursor() as cursor:
                cursor.execute("UPDATE users SET is_verified = %s WHERE email = %s",
                               (is_verified, email))

        return True
    except Exception as e:
        logger.error(f"Error verifying user: {e}", exc_info=True)
        raise


def update_user_password(email, password):
    hashed_pw = hash_password(password)
    try:
        with conn:
            with conn.cursor() as cursor:
                cursor.execute("UPDATE users SET password = %s WHERE email = %s",
                               (hashed_pw, email))

        return True
    except Exception as e:
        logger.error(f"Error updating password: {e}", exc_info=True)
        raise


def update_user_info(username, fields_to_edit):
    try:
        if not fields_to_edit:
            raise InsufficientDataError("No field provided for edit")
        set_clause = ", ".join(f"{key} = %s" for key in fields_to_edit)
        values = list(fields_to_edit.values())

        values.extend([username])

        with conn:
            with conn.cursor() as cursor:
                cursor.execute(f"""
                    UPDATE users SET {set_clause} WHERE username = %s
                """, values)

        return True

    except Exception as e:
        logger.error(f"Exception occurred in update user info: {e}", exc_info=True)
        raise


def enable_2fa(user_id, otp_secret, enabled: bool):
    try:
        with conn:
            with conn.cursor() as cursor:
                cursor.execute("""
                    UPDATE users SET otp_secret = %s, two_factor_enabled = %s WHERE user_id = %s
                """, (otp_secret, enabled, user_id))

        insert_audit_log(user_id, "2FA_ENABLED", {"secret_last4": otp_secret[-4:]})

        return True
    except Exception as e:
        logger.error(f"Error enabling 2FA: {e}", exc_info=True)
        raise


def delete_account(user_id):
    try:
        with conn:
            with conn.cursor() as cursor:
                cursor.execute("DELETE FROM users WHERE user_id = %s", (user_id,))

        return True
    except Exception as e:
        logger.error(f"Error deleting account: {e}", exc_info=True)
        raise


def update_fcm_token(token, user_id):
    try:
        with conn:
            with conn.cursor() as cursor:
                cursor.execute("UPDATE users SET fcm_token = %s WHERE user_id = %s",
                               (token, user_id))

        return True
    except Exception as e:
        logger.error(f"Error verifying user: {e}", exc_info=True)
        raise
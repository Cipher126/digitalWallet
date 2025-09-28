import redis
import time
import os
from dotenv import load_dotenv

load_dotenv()
SECRET_KEY = os.getenv("SECRET_KEY")
REDIS_HOST = os.getenv("REDIS_HOST")
REDIS_PORT = int(os.getenv("REDIS_PORT"))
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD")
REDIS_USER = os.getenv("REDIS_USER")

r = redis.Redis(
    host=REDIS_HOST,
    port=REDIS_PORT,
    username=REDIS_USER,
    password=REDIS_PASSWORD,
    decode_responses=True
)


def _lockout_key(scope: str, identifier: str):
    """Generate Redis key with scope (user/wallet)."""
    return f"lockout:{scope}:{identifier}"


def _failures_key(scope: str, identifier: str):
    """Generate Redis key for failures tracking."""
    return f"failures:{scope}:{identifier}"


def is_user_locked_out(scope: str, identifier: str) -> bool:
    """
    Check if a user or wallet is locked.
    scope: "user" or "wallet"
    """
    return r.exists(_lockout_key(scope, identifier))


def register_failed_login(scope: str, identifier: str,
                            max_attempt=5, window=300, lockout_time=7200):
    """
    Register a failed attempt.
    - max_attempt: number of failed attempts allowed
    - window: time window in seconds (e.g. 5 min)
    - lockout_time: how long to lock after exceeding limit
    """
    key = _failures_key(scope, identifier)
    now = int(time.time())

    r.lpush(key, now)
    r.ltrim(key, 0, max_attempt - 1)
    r.expire(key, window)

    attempts = r.lrange(key, 0, -1)

    if len(attempts) >= max_attempt:
        first_attempt_time = int(attempts[-1])
        if now - first_attempt_time <= window:
            r.setex(_lockout_key(scope, identifier), lockout_time, 1)


def clear_failed_attempts(scope: str, identifier: str):
    """Clear lockout and failed attempts after success."""
    r.delete(_lockout_key(scope, identifier))
    r.delete(_failures_key(scope, identifier))

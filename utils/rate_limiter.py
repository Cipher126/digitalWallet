import time
from error_handling.errors import InternalServerError
from services.auth_services import r, logger


def rate_limit(identifier, capacity=5, refill_rate=0.1):
    """
    Token Bucket Rate Limiter using Redis.

    :param identifier: Unique key (e.g., user_id or IP)
    :param capacity: Max number of requests allowed in bucket
    :param refill_rate: Tokens refilled per second
    :return: True if blocked, False if allowed
    """
    try:
        key_tokens = f"rate:{identifier}:tokens"
        key_timestamp = f"rate:{identifier}:ts"

        now = time.time()

        tokens = r.get(key_tokens)
        tokens = float(tokens) if tokens else capacity

        last_ts = r.get(key_timestamp)
        last_ts = float(last_ts) if last_ts else now

        elapsed = now - last_ts
        tokens = min(capacity, int(tokens + elapsed * refill_rate))

        r.set(key_timestamp, now, ex=3600)

        if tokens < 1:
            r.set(key_tokens, tokens, ex=3600)
            return True

        tokens -= 1
        r.set(key_tokens, tokens, ex=3600)

        return False

    except Exception as e:
        logger.error(f"Exception in rate limiter: {e}", exc_info=True)
        raise InternalServerError
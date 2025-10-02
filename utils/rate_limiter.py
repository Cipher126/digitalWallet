import time

from error_handling.errors import InternalServerError
from services.auth_services import r, logger


def rate_limit(identifier, capacity, refill_rate):
    """
    Token bucket rate limiter

    :param identifier:
    :param capacity:
    :param refill_rate:
    :return: True if request should be blocked and False if allowed
    """
    try:
        key_tokens = f"rate:{identifier}:tokens"
        key_timestamp = f"rate:{identifier}:ts"

        now = time.time()

        tokens = r.get(key_tokens)
        tokens= float(tokens) if tokens else capacity
        last_ts = r.get(key_timestamp)
        last_ts = float(last_ts) if last_ts else now

        elapsed = now - last_ts

        tokens = min(capacity, tokens + elapsed * refill_rate)

        r.set(key_timestamp, now)

        if tokens < 1:
            r.set(key_tokens, tokens)
            return True

        tokens -= 1
        r.set(key_tokens, tokens)

        return False

    except Exception as e:
        logger.error(f"exception occurred in rate limit: {e}", exc_info=True)
        raise InternalServerError
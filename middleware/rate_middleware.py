from functools import wraps
from flask import request

from error_handling.error_handler import logger
from error_handling.errors import LockoutError, InternalServerError
from utils.rate_limiter import rate_limit


def rate_limiter(capacity=10, refill_rate=1):
    """
    Decorator for per_route rate limiting.

    :param capacity = 10 - max tokens
    :param refill_rate = 1 - one token per seconds
    :return:
    """

    try:

        def decorator(f):
            @wraps(f)
            def wrapper(*args, **kwargs):
                identifier = request.remote_addr or request.remote_user

                if rate_limit(identifier, capacity, refill_rate):
                    raise LockoutError("Too many requests. try again later")

                return f(*args, **kwargs)
            return wrapper
        return decorator

    except LockoutError as e:
        raise e

    except Exception as e:
        logger.error(f"exception occurred in rate limiter: {e}", exc_info=True)
        raise InternalServerError
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

r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, username=REDIS_USER, password=REDIS_PASSWORD, decode_responses=True)

def is_user_locked_out(user_id):

    return r.exists(f"lockout{user_id}")

def register_failed_login(user_id, max_attempt=5, window=300, lockout_time=7200):
    key = f"failures:{user_id}"
    now = int(time.time())

    r.lpush(key, now)
    r.ltrim(key, 0, max_attempt - 1)
    r.expire(key, window)

    attempts = r.lrange(key, 0, -1)

    if len(attempts) >= max_attempt:
        first_attempt_time = int((attempts[-1]))

        if now - first_attempt_time <= window:
            r.setex(f"lockout:{user_id}", lockout_time, 1)

def clear_failed_attempts(user_id):
    r.delete(f"lockout:{user_id}")
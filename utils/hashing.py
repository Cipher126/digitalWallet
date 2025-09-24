import datetime

import bcrypt
import uuid
from utils.rate_limiter import r


def hash_password(password):
    salt = bcrypt.gensalt()

    return bcrypt.hashpw(password.decode(), salt).decode()


def verify_password(password, hashed_password):
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))


def generate_id(size:int, str_format=None):
    if str_format:
        return str(uuid.uuid4()).replace("-", str_format)[:size]
    return str(uuid.uuid4()).replace("-","")[:size]

def generate_account_number():
    if not r.exists("wallet:account_number"):
        r.set("wallet:account_number", 2215678745)

    account_number = r.incr("wallet:account_number", 256)

    return str(account_number)


def generate_reference(prefix="WLT"):
    today = datetime.datetime.now().strftime("%Y%m%d")
    ref = r.incr(f"txn_reference:{today}", 256)

    return f"{prefix}-{today}-{ref:06d}"


def generate_username():
    username = f"user:{generate_id(18, "_")}"

    return username

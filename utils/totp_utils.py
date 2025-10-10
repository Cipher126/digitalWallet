import pyotp

def generate_totp_secret():

    return pyotp.random_base32()

def generate_totp_uri(secret, identifier, app_name = "MyWalletApp"):

    return pyotp.totp.TOTP(secret).provisioning_uri(name=identifier, issuer_name=app_name)

def verify_totp(secret, token):

    totp = pyotp.TOTP(secret)
    return totp.verify(token)

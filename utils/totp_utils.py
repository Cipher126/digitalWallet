import pyotp

def generate_totp_secret():

    return pyotp.random_base32()

def generate_totp_uri(secret, username, app_name = "MyWalletApp"):

    return pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name=app_name)

def verify_totp(secret, token):

    totp = pyotp.TOTP(secret)
    return totp.verify(token)

# secret = generate_totp_secret()
# print(secret)
# uri = generate_totp_uri(secret, "cipher")
# print(uri)
# verified = verify_totp("FJ5ML7N7QYG4OGS4FFYYQ72DKET37GHH", 835986)
# print(verified)

# import qrcode
#
# img = qrcode.make("otpauth://totp/MyWalletApp:cipher?secret=FJ5ML7N7QYG4OGS4FFYYQ72DKET37GHH&issuer=MyWalletApp")
# img.save("qrcode.png")
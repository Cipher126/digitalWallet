from models.users_model import (create_user, get_user_by_oauth, oauth_login,
                                authenticate_user_with_email, authenticate_user_with_username)

def signup(data):
    email = data.get("email")
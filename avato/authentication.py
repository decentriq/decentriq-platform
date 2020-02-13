import pyrebase
from .config import FIREBASE_CONFIG

__auth = pyrebase.initialize_app(FIREBASE_CONFIG).auth()


class LoginError(Exception):
    """Raised when the certificate validation failed"""

    pass


class UserParsingError(Exception):
    """Raised when the user from Firebase couldn't be parsed"""

    pass


def user_decoder(obj):
    return User(obj["email"], obj["displayName"], obj["idToken"])


class User:
    def __init__(self, email, display_name, id_token):
        self.email = email
        self.display_name = display_name
        self.id_token = id_token

    def __str__(self):
        return f"email: {self.email}, display_name: {self.display_name}, id_token: {self.id_token}"


def sign_in(email, password):
    try:
        user_dic = __auth.sign_in_with_email_and_password(email, password)
    except:
        raise LoginError

    try:
        user = user_decoder(user_dic)
    except:
        raise UserParsingError

    return user

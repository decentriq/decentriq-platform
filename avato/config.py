import os

AVATO_HOST = os.getenv("AVATO_HOST", "localhost")
AVATO_PORT = int(os.getenv("AVATO_PORT", "3000"))
AVATO_USE_SSL = True if os.getenv("AVATO_USE_SSL") else False

FIREBASE_CONFIG = {
    "apiKey": "AIzaSyCUhhD-qgDxOOE3EeKfwnNVkoBQxD2jNvA",
    "authDomain": "decentriq.firebaseapp.com",
    "databaseURL": "https://decentriq.firebaseio.com",
    "storageBucket": "decentriq.appspot.com",
}

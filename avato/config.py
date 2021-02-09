import os

AVATO_HOST = os.getenv("AVATO_HOST", "localhost")
AVATO_PORT = int(os.getenv("AVATO_PORT", "3000"))
AVATO_USE_TLS = True if os.getenv("AVATO_USE_TLS") else False

import os

AVATO_HOST = os.getenv("AVATO_HOST", "api.decentriq.ch")
AVATO_PORT = int(os.getenv("AVATO_PORT", "443"))
AVATO_USE_TLS = True if os.getenv("AVATO_USE_TLS", "true") == "true" else False

import os

def _use_tls():
    return False if os.getenv("DECENTRIQ_USE_TLS", "true") == "false" else True

DECENTRIQ_CLIENT_ID = os.getenv("DECENTRIQ_CLIENT_ID", "MHyVW112w7Ql95G96fn9rnLWkYuOLmdk")
DECENTRIQ_HOST = os.getenv("DECENTRIQ_HOST", "api-v3.decentriq.com")
DECENTRIQ_PORT = int(os.getenv("DECENTRIQ_PORT", "443"))
DECENTRIQ_USE_TLS = _use_tls()

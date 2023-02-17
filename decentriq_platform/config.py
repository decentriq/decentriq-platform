import os

def _use_tls():
    return False if os.getenv("DECENTRIQ_USE_TLS", "true") == "false" else True

DECENTRIQ_CLIENT_ID = os.getenv("DECENTRIQ_CLIENT_ID", "MHyVW112w7Ql95G96fn9rnLWkYuOLmdk")
DECENTRIQ_HOST = os.getenv("DECENTRIQ_HOST", "api.decentriq.com")
DECENTRIQ_PORT = int(os.getenv("DECENTRIQ_PORT", "443"))
DECENTRIQ_USE_TLS = _use_tls()
DECENTRIQ_REQUEST_RETRY_TOTAL = int(os.getenv("DECENTRIQ_REQUEST_RETRY_TOTAL", "3"))
DECENTRIQ_REQUEST_RETRY_BACKOFF_FACTOR = float(os.getenv("DECENTRIQ_REQUEST_RETRY_BACKOFF_FACTOR", "0"))

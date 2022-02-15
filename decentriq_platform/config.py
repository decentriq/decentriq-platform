import os

DECENTRIQ_CLIENT_ID = os.getenv("DECENTRIQ_CLIENT_ID", "MHyVW112w7Ql95G96fn9rnLWkYuOLmdk")
DECENTRIQ_HOST = os.getenv("DECENTRIQ_HOST", "api.decentriq.com")
DECENTRIQ_PORT = int(os.getenv("DECENTRIQ_PORT", "443"))
DECENTRIQ_USE_TLS = True if os.getenv("DECENTRIQ_USE_TLS", "true") == "true" else False

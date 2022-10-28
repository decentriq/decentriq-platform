import os

DECENTRIQ_CLIENT_ID = os.getenv("DECENTRIQ_CLIENT_ID", "MHyVW112w7Ql95G96fn9rnLWkYuOLmdk")

DECENTRIQ_HOST = os.getenv("DECENTRIQ_HOST", "api-ch.decentriq.com")
DECENTRIQ_PORT = int(os.getenv("DECENTRIQ_PORT", "443"))
DECENTRIQ_USE_TLS = False if os.getenv("DECENTRIQ_USE_TLS", "true") == "false" else True

DECENTRIQ_API_CORE_HOST = os.getenv("DECENTRIQ_API_CORE_HOST", None)

if "DECENTRIQ_API_CORE_PORT" in os.environ:
    DECENTRIQ_API_CORE_PORT = int(os.getenv("DECENTRIQ_API_CORE_PORT"))
else:
    DECENTRIQ_API_CORE_PORT = None

if "DECENTRIQ_API_CORE_USE_TLS" in os.environ:
    DECENTRIQ_API_CORE_USE_TLS = False if os.getenv("DECENTRIQ_API_CORE_USE_TLS", "true") == "false" else True
else:
    DECENTRIQ_API_CORE_USE_TLS = None

DECENTRIQ_API_PLATFORM_HOST = os.getenv("DECENTRIQ_API_PLATFORM_HOST", None)

if "DECENTRIQ_API_PLATFORM_PORT" in os.environ:
    DECENTRIQ_API_PLATFORM_PORT = int(os.getenv("DECENTRIQ_API_PLATFORM_PORT"))
else:
    DECENTRIQ_API_PLATFORM_PORT = None

if "DECENTRIQ_API_PLATFORM_USE_TLS" in os.environ:
    DECENTRIQ_API_PLATFORM_USE_TLS = False if os.getenv("DECENTRIQ_API_PLATFORM_USE_TLS", "true") == "false" else True
else:
    DECENTRIQ_API_PLATFORM_USE_TLS = None

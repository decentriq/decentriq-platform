import logging, sys

logger = logging.getLogger("decentriq_platform")
logger.setLevel("INFO")
logger.addHandler(logging.StreamHandler(sys.stdout))

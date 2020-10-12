import logging
from logging import NullHandler

logger = logging.getLogger(__name__)
logger.addHandler(NullHandler())

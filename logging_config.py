"""Application-wide logging setup.

Call :func:`setup_logging` once at application start. Modules only do
``logger = logging.getLogger(__name__)`` and never add handlers. The log
file rotates, so it never exceeds ``LOG_MAX_BYTES * (LOG_BACKUP_COUNT + 1)``.
"""

import logging
import os
from logging.handlers import RotatingFileHandler
from typing import Optional

LOG_LEVEL = os.environ.get('PHISHING_LOG_LEVEL', 'INFO')
LOG_FILE = os.environ.get('PHISHING_LOG_FILE', 'logs/phishing.log')
LOG_MAX_BYTES = 5_000_000  # per file
LOG_BACKUP_COUNT = 3  # total on disk: LOG_MAX_BYTES x (count + 1)
LOG_FORMAT = '%(asctime)s %(levelname)s %(name)s: %(message)s'

_configured = False


def setup_logging(level: Optional[str] = None,
                  log_file: Optional[str] = None,
                  max_bytes: int = LOG_MAX_BYTES,
                  backup_count: int = LOG_BACKUP_COUNT,
                  force: bool = False) -> None:
    """Log to the console and to a size-capped rotating file.

    Calling it again does nothing unless ``force`` is true.
    """
    global _configured
    if _configured and not force:
        return
    log_file = log_file or LOG_FILE
    os.makedirs(os.path.dirname(log_file) or '.', exist_ok=True)
    logging.basicConfig(
        level=(level or LOG_LEVEL).upper(), format=LOG_FORMAT,
        force=True,
        handlers=[logging.StreamHandler(),
                  RotatingFileHandler(log_file, maxBytes=max_bytes,
                                      backupCount=backup_count,
                                      encoding='utf-8')])
    _configured = True

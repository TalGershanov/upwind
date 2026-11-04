"""Application-wide logging setup.

Call :func:`setup_logging` once at application start. Modules only do
``logger = logging.getLogger(__name__)`` and never add handlers.

Disk usage is capped: the rotating file never exceeds
``LOG_MAX_BYTES * (LOG_BACKUP_COUNT + 1)`` bytes in total, and every
message is cut to ``LOG_MAX_MESSAGE_CHARS`` characters.
"""

import logging
import logging.config
import os
from typing import Optional

from logic import config

LOG_FORMAT = '%(asctime)s %(levelname)s %(name)s: %(message)s'
TRUNCATION_MARK = '…[truncated]'

_configured = False


class TruncateFilter(logging.Filter):
    """Cut log messages longer than ``max_chars`` characters.

    A traceback from ``logger.exception`` is folded into the message
    first, so it counts toward the limit too.
    """

    _formatter = logging.Formatter()

    def __init__(self, max_chars: int = config.LOG_MAX_MESSAGE_CHARS):
        super().__init__()
        self.max_chars = max_chars

    def filter(self, record: logging.LogRecord) -> bool:
        message = record.getMessage()
        if record.exc_info:
            message += '\n' + self._formatter.formatException(
                record.exc_info)
            record.exc_info = None
            record.exc_text = None
            record.msg, record.args = message, None
        if len(message) > self.max_chars:
            record.msg = message[:self.max_chars] + TRUNCATION_MARK
            record.args = None
        return True


def setup_logging(level: Optional[str] = None,
                  log_file: Optional[str] = None,
                  max_bytes: int = config.LOG_MAX_BYTES,
                  backup_count: int = config.LOG_BACKUP_COUNT,
                  max_chars: int = config.LOG_MAX_MESSAGE_CHARS,
                  force: bool = False) -> None:
    """Configure console and size-capped rotating file logging.

    Calling it again does nothing unless ``force`` is true.

    Raises:
        ValueError: if the size limits would disable rotation.
    """
    global _configured
    if _configured and not force:
        return
    if max_bytes <= 0 or backup_count < 1:
        raise ValueError('log rotation needs max_bytes > 0 and '
                         'backup_count >= 1')
    if max_chars <= 0:
        raise ValueError('max_chars must be > 0')

    log_file = log_file or config.LOG_FILE
    log_dir = os.path.dirname(log_file)
    if log_dir:
        os.makedirs(log_dir, exist_ok=True)

    logging.config.dictConfig({
        'version': 1,
        'disable_existing_loggers': False,
        'filters': {
            'truncate': {'()': TruncateFilter, 'max_chars': max_chars},
        },
        'formatters': {
            'default': {'format': LOG_FORMAT},
        },
        'handlers': {
            'console': {
                'class': 'logging.StreamHandler',
                'formatter': 'default',
                'filters': ['truncate'],
            },
            'file': {
                'class': 'logging.handlers.RotatingFileHandler',
                'formatter': 'default',
                'filters': ['truncate'],
                'filename': log_file,
                'maxBytes': max_bytes,
                'backupCount': backup_count,
                'encoding': 'utf-8',
            },
        },
        'root': {
            'level': (level or config.LOG_LEVEL).upper(),
            'handlers': ['console', 'file'],
        },
    })
    _configured = True

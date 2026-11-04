"""Deployment step: create the DB tables. Run: python -m dal.init_db"""

import logging
import sys

from dal.db_config import create_history_store
from logic.logging_config import setup_logging

logger = logging.getLogger(__name__)


def main() -> None:
    setup_logging()
    try:
        create_history_store().create_schema()
        logger.info('Schema created')
    except Exception:
        logger.exception('Schema creation failed')
        sys.exit(1)


if __name__ == '__main__':
    main()

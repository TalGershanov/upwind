"""The bundled list of popular domains (Tranco)."""

import functools
import logging

from logic import config

logger = logging.getLogger(__name__)


@functools.cache
def load_top_domains(path: str = config.TRANCO_FILE) -> frozenset:
    """Return the registered domains in ``path`` (one per line).

    Blank lines and ``#`` comments are ignored. A missing or unreadable
    file gives an empty set (logged as an error), so analysis keeps
    working without it. The result is cached, so the file is read once.
    """
    try:
        with open(path, encoding='utf-8') as f:
            lines = [line.strip().lower() for line in f]
    except OSError:
        logger.error('Popular-domains file %s could not be read', path)
        return frozenset()
    return frozenset(line for line in lines
                     if line and not line.startswith('#'))

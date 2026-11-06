"""The interface of the data access layer.

:class:`HistoryStore` only fetches and stores; it decides nothing. The logic
layer calls it (and can mock it in tests), and the DAL implements it.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from typing import Optional


@dataclass
class Reputation:
    """What is known about a sender domain."""

    first_seen: datetime
    legit_count: int = 0
    phishing_count: int = 0


@dataclass(frozen=True)
class BlocklistEntry:
    """A blocklisted sender domain.

    ``report`` holds the indicator results of the analysis that got it
    blocklisted, so they can still be shown on a later hit.
    """

    domain: str
    added_at: datetime
    report: Optional[dict] = None


class HistoryStore(ABC):
    """Sender blocklist and reputation."""

    @abstractmethod
    def get_blocked(self, domain: str) -> Optional[BlocklistEntry]:
        """Return the entry for ``domain``, or ``None`` if not listed."""

    @abstractmethod
    def add_blocked(self, domain: str, report: Optional[dict] = None) -> None:
        """Blocklist ``domain``, keeping the indicator ``report``."""

    @abstractmethod
    def get_reputation(self, domain: str) -> Optional[Reputation]:
        """Return the reputation of ``domain``, or ``None`` if unseen."""

    @abstractmethod
    def record_message(self, domain: str, legit: bool,
                       phishing: bool) -> None:
        """Count one analysed message from ``domain``.

        Adds 1 to ``legit_count`` if ``legit`` and 1 to ``phishing_count``
        if ``phishing``. The caller decides what counts as which.
        """

"""The contract between the logic layer and the data access layer.

The DAL implements :class:`HistoryStore`; the logic layer only depends on
this interface (dependency inversion), so it can be mocked in tests.
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
    """A blocklisted domain, IP or attachment hash.

    ``report`` holds the indicator results of the analysis that got it
    blocklisted (``None`` for entries added by hand), so they can still
    be shown on a later hit.
    """

    kind: str  # 'domain', 'ip' or 'hash'
    value: str
    added_at: datetime
    report: Optional[dict] = None


class HistoryStore(ABC):
    """Blocklist, sender reputation and the growing legit-domain list."""

    @abstractmethod
    def get_blocklist_entry(self, kind: str,
                            value: str) -> Optional[BlocklistEntry]:
        """Return the entry for ``value``, or ``None`` if not listed."""

    @abstractmethod
    def add_to_blocklist(self, kind: str, value: str,
                         report: Optional[dict] = None) -> None:
        """Blocklist ``value``, keeping the indicator ``report``."""

    @abstractmethod
    def get_reputation(self, domain: str) -> Optional[Reputation]:
        """Return the reputation of ``domain``, or ``None`` if unseen."""

    @abstractmethod
    def record_message(self, domain: str, verdict: int,
                       fully_authenticated: bool) -> None:
        """Count one analysed message from ``domain``.

        Against data poisoning, a message may only add to ``legit_count``
        when ``fully_authenticated`` is true (SPF, DKIM and DMARC all
        passed). A phishing verdict adds to ``phishing_count``.
        """

    @abstractmethod
    def get_legit_domains(self) -> set:
        """Return the registered domains known to be legit."""

    @abstractmethod
    def add_legit_domain(self, domain: str) -> None:
        """Add ``domain`` to the legit list."""

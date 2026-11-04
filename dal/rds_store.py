"""PostgreSQL (Amazon RDS) implementation of :class:`HistoryStore`.

Rotation safety: when built with ``refresh_url``, a DB authentication
failure (e.g. the password was rotated in Secrets Manager) triggers one
secret re-fetch, an engine rebuild and a single retry of the operation.
"""

import functools
import logging
import threading
from datetime import datetime, timezone
from typing import Callable, Optional, Union

from sqlalchemy import create_engine, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.engine import URL
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import sessionmaker

from dal.models import Base, Blocklist, LegitDomain
from dal.models import Reputation as ReputationRow
from logic import config
from logic.history_store import BlocklistEntry, HistoryStore, Reputation

logger = logging.getLogger(__name__)

# invalid_password, invalid_authorization_specification
AUTH_PGCODES = frozenset({'28P01', '28000'})
AUTH_MESSAGES = ('password authentication failed',)


def _norm(domain: str) -> str:
    """Canonical form of a domain/value used as a key."""
    return domain.strip().rstrip('.').lower()


def _is_auth_error(exc: OperationalError) -> bool:
    """True if ``exc`` means the DB rejected our credentials.

    psycopg2 leaves ``pgcode`` unset for connect-time failures, so the
    libpq message is checked as well.
    """
    orig = getattr(exc, 'orig', None)
    if getattr(orig, 'pgcode', None) in AUTH_PGCODES:
        return True
    message = str(orig if orig is not None else exc).lower()
    return any(marker in message for marker in AUTH_MESSAGES)


def _retry_on_auth_failure(method):
    """Re-fetch credentials and retry ``method`` once on an auth failure.

    Safe for writes: auth fails while connecting, before any statement
    runs, so the first attempt has no effect.
    """
    @functools.wraps(method)
    def wrapper(self, *args, **kwargs):
        generation = self._generation
        try:
            return method(self, *args, **kwargs)
        except OperationalError as exc:
            if self._refresh_url is None or not _is_auth_error(exc):
                raise
            self._refresh(generation, exc)
        return method(self, *args, **kwargs)
    return wrapper


class RDSHistoryStore(HistoryStore):
    """History store backed by a PostgreSQL database."""

    def __init__(self, db_url: Union[str, URL], *,
                 refresh_url: Optional[Callable[[], URL]] = None):
        """
        Args:
            db_url: Connection URL; SSL is set via the URL
                (e.g. ``?sslmode=require``).
            refresh_url: Returns a fresh URL (re-reads the secret). When
                given, auth failures trigger one refresh and retry.
        """
        self._refresh_url = refresh_url
        self._lock = threading.Lock()
        self._generation = 0
        self._build_engine(db_url)

    def _build_engine(self, db_url: Union[str, URL]) -> None:
        # Fail fast when RDS is unreachable.
        self._engine = create_engine(
            db_url, pool_pre_ping=True, pool_size=5, pool_timeout=10,
            connect_args={'connect_timeout': 5})
        self._session = sessionmaker(self._engine, expire_on_commit=False)

    def _refresh(self, seen_generation: int,
                 cause: Optional[BaseException] = None) -> None:
        """Rebuild the engine from a fresh URL, once per failure wave."""
        with self._lock:
            if self._generation != seen_generation:
                return  # another thread already rebuilt the engine
            try:
                url = self._refresh_url()
            except Exception as exc:
                raise exc from cause
            old_engine = self._engine
            self._build_engine(url)
            self._generation += 1
            old_engine.dispose()
            logger.warning('DB authentication failed; re-fetched the secret '
                           'and rebuilt the engine')

    @_retry_on_auth_failure
    def create_schema(self) -> None:
        """Create the tables; run once as a deployment/init step."""
        Base.metadata.create_all(self._engine)

    @_retry_on_auth_failure
    def get_blocklist_entry(self, kind: str,
                            value: str) -> Optional[BlocklistEntry]:
        with self._session() as session:
            row = session.get(Blocklist, (kind, _norm(value)))
            if row is None:
                return None
            return BlocklistEntry(kind=row.kind, value=row.value,
                                  added_at=row.added_at, report=row.report)

    @_retry_on_auth_failure
    def add_to_blocklist(self, kind: str, value: str,
                         report: Optional[dict] = None) -> None:
        with self._session.begin() as session:
            # Keep the original added_at/report if already listed.
            session.execute(
                pg_insert(Blocklist)
                .values(kind=kind, value=_norm(value),
                        added_at=datetime.now(timezone.utc), report=report)
                .on_conflict_do_nothing(index_elements=['kind', 'value']))

    @_retry_on_auth_failure
    def get_reputation(self, domain: str) -> Optional[Reputation]:
        with self._session() as session:
            row = session.get(ReputationRow, _norm(domain))
            if row is None:
                return None
            return Reputation(first_seen=row.first_seen,
                              legit_count=row.legit_count,
                              phishing_count=row.phishing_count)

    @_retry_on_auth_failure
    def record_message(self, domain: str, verdict: int,
                       fully_authenticated: bool) -> None:
        domain = _norm(domain)
        legit = fully_authenticated and verdict == config.NOT_PHISHING
        phishing = verdict >= config.PROBABLY_PHISHING
        legit_inc, phishing_inc = int(legit), int(phishing)
        with self._session.begin() as session:
            # One atomic upsert; first_seen comes from the model default.
            session.execute(
                pg_insert(ReputationRow)
                .values(domain=domain, legit_count=legit_inc,
                        phishing_count=phishing_inc)
                .on_conflict_do_update(
                    index_elements=['domain'],
                    set_={'legit_count':
                          ReputationRow.legit_count + legit_inc,
                          'phishing_count':
                          ReputationRow.phishing_count + phishing_inc}))

    @_retry_on_auth_failure
    def get_legit_domains(self) -> set:
        with self._session() as session:
            return set(session.scalars(select(LegitDomain.domain)))

    @_retry_on_auth_failure
    def add_legit_domain(self, domain: str) -> None:
        with self._session.begin() as session:
            session.execute(
                pg_insert(LegitDomain)
                .values(domain=_norm(domain))
                .on_conflict_do_nothing(index_elements=['domain']))

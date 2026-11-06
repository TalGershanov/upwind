"""PostgreSQL (Amazon RDS) implementation of :class:`HistoryStore`."""

from datetime import datetime, timezone
from typing import Callable, Optional, Union

from sqlalchemy import create_engine, event, text
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.engine import URL
from sqlalchemy.orm import sessionmaker

from dal.history_store import BlocklistEntry, HistoryStore, Reputation
from dal.models import Base, BlockedDomain
from dal.models import Reputation as ReputationRow

SCHEMA_LOCK_KEY = 7_201_944  # arbitrary; serialises concurrent create_schema


def _norm(domain: str) -> str:
    """Canonical form of a domain used as a key."""
    return domain.strip().rstrip('.').lower()


class RDSHistoryStore(HistoryStore):
    """History store backed by a PostgreSQL database."""

    def __init__(self, db_url: Union[str, URL], *,
                 credentials: Optional[Callable[[], tuple]] = None):
        """
        Args:
            db_url: Connection URL; SSL is set via the URL
                (e.g. ``?sslmode=require``).
            credentials: Returns ``(username, password)``. Called for every
                new connection, so a rotated password is picked up.
        """
        # Fail fast when RDS is unreachable.
        self._engine = create_engine(
            db_url, pool_pre_ping=True, pool_size=5, pool_timeout=10,
            connect_args={'connect_timeout': 5})
        if credentials is not None:
            @event.listens_for(self._engine, 'do_connect')
            def _set_credentials(dialect, conn_rec, cargs, cparams):
                cparams['user'], cparams['password'] = credentials()
        self._session = sessionmaker(self._engine, expire_on_commit=False)

    def create_schema(self) -> None:
        """Create the tables; run at deployment.

        A Postgres advisory lock makes instances booting at the same time
        take turns instead of racing on ``CREATE TABLE``.
        """
        with self._engine.begin() as conn:
            conn.execute(text('SELECT pg_advisory_xact_lock(:key)'),
                         {'key': SCHEMA_LOCK_KEY})
            Base.metadata.create_all(conn)

    def ping(self, timeout_ms: int = 2000) -> None:
        """Cheap liveness check: SELECT 1 with a server-side timeout."""
        with self._engine.begin() as conn:
            conn.execute(text(f'SET LOCAL statement_timeout = {int(timeout_ms)}'))
            conn.execute(text('SELECT 1'))

    def get_blocked(self, domain: str) -> Optional[BlocklistEntry]:
        with self._session() as session:
            row = session.get(BlockedDomain, _norm(domain))
            if row is None:
                return None
            return BlocklistEntry(domain=row.domain, added_at=row.added_at,
                                  report=row.report)

    def add_blocked(self, domain: str, report: Optional[dict] = None) -> None:
        with self._session.begin() as session:
            # Keep the original added_at/report if already listed.
            session.execute(
                pg_insert(BlockedDomain)
                .values(domain=_norm(domain),
                        added_at=datetime.now(timezone.utc), report=report)
                .on_conflict_do_nothing(index_elements=['domain']))

    def get_reputation(self, domain: str) -> Optional[Reputation]:
        with self._session() as session:
            row = session.get(ReputationRow, _norm(domain))
            if row is None:
                return None
            return Reputation(first_seen=row.first_seen,
                              legit_count=row.legit_count,
                              phishing_count=row.phishing_count)

    def record_message(self, domain: str, legit: bool,
                       phishing: bool) -> None:
        domain = _norm(domain)
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

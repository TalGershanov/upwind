"""PostgreSQL (Amazon RDS) implementation of :class:`HistoryStore`."""

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import create_engine, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import sessionmaker

from dal.models import Base, Blocklist, LegitDomain
from dal.models import Reputation as ReputationRow
from logic import config
from logic.history_store import BlocklistEntry, HistoryStore, Reputation


def _norm(domain: str) -> str:
    """Canonical form of a domain/value used as a key."""
    return domain.strip().rstrip('.').lower()


class RDSHistoryStore(HistoryStore):
    """History store backed by a PostgreSQL database."""

    def __init__(self, db_url: str):
        # Fail fast when RDS is unreachable; SSL is set via the URL
        # (e.g. ``?sslmode=require``).
        self._engine = create_engine(
            db_url, pool_pre_ping=True, pool_size=5, pool_timeout=10,
            connect_args={'connect_timeout': 5})
        self._session = sessionmaker(self._engine, expire_on_commit=False)

    def create_schema(self) -> None:
        """Create the tables; run once as a deployment/init step."""
        Base.metadata.create_all(self._engine)

    def get_blocklist_entry(self, kind: str,
                            value: str) -> Optional[BlocklistEntry]:
        with self._session() as session:
            row = session.get(Blocklist, (kind, _norm(value)))
            if row is None:
                return None
            return BlocklistEntry(kind=row.kind, value=row.value,
                                  added_at=row.added_at, report=row.report)

    def add_to_blocklist(self, kind: str, value: str,
                         report: Optional[dict] = None) -> None:
        with self._session.begin() as session:
            # Keep the original added_at/report if already listed.
            session.execute(
                pg_insert(Blocklist)
                .values(kind=kind, value=_norm(value),
                        added_at=datetime.now(timezone.utc), report=report)
                .on_conflict_do_nothing(index_elements=['kind', 'value']))

    def get_reputation(self, domain: str) -> Optional[Reputation]:
        with self._session() as session:
            row = session.get(ReputationRow, _norm(domain))
            if row is None:
                return None
            return Reputation(first_seen=row.first_seen,
                              legit_count=row.legit_count,
                              phishing_count=row.phishing_count)

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

    def get_legit_domains(self) -> set:
        with self._session() as session:
            return set(session.scalars(select(LegitDomain.domain)))

    def add_legit_domain(self, domain: str) -> None:
        with self._session.begin() as session:
            session.execute(
                pg_insert(LegitDomain)
                .values(domain=_norm(domain))
                .on_conflict_do_nothing(index_elements=['domain']))

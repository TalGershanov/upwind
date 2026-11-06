"""SQLAlchemy models for the phishing history store (PostgreSQL)."""

from datetime import datetime, timezone

from sqlalchemy import JSON, Column, DateTime, Integer, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import declarative_base

Base = declarative_base()


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Reputation(Base):
    """Per-sender-domain message counters."""

    __tablename__ = 'reputation'

    domain = Column(String, primary_key=True)
    first_seen = Column(DateTime(timezone=True), nullable=False,
                        default=_utcnow)
    legit_count = Column(Integer, nullable=False, default=0)
    phishing_count = Column(Integer, nullable=False, default=0)


class BlockedDomain(Base):
    """A blocklisted sender domain and the report that got it listed.

    (The older ``blocklist`` table, keyed by kind and value, is no longer
    used; a new name lets ``create_all`` add this one on a live database.)
    """

    __tablename__ = 'blocked_domains'

    domain = Column(String, primary_key=True)
    added_at = Column(DateTime(timezone=True), nullable=False,
                      default=_utcnow)
    report = Column(JSON().with_variant(JSONB(), 'postgresql'),
                    nullable=True)

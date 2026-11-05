"""Secret-rotation safety of RDSHistoryStore, with a mocked database.

The fake DB accepts only its *current* password; an engine built with any
other password fails like psycopg2 does on a rotated secret.
"""

import logging

import psycopg2
import pytest
from sqlalchemy.engine import URL
from sqlalchemy.exc import OperationalError

from dal import rds_store
from dal.db_config import DBConfigError, create_history_store
from dal.rds_store import RDSHistoryStore, _is_auth_error
from tests.test_db_config import FakeSecretsClient, make_env

OLD_PASSWORD = 'old-Pa55word'
NEW_PASSWORD = 'new-Pa55word'


def auth_error():
    return OperationalError(None, None, psycopg2.OperationalError(
        'connection to server failed: FATAL:  password authentication '
        'failed for user "app"'))


def url_with(password):
    return URL.create('postgresql+psycopg2', username='app',
                      password=password, host='db.example', port=5432,
                      database='phishing', query={'sslmode': 'require'})


class FakeDB:
    """Shared state of the fake server: current password + executed ops."""

    def __init__(self, password):
        self.password = password
        self.executed = []
        self.error = None  # force a specific error on every op


class FakeEngine:
    def __init__(self, url, db):
        self.url = url
        self.db = db
        self.disposed = False

    def dispose(self):
        self.disposed = True


class FakeSession:
    def __init__(self, engine):
        self.engine = engine

    def _connect(self):
        db = self.engine.db
        if db.error is not None:
            raise db.error
        if self.engine.url.password != db.password:
            raise auth_error()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute(self, statement):
        self._connect()
        self.engine.db.executed.append(statement)

    def get(self, model, key):
        self._connect()
        return None


class FakeSessionMaker:
    def __init__(self, engine, **kwargs):
        self.engine = engine

    def __call__(self):
        return FakeSession(self.engine)

    def begin(self):
        return FakeSession(self.engine)


@pytest.fixture
def db(monkeypatch):
    fake_db = FakeDB(OLD_PASSWORD)
    engines = []

    def fake_create_engine(url, **kwargs):
        engine = FakeEngine(url, fake_db)
        engines.append(engine)
        return engine

    monkeypatch.setattr(rds_store, 'create_engine', fake_create_engine)
    monkeypatch.setattr(rds_store, 'sessionmaker', FakeSessionMaker)
    fake_db.engines = engines
    return fake_db


class Refresher:
    """Counts calls; returns a URL with the given password."""

    def __init__(self, password=NEW_PASSWORD, error=None):
        self.password = password
        self.error = error
        self.calls = 0

    def __call__(self):
        self.calls += 1
        if self.error is not None:
            raise self.error
        return url_with(self.password)


class TestRotation:
    def test_auth_failure_refreshes_and_retries(self, db):
        refresh = Refresher()
        store = RDSHistoryStore(url_with(OLD_PASSWORD), refresh_url=refresh)
        db.password = NEW_PASSWORD  # secret rotated

        assert store.get_reputation('example.com') is None
        assert refresh.calls == 1
        assert len(db.engines) == 2
        assert db.engines[0].disposed
        assert db.engines[1].url.password == NEW_PASSWORD
        assert not db.engines[1].disposed

    def test_no_refresh_when_credentials_work(self, db):
        refresh = Refresher()
        store = RDSHistoryStore(url_with(OLD_PASSWORD), refresh_url=refresh)
        store.get_reputation('example.com')
        assert refresh.calls == 0
        assert len(db.engines) == 1

    def test_write_executes_exactly_once(self, db):
        refresh = Refresher()
        store = RDSHistoryStore(url_with(OLD_PASSWORD), refresh_url=refresh)
        db.password = NEW_PASSWORD

        store.record_message('example.com', 0, True)
        assert len(db.executed) == 1
        assert refresh.calls == 1

    def test_later_calls_use_new_engine(self, db):
        refresh = Refresher()
        store = RDSHistoryStore(url_with(OLD_PASSWORD), refresh_url=refresh)
        db.password = NEW_PASSWORD
        store.get_reputation('example.com')
        store.get_reputation('a.com')
        assert refresh.calls == 1

    def test_retries_only_once(self, db):
        refresh = Refresher(password='still-wrong')
        store = RDSHistoryStore(url_with(OLD_PASSWORD), refresh_url=refresh)
        db.password = NEW_PASSWORD

        with pytest.raises(OperationalError) as info:
            store.get_reputation('example.com')
        assert _is_auth_error(info.value)
        assert refresh.calls == 1

    def test_non_auth_error_is_not_retried(self, db):
        refresh = Refresher()
        store = RDSHistoryStore(url_with(OLD_PASSWORD), refresh_url=refresh)
        db.error = OperationalError(None, None, psycopg2.OperationalError(
            'could not connect to server: Connection timed out'))

        with pytest.raises(OperationalError, match='timed out'):
            store.get_reputation('example.com')
        assert refresh.calls == 0
        assert len(db.engines) == 1

    def test_without_refresh_url_auth_error_propagates(self, db):
        store = RDSHistoryStore(url_with(OLD_PASSWORD))
        db.password = NEW_PASSWORD
        with pytest.raises(OperationalError, match='password authentication'):
            store.get_reputation('example.com')
        assert len(db.engines) == 1

    def test_refresh_failure_propagates_with_cause(self, db):
        refresh = Refresher(error=DBConfigError('could not read DB secret'))
        store = RDSHistoryStore(url_with(OLD_PASSWORD), refresh_url=refresh)
        db.password = NEW_PASSWORD

        with pytest.raises(DBConfigError) as info:
            store.get_reputation('example.com')
        assert isinstance(info.value.__cause__, OperationalError)
        assert not db.engines[0].disposed  # old engine kept

    def test_stale_generation_does_not_refetch(self, db):
        refresh = Refresher()
        store = RDSHistoryStore(url_with(OLD_PASSWORD), refresh_url=refresh)
        stale = store._generation
        store._refresh(stale)
        assert refresh.calls == 1
        store._refresh(stale)  # e.g. a second thread with the same failure
        assert refresh.calls == 1

    def test_passwords_not_logged(self, db, caplog):
        store = RDSHistoryStore(url_with(OLD_PASSWORD),
                                refresh_url=Refresher())
        db.password = NEW_PASSWORD
        with caplog.at_level(logging.DEBUG):
            store.get_reputation('example.com')
        assert 'rebuilt the engine' in caplog.text
        assert OLD_PASSWORD not in caplog.text
        assert NEW_PASSWORD not in caplog.text


class TestIsAuthError:
    def test_message_match(self):
        assert _is_auth_error(auth_error())

    def test_pgcode_match(self):
        class PgError(Exception):
            pgcode = '28P01'

        assert _is_auth_error(OperationalError(None, None, PgError('x')))

    def test_other_errors(self):
        err = OperationalError(None, None,
                               psycopg2.OperationalError('server closed'))
        assert not _is_auth_error(err)


class TestCreateHistoryStore:
    def test_recovers_after_secret_rotation(self, db):
        client = FakeSecretsClient({'username': 'app',
                                    'password': OLD_PASSWORD})
        store = create_history_store(make_env(), client)
        assert store.get_reputation('example.com') is None

        # Rotation: Secrets Manager and the DB both get the new password.
        client.secret_string = ('{"username": "app", "password": "%s"}'
                                % NEW_PASSWORD)
        db.password = NEW_PASSWORD

        assert store.get_reputation('example.com') is None
        assert len(client.calls) == 2
        assert db.engines[-1].url.password == NEW_PASSWORD

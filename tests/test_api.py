from unittest.mock import create_autospec

import pytest
from fastapi.testclient import TestClient

from api.main import MAX_BYTES, app
from dal.rds_store import RDSHistoryStore

SAMPLE = 'tests/data/sample_wolt.txt'


@pytest.fixture
def store():
    store = create_autospec(RDSHistoryStore, instance=True)
    store.get_blocklist_entry.return_value = None
    store.get_reputation.return_value = None
    store.get_legit_domains.return_value = set()
    return store


@pytest.fixture
def client(store, monkeypatch):
    # Keep the lifespan from setting logging's module-level _configured flag
    # or creating logs/phishing.log (would break test_logging_config.py).
    monkeypatch.setattr('api.main.setup_logging', lambda: None)
    # Set before entering TestClient so the lifespan guards skip AWS.
    app.state.store = store
    app.state.instance_id = 'i-test'
    with TestClient(app) as c:
        yield c


def post(client, data):
    return client.post('/api/analyze', files={'file': ('m.eml', data)})


def test_analyze_ok(client):
    with open(SAMPLE, 'rb') as f:
        r = post(client, f.read())
    assert r.status_code == 200
    body = r.json()
    assert 'verdict_name' in body and 'score' in body


def test_analyze_empty(client):
    assert post(client, b'').status_code == 400


def test_analyze_garbage(client):
    r = post(client, b'\x00\x01\x02 not an email')
    assert r.status_code == 400
    assert r.json()['detail'] == 'Could not parse email'


def test_analyze_too_large(client):
    assert post(client, b'a' * (MAX_BYTES + 1)).status_code == 413


def test_health_does_not_touch_store(client, store):
    assert client.get('/health').json() == {'status': 'ok'}
    assert store.method_calls == []


def test_health_deep_ok(client, store):
    r = client.get('/health/deep')
    assert r.status_code == 200 and r.json() == {'db': 'ok'}
    store.ping.assert_called_once()


def test_health_deep_failure(client, store):
    store.ping.side_effect = RuntimeError('db down')
    r = client.get('/health/deep')
    assert r.status_code == 503 and r.json() == {'db': 'error'}


def test_instance_id_header(client):
    assert client.get('/health').headers['X-Instance-Id'] == 'i-test'

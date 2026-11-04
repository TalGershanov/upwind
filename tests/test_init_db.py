from unittest.mock import MagicMock

import pytest

from dal import init_db


def test_main_success(monkeypatch):
    store = MagicMock()
    monkeypatch.setattr(init_db, 'setup_logging', lambda: None)
    monkeypatch.setattr(init_db, 'create_history_store', lambda: store)
    init_db.main()
    store.create_schema.assert_called_once()


def test_main_failure_exits_1(monkeypatch):
    store = MagicMock()
    store.create_schema.side_effect = RuntimeError('boom')
    monkeypatch.setattr(init_db, 'setup_logging', lambda: None)
    monkeypatch.setattr(init_db, 'create_history_store', lambda: store)
    with pytest.raises(SystemExit) as exc:
        init_db.main()
    assert exc.value.code == 1

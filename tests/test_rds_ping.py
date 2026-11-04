from unittest.mock import MagicMock

from dal.rds_store import RDSHistoryStore


def test_ping_sets_timeout_then_selects():
    store = RDSHistoryStore.__new__(RDSHistoryStore)
    store._refresh_url = None
    store._generation = 0
    conn = MagicMock()
    store._engine = MagicMock()
    store._engine.begin.return_value.__enter__.return_value = conn

    store.ping(timeout_ms=1500)

    sql = [str(c.args[0]) for c in conn.execute.call_args_list]
    assert sql == ['SET LOCAL statement_timeout = 1500', 'SELECT 1']

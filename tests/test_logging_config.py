"""Tests for the logging setup and the analysis log lines."""

import logging
import os
from pathlib import Path
from unittest.mock import create_autospec

import pytest

from logic import logging_config
from logic.email_parser import parse_email
from logic.history_store import HistoryStore
from logic.indicators import Indicators
from logic.logging_config import TRUNCATION_MARK, setup_logging

SAMPLE = Path(__file__).parent / 'data' / 'sample_wolt.txt'


def _analyzer():
    store = create_autospec(HistoryStore, instance=True)
    store.get_blocklist_entry.return_value = None
    store.get_reputation.return_value = None
    return Indicators(parse_email(SAMPLE.read_text(encoding='utf-8')),
                      store)


@pytest.fixture
def restore_logging():
    """Undo setup_logging() so it does not leak into other tests."""
    root = logging.getLogger()
    handlers, level = root.handlers[:], root.level
    yield
    for handler in root.handlers:
        if handler not in handlers:
            handler.close()
    root.handlers[:] = handlers
    root.setLevel(level)
    logging_config._configured = False


class TestLogging:

    def test_analysis_logs_one_info_line(self, caplog):
        with caplog.at_level(logging.INFO, logger='logic'):
            _analyzer().analyze()
        info = [r for r in caplog.records if r.levelno == logging.INFO]
        assert len(info) == 1
        assert 'from_domain=wolt.com' in info[0].getMessage()
        assert 'verdict=' in info[0].getMessage()

    def test_full_address_is_not_logged(self, caplog):
        with caplog.at_level(logging.DEBUG):
            _analyzer().analyze()
        assert caplog.records
        assert 'info@wolt.com' not in caplog.text

    def test_long_message_is_truncated(self, tmp_path, restore_logging):
        log_file = tmp_path / 'app.log'
        setup_logging(level='INFO', log_file=str(log_file), max_chars=50,
                      force=True)
        logging.getLogger('logic.test').info('x' * 500)
        text = log_file.read_text(encoding='utf-8')
        assert TRUNCATION_MARK in text
        assert 'x' * 51 not in text

    def test_exception_traceback_is_truncated(self, tmp_path,
                                              restore_logging):
        log_file = tmp_path / 'app.log'
        setup_logging(level='INFO', log_file=str(log_file), max_chars=200,
                      force=True)
        try:
            raise ValueError('y' * 5000)
        except ValueError:
            logging.getLogger('logic.test').exception('parse failed')
        text = log_file.read_text(encoding='utf-8')
        assert 'parse failed' in text
        assert TRUNCATION_MARK in text
        assert 'y' * 201 not in text

    def test_log_rotation_caps_disk_usage(self, tmp_path, restore_logging):
        log_file = tmp_path / 'app.log'
        setup_logging(level='INFO', log_file=str(log_file), max_bytes=300,
                      backup_count=2, force=True)
        log = logging.getLogger('logic.test')
        for i in range(200):
            log.info('record number %d', i)
        files = sorted(os.listdir(tmp_path))
        assert files == ['app.log', 'app.log.1', 'app.log.2']
        assert all(os.path.getsize(tmp_path / name) <= 300 for name in files)

    def test_setup_twice_adds_no_duplicate_handlers(self, tmp_path,
                                                    restore_logging):
        setup_logging(log_file=str(tmp_path / 'logs' / 'app.log'),
                      force=True)
        count = len(logging.getLogger().handlers)
        setup_logging(log_file=str(tmp_path / 'other.log'))
        assert len(logging.getLogger().handlers) == count
        assert (tmp_path / 'logs').is_dir()
        assert not (tmp_path / 'other.log').exists()

    @pytest.mark.parametrize('kwargs', [{'max_bytes': 0},
                                        {'backup_count': 0},
                                        {'max_chars': 0}])
    def test_rotation_cannot_be_disabled(self, tmp_path, kwargs,
                                         restore_logging):
        with pytest.raises(ValueError):
            setup_logging(log_file=str(tmp_path / 'app.log'), force=True,
                          **kwargs)

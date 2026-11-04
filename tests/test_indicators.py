"""Tests for the indicators, run on the example email in tests/data.

The history store is a stand-in with no data: every lookup answers
"nothing known". It goes away once the real DAL exists.
"""

import json
from pathlib import Path
from unittest.mock import create_autospec

import pytest

from logic import config
from logic.email_parser import parse_email
from logic.history_store import HistoryStore
from logic.indicators import (INDICATOR_MAP, IndicatorResult, Indicators,
                              score_sender_auth)

DATA = Path(__file__).parent / 'data'
SAMPLE_TEXT = (DATA / 'sample_wolt.txt').read_text(encoding='utf-8')


def empty_store():
    store = create_autospec(HistoryStore, instance=True)
    store.get_blocklist_entry.return_value = None
    store.get_reputation.return_value = None
    store.get_legit_domains.return_value = set()
    return store


def analyzer(text=SAMPLE_TEXT, store=None):
    return Indicators(parse_email(text), store or empty_store())


def with_sender(domain, display='Alice'):
    """The example email, sent from ``display <alice@domain>``."""
    return SAMPLE_TEXT.replace('From: Wolt <info@wolt.com>',
                               f'From: {display} <alice@{domain}>')


def _lines(name):
    return (DATA / name).read_text(encoding='utf-8').split()


# =========================================================================
# Indicator: Sender Authentication
# =========================================================================

class TestSenderAuthentication:

    def test_real_email_sample_is_not_phishing(self):
        result = analyzer().detect_sender_impersonation()
        assert result.score == config.NOT_PHISHING

    @pytest.mark.parametrize('spf, dkim, dmarc, expected', [
        ('pass', 'pass', 'pass', config.NOT_PHISHING),
        ('fail', 'pass', 'pass', config.NOT_PHISHING),
        ('fail', 'none', 'fail', config.PHISHING),
        ('softfail', 'fail', 'fail', config.PHISHING),
        ('pass', 'none', 'fail', config.PROBABLY_PHISHING),
        ('fail', 'pass', 'none', config.PROBABLY_NOT_PHISHING),
        ('pass', 'none', 'none', config.PROBABLY_NOT_PHISHING),
        ('fail', 'none', 'none', config.PROBABLY_PHISHING),
        ('none', 'permerror', 'none', config.PROBABLY_PHISHING),
        ('none', 'none', 'none', config.PROBABLY_PHISHING),
        ('temperror', 'neutral', 'temperror', config.PROBABLY_NOT_PHISHING),
    ])
    def test_score_sender_auth(self, spf, dkim, dmarc, expected):
        assert score_sender_auth(spf, dkim, dmarc) == expected


# =========================================================================
# Indicator: Spoofed sender
# =========================================================================

class TestSpoofedSender:

    @staticmethod
    def spoof(domain, display='Alice'):
        return analyzer(with_sender(domain, display)
                        ).detect_spoofed_sender()

    def test_real_email_sample_is_not_flagged(self):
        assert analyzer().detect_spoofed_sender().score == (
            config.NOT_PHISHING)

    @pytest.mark.parametrize('domain', _lines('legit_domains.txt'))
    def test_legit_list_is_not_flagged(self, domain):
        result = self.spoof(domain)
        assert result.score == config.NOT_PHISHING, result.reasons

    @pytest.mark.parametrize('domain', _lines('phishy_domains.txt'))
    def test_phishy_list_is_flagged(self, domain):
        result = self.spoof(domain)
        assert result.score >= config.PROBABLY_PHISHING, domain


# =========================================================================
# Risk scoring
# =========================================================================

def _results(**scores):
    """IndicatorResults by short name; unlisted ones are NOT_PHISHING."""
    names = {'auth': 'Sender Authentication', 'spoof': 'Spoofed sender',
             'links': 'Suspicious links', 'files': 'Attachment analysis',
             'words': 'Suspicious wording', 'history': 'Sender history'}
    return {name: IndicatorResult(scores.get(short, config.NOT_PHISHING))
            for short, name in names.items()}


class TestRiskScoring:

    @staticmethod
    def score(results):
        return analyzer().risk_score(results)

    def test_weights_add_up_to_one(self):
        assert sum(config.INDICATOR_WEIGHTS.values()) == pytest.approx(1)

    def test_every_indicator_has_a_weight(self):
        assert set(INDICATOR_MAP) == set(config.INDICATOR_WEIGHTS)

    def test_all_clean(self):
        assert self.score(_results()) == (config.NOT_PHISHING, 1.0)

    @pytest.mark.parametrize('score, verdict', [
        (1.0, config.NOT_PHISHING), (1.74, config.NOT_PHISHING),
        (1.75, config.PROBABLY_NOT_PHISHING),
        (2.49, config.PROBABLY_NOT_PHISHING),
        (2.5, config.PROBABLY_PHISHING),
        (3.24, config.PROBABLY_PHISHING),
        (3.25, config.PHISHING), (4.0, config.PHISHING),
    ])
    def test_threshold_mapping(self, monkeypatch, score, verdict):
        monkeypatch.setattr(config, 'AMPLIFY_BONUS', 0)
        monkeypatch.setattr(config, 'STRONG_SIGNAL_INDICATORS', ())
        # one weighted indicator carries the whole score
        monkeypatch.setattr(config, 'INDICATOR_WEIGHTS',
                            {'Sender Authentication': 1.0})
        result = {'Sender Authentication': IndicatorResult(score)}
        assert self.score(result)[0] == verdict

    def test_amplification_raises_the_verdict(self, monkeypatch):
        results = _results(auth=3, spoof=3, links=3)
        assert self.score(results)[0] == config.PHISHING
        monkeypatch.setattr(config, 'AMPLIFY_BONUS', 0)
        assert self.score(results)[0] == config.PROBABLY_NOT_PHISHING

    def test_single_weak_signals_do_not_amplify(self):
        verdict, score = self.score(_results(auth=3, words=3))
        assert score == 1.6 and verdict == config.NOT_PHISHING

    def test_one_strong_signal_is_not_diluted(self):
        verdict, score = self.score(_results(links=config.PHISHING))
        assert verdict == config.PROBABLY_PHISHING
        assert score == 2.5

    def test_score_stays_on_the_scale(self):
        verdict, score = self.score(_results(
            auth=4, spoof=4, links=4, files=4, words=4, history=4))
        assert (verdict, score) == (config.PHISHING, 4.0)

    def test_wording_alone_is_not_a_floor(self):
        verdict, _ = self.score(_results(words=config.PHISHING))
        assert verdict == config.NOT_PHISHING


# =========================================================================
# analyze(): the whole pipeline
# =========================================================================

class TestAnalyze:

    def test_real_email_is_not_phishing(self):
        report = analyzer().analyze()
        assert report['verdict'] == config.NOT_PHISHING
        assert report['verdict_name'] == 'NOT_PHISHING'

    def test_real_email_is_recorded_as_legit(self):
        store = empty_store()
        analyzer(store=store).analyze()
        store.record_message.assert_called_once_with(
            'wolt.com', config.NOT_PHISHING, True)
        store.add_legit_domain.assert_called_once_with('wolt.com')

    def test_report_can_be_a_json(self):
        report = analyzer().analyze()
        assert json.loads(json.dumps(report))['verdict'] == (
            config.NOT_PHISHING)

    def test_registry(self):
        assert 'Sender Authentication' in INDICATOR_MAP
        assert len(INDICATOR_MAP) == 6

    def test_run_all_returns_results_for_every_indicator(self):
        results = analyzer().run_all()
        assert set(results) == set(INDICATOR_MAP)
        assert results['Sender Authentication'].score == config.NOT_PHISHING

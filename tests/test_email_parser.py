"""Tests for logic.email_parser, run on the example email in tests/data."""

from pathlib import Path

import pytest

from logic import email_parser
from logic.email_parser import EmailParseError, parse_email

SAMPLE = Path(__file__).parent / 'data' / 'sample_wolt.txt'


@pytest.fixture(scope='module')
def email():
    return parse_email(SAMPLE.read_text(encoding='utf-8'))


class TestParseEmail:

    def test_headers_are_parsed(self, email):
        assert email['header']['from'] == 'info@wolt.com'
        assert email['header']['subject'] == 'קבלת רכישה ב-Wolt'

    def test_authentication_results_are_parsed(self, email):
        assert email['header']['authentication'] == {
            'dkim': ['pass', 'pass'], 'spf': ['pass', 'pass'],
            'dmarc': ['pass']}

    def test_bytes_input_is_accepted(self):
        parsed = parse_email(SAMPLE.read_bytes())
        assert parsed['header']['from'] == 'info@wolt.com'

    @pytest.mark.parametrize('content', ['', '   ', b'', None, 123,
                                         'garbage no headers'])
    def test_bad_input_raises(self, content):
        with pytest.raises(EmailParseError):
            parse_email(content)


class TestAccessors:

    def test_header_returns_raw_values(self, email):
        values = email_parser.header(email, 'authentication-results')
        assert len(values) == 1
        assert values[0].startswith('mx.google.com;')

    def test_missing_header_is_empty(self, email):
        assert email_parser.header(email, 'x-no-such-header') == []

    def test_sender_domain(self, email):
        assert email_parser.sender_domain(email) == 'wolt.com'

    def test_display_name(self, email):
        assert email_parser.display_name(email) == 'Wolt'

    def test_subject(self, email):
        assert email_parser.subject(email) == 'קבלת רכישה ב-Wolt'

    def test_body_texts_are_visible_text(self, email):
        texts = list(email_parser.body_texts(email, 1000))
        assert len(texts) == 1
        assert '<' not in texts[0]

    def test_body_texts_are_cut_to_the_limit(self, email):
        assert all(len(text) <= 5
                   for text in email_parser.body_texts(email, 5))

    def test_body_urls(self, email):
        assert list(email_parser.body_urls(email)) == [
            'https://consumer-static-assets.wolt.com/email/logo-wolt.png']

    def test_attachments(self, email):
        attachments = email_parser.attachments(email)
        assert len(attachments) == 1
        assert attachments[0]['extension'] == 'pdf'
        assert attachments[0]['hash']['sha256']

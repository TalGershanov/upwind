"""Tests for the indicators, one test class per indicator.

The input is the content of a text file with the email in it, as the
API endpoint will receive it. The DAL is replaced by an in-memory store.
"""

import hashlib
import io
import json
import logging
import os
import zipfile
from datetime import datetime, timezone
from email.message import EmailMessage
from pathlib import Path

import pytest

from logic import config, indicators, logging_config
from logic.email_parser import EmailParseError, parse_email
from logic.history_store import (BlocklistEntry, HistoryStore,
                                 Reputation)
from logic.indicators import (INDICATOR_MAP, IndicatorResult, Indicators,
                              score_sender_auth)
from logic.logging_config import TRUNCATION_MARK, setup_logging

SECRET_BODY = 'secret-body-text-1234'
DATA = Path(__file__).parent / 'data'
SAMPLE_WOLT = DATA / 'sample_wolt.txt'
ALL_PASS = 'mx.google.com; spf=pass; dkim=pass; dmarc=pass'


class InMemoryHistoryStore(HistoryStore):
    """A fake DAL: the same contract, kept in dicts."""

    def __init__(self, legit_domains=()):
        self.blocklist = {}
        self.reputation = {}
        self.legit = set(legit_domains)

    def get_blocklist_entry(self, kind, value):
        return self.blocklist.get((kind, value))

    def add_to_blocklist(self, kind, value, report=None):
        self.blocklist[(kind, value)] = BlocklistEntry(
            kind, value, datetime.now(timezone.utc), report)

    def get_reputation(self, domain):
        return self.reputation.get(domain)

    def record_message(self, domain, verdict, fully_authenticated):
        rep = self.reputation.setdefault(
            domain, Reputation(first_seen=datetime.now(timezone.utc)))
        if verdict >= config.PROBABLY_PHISHING:
            rep.phishing_count += 1
        elif fully_authenticated:
            rep.legit_count += 1

    def get_legit_domains(self):
        return set(self.legit)

    def add_legit_domain(self, domain):
        self.legit.add(domain)


def make_email(auth_results=(), sender='Alice <alice@example.com>',
               subject='Invoice', body=SECRET_BODY, html=None,
               attachments=()):
    """Build the text of an email, as found in the input text file.

    ``attachments`` is a list of ``(filename, bytes, content type)``.
    """
    msg = EmailMessage()
    for value in auth_results:
        msg['Authentication-Results'] = value
    msg['From'] = sender
    msg['To'] = 'bob@victim.org'
    msg['Subject'] = subject
    msg['Message-ID'] = '<id-1@example.com>'
    msg.set_content(body)
    if html:
        msg.add_alternative(html, subtype='html')
    for filename, data, content_type in attachments:
        maintype, subtype = content_type.split('/')
        msg.add_attachment(data, maintype=maintype, subtype=subtype,
                           filename=filename)
    return msg.as_string()


def analyzer(text, store=None):
    return Indicators(parse_email(text), store or InMemoryHistoryStore())


def run(indicator_name, **kwargs):
    """Run one indicator on a freshly built email."""
    store = kwargs.pop('store', None)
    return INDICATOR_MAP[indicator_name](
        analyzer(make_email(**kwargs), store))


def zip_bytes(entries, encrypted=False):
    """A zip with ``entries`` (``{name: bytes}``), optionally flagged
    as encrypted in both headers (zipfile cannot write encryption)."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as archive:
        for name, data in entries.items():
            archive.writestr(name, data)
    data = bytearray(buf.getvalue())
    if encrypted:
        for signature, offset in ((b'PK\x03\x04', 6), (b'PK\x01\x02', 8)):
            pos = data.find(signature)
            while pos != -1:
                data[pos + offset] |= 1
                pos = data.find(signature, pos + 1)
    return bytes(data)


# =========================================================================
# Email parsing
# =========================================================================

class TestEmailParsing:

    def test_text_input_returns_eml_parser_dict(self):
        email = parse_email(make_email(auth_results=[ALL_PASS]))
        assert email['header']['from'] == 'alice@example.com'
        assert email['header']['subject'] == 'Invoice'
        assert email['header']['authentication'] == {
            'spf': ['pass'], 'dkim': ['pass'], 'dmarc': ['pass']}

    def test_text_file_is_parsed(self, tmp_path):
        path = tmp_path / 'email.txt'
        path.write_text(make_email(), encoding='utf-8')
        with open(path, encoding='utf-8') as file:
            email = parse_email(file.read())
        assert email['header']['from'] == 'alice@example.com'

    def test_bodies_and_attachments_are_available(self):
        email = parse_email(make_email(
            body='see http://45.83.64.9/x',
            attachments=[('a.txt', b'hello', 'text/plain')]))
        assert 'http://45.83.64.9/x' in email['body'][0]['uri']
        assert email['attachment'][0]['filename'] == 'a.txt'
        assert email['attachment'][0]['hash']['sha256']

    def test_real_email_sample(self):
        email = parse_email(SAMPLE_WOLT.read_text(encoding='utf-8'))
        assert email['header']['from'] == 'info@wolt.com'
        assert email['header']['subject'] == 'קבלת רכישה ב-Wolt'
        assert email['header']['authentication'] == {
            'dkim': ['pass', 'pass'], 'spf': ['pass', 'pass'],
            'dmarc': ['pass']}

    @pytest.mark.parametrize('content', ['', '   ', b'', None, 123,
                                         'garbage no headers'])
    def test_bad_input_raises(self, content):
        with pytest.raises(EmailParseError):
            parse_email(content)


# =========================================================================
# Indicator: Sender Authentication
# =========================================================================

class TestSenderAuthentication:

    @staticmethod
    def check(*auth_results):
        return run('Sender Authentication', auth_results=auth_results)

    def test_all_pass_is_not_phishing(self):
        result = self.check('mx.google.com; spf=pass '
                            'smtp.mailfrom=example.com; '
                            'dkim=pass header.d=example.com; dmarc=pass')
        assert result.details == {'spf': 'pass', 'dkim': 'pass',
                                  'dmarc': 'pass'}
        assert result.score == config.NOT_PHISHING

    def test_forwarded_mail_is_not_phishing(self):
        result = self.check('mx.google.com; spf=fail; dkim=pass header.d=x.com; '
                            'dmarc=pass')
        assert result.score == config.NOT_PHISHING
        assert result.reasons == ('spf-fail',)

    def test_spoofed_mail_is_phishing(self):
        result = self.check('mx.google.com; spf=fail; dkim=fail; '
                            'dmarc=fail (p=REJECT sp=NONE dis=REJECT)')
        assert result.score == config.PHISHING

    def test_only_top_header_is_used(self):
        result = self.check('mx.google.com; spf=fail; dkim=fail; dmarc=fail',
                            'mx.lower; spf=pass; dkim=pass; dmarc=pass')
        assert result.details == {'spf': 'fail', 'dkim': 'fail',
                                  'dmarc': 'fail'}

    def test_missing_header_is_no_authentication(self):
        result = self.check()
        assert result.details == {'spf': 'none', 'dkim': 'none',
                                  'dmarc': 'none'}
        assert result.score == config.PROBABLY_PHISHING

    def test_untrusted_server_is_no_authentication(self):
        result = self.check('mx.attacker.example; spf=pass; dkim=pass; '
                            'dmarc=pass')
        assert result.details == {'spf': 'none', 'dkim': 'none',
                                  'dmarc': 'none'}
        assert 'auth-untrusted-server' in result.reasons
        assert result.score == config.PROBABLY_PHISHING

    def test_methods_are_not_mixed_across_headers(self):
        # the trusted header has no DKIM; a forged one below claims it
        result = self.check('mx.google.com; spf=fail; dmarc=fail',
                            'mx.google.com; dkim=pass; dmarc=pass')
        assert result.details == {'spf': 'fail', 'dkim': 'none',
                                  'dmarc': 'fail'}
        assert result.score == config.PHISHING

    def test_forged_pass_header_builds_no_good_name(self):
        store = InMemoryHistoryStore()
        analyzer(make_email(
            auth_results=['mx.attacker.example; spf=pass; dkim=pass; '
                          'dmarc=pass'],
            sender='Carl <carl@example.org>'), store).analyze()
        assert store.reputation['example.org'].legit_count == 0
        assert 'example.org' not in store.legit

    def test_trusted_servers_come_from_config(self, monkeypatch):
        monkeypatch.setattr(config, 'TRUSTED_AUTHSERV_IDS',
                            frozenset({'mx.mycorp.example'}))
        assert self.check('mx.mycorp.example; spf=pass; dkim=pass; '
                          'dmarc=pass').score == config.NOT_PHISHING
        assert self.check(ALL_PASS).score == config.PROBABLY_PHISHING

    def test_real_email_sample_is_not_phishing(self):
        email = parse_email(SAMPLE_WOLT.read_text(encoding='utf-8'))
        result = Indicators(email, InMemoryHistoryStore()
                            ).detect_sender_impersonation()
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
# Indicator: Suspicious links
# =========================================================================

class TestSuspiciousLinks:

    @staticmethod
    def links(*urls):
        return run('Suspicious links', body=' '.join(urls))

    @pytest.mark.parametrize('url, flag, score', [
        ('http://45.83.64.9/login', 'url-ip-host', config.PHISHING),
        ('http://paypal.com@evil.example/login', 'url-userinfo',
         config.PHISHING),
        ('https://bit.ly/abc123', 'url-shortener',
         config.PROBABLY_PHISHING),
        ('https://tinyurl.com/abc123', 'url-shortener',
         config.PROBABLY_PHISHING),
        ('https://login.example.xyz/a', 'url-cheap-tld',
         config.PROBABLY_PHISHING),
        ('https://a.b.c.d.example.com/x', 'url-many-subdomains',
         config.PROBABLY_PHISHING),
        ('https://xn--pypal-4ve.com/', 'url-punycode',
         config.PROBABLY_PHISHING),
        ('https://example.com:8443/x', 'url-port',
         config.PROBABLY_PHISHING),
    ])
    def test_flags(self, url, flag, score):
        result = self.links(url)
        assert flag in result.reasons
        assert result.score == score

    def test_two_weak_flags_on_one_url_are_phishing(self):
        result = self.links('https://a.b.c.d.evil.xyz/verify')
        assert {'url-cheap-tld', 'url-many-subdomains'} <= set(
            result.reasons)
        assert result.score == config.PHISHING

    def test_clean_links(self):
        result = self.links('https://www.google.com/', 'http://wolt.com/a')
        assert result.score == config.NOT_PHISHING
        assert result.reasons == ()

    def test_no_links(self):
        assert run('Suspicious links').score == config.NOT_PHISHING

    def test_worst_url_decides_and_is_reported(self):
        result = self.links('https://www.google.com/', 'https://bit.ly/x',
                            'http://45.83.64.9/y')
        assert result.score == config.PHISHING
        assert len(result.details['flagged_urls']) == 2

    def test_only_strong_urls_are_offered_for_blocklisting(self):
        result = self.links('https://bit.ly/x', 'http://45.83.64.9/y',
                            'https://a.b.c.d.evil.xyz/z')
        assert result.details['block'] == [
            {'kind': 'ip', 'value': '45.83.64.9'},
            {'kind': 'domain', 'value': 'evil.xyz'}]

    @pytest.mark.parametrize('ip', ['10.0.0.5', '127.0.0.1',
                                    '192.168.1.1', '203.0.113.9'])
    def test_non_global_ips_are_flagged_but_never_blocklisted(self, ip):
        result = self.links(f'http://{ip}/login')
        assert result.score == config.PHISHING
        assert result.details['block'] == []

    def test_links_without_a_scheme_are_analyzed(self):
        result = run('Suspicious links',
                     body='log in at www.paypa1-secure.xyz/verify today')
        assert 'url-cheap-tld' in result.reasons
        assert result.details['url_count'] == 1

    def test_unicode_host_is_flagged_and_normalized(self):
        result = self.links('http://pаypal.com/login')  # Cyrillic а
        assert 'url-punycode' in result.reasons
        punycode = 'pаypal.com'.encode('idna').decode()
        email = analyzer(make_email(body=f'see http://{punycode}/x'))
        assert email._urls[0][2] == 'pаypal.com'


# =========================================================================
# Indicator: Spoofed sender
# =========================================================================

def _lines(name):
    return (DATA / name).read_text(encoding='utf-8').split()


class TestSpoofedSender:

    @staticmethod
    def spoof(domain, display='Alice', store=None):
        return run('Spoofed sender', sender=f'{display} <alice@{domain}>',
                   store=store)

    @pytest.mark.parametrize('domain', _lines('legit_domains.txt'))
    def test_legit_list_is_not_flagged(self, domain):
        result = self.spoof(domain)
        assert result.score == config.NOT_PHISHING, result.reasons

    @pytest.mark.parametrize('domain', _lines('phishy_domains.txt'))
    def test_phishy_list_is_flagged(self, domain):
        result = self.spoof(domain)
        assert result.score >= config.PROBABLY_PHISHING, domain

    @pytest.mark.parametrize('domain', ['paypal.com', 'mail.google.com',
                                        'wolt.com', 'leumi.co.il'])
    def test_known_domains_are_not_flagged(self, domain):
        assert self.spoof(domain).score == config.NOT_PHISHING

    def test_punycode_homoglyph_is_decoded_and_flagged(self):
        domain = 'pаypal.com'.encode('idna').decode()
        assert domain.startswith('xn--')
        result = self.spoof(domain)
        assert result.score == config.PHISHING
        assert 'lookalike-domain' in result.reasons

    def test_containment_and_edit_distance_reasons(self):
        assert 'brand-in-domain' in self.spoof('paypal-secure.com').reasons
        assert 'lookalike-domain' in self.spoof('paypa1.com').reasons
        assert 'brand-other-tld' in self.spoof('paypal.net').reasons

    def test_display_name_brand_on_other_domain(self):
        result = self.spoof('gmail.com', display='"PayPal Support"')
        assert result.score == config.PROBABLY_PHISHING
        assert result.reasons == ('display-name-brand',)

    def test_display_name_matching_its_own_domain_is_fine(self):
        assert self.spoof('wolt.com', display='Wolt').score == (
            config.NOT_PHISHING)

    def test_legit_list_grows_from_the_store(self):
        store = InMemoryHistoryStore(legit_domains=['mybank.com'])
        assert self.spoof('mybank.com', store=store).score == (
            config.NOT_PHISHING)
        assert self.spoof('mybank-login.com', store=store).score == (
            config.PHISHING)
        assert self.spoof('mybank-login.com').score == (
            config.NOT_PHISHING)

    def test_missing_from_is_suspicious(self):
        email = parse_email(make_email().replace(
            'From: Alice <alice@example.com>\n', ''))
        result = Indicators(email, InMemoryHistoryStore()
                            ).detect_spoofed_sender()
        assert result.reasons == ('from-missing',)

    @pytest.mark.parametrize('domain', ['purchase-portal.com',
                                        'pineapple-farm.com'])
    def test_brand_inside_a_word_is_not_flagged(self, domain):
        assert self.spoof(domain).score == config.NOT_PHISHING

    @pytest.mark.parametrize('domain', ['appleid-verify.com',
                                        'mizrahi-tefahot-secure.com',
                                        'paypal.com.evil.xyz'])
    def test_brand_at_a_label_start_is_flagged(self, domain):
        assert 'brand-in-domain' in self.spoof(domain).reasons

    def test_display_name_brand_on_other_tld_is_phishing(self):
        result = self.spoof('paypal.co', display='PayPal')
        assert {'brand-other-tld', 'display-name-brand'} <= set(
            result.reasons)
        assert result.score == config.PHISHING


# =========================================================================
# Indicator: Suspicious wording
# =========================================================================

class TestSuspiciousWording:

    @pytest.mark.parametrize('subject, body, expected', [
        ('Invoice', 'Hello, your order is ready.', config.NOT_PHISHING),
        ('Invoice', 'This is urgent, please read.',
         config.PROBABLY_NOT_PHISHING),
        ('Hi', 'URGENT: verify your account now!',
         config.PROBABLY_PHISHING),
        ('Action required', 'Your account will be suspended. Verify your '
         'account and update your payment details.', config.PHISHING),
        ('דחוף', 'אמת את החשבון שלך. החשבון שלך יושעה תוך 24 שעות.',
         config.PHISHING),
        ('שלום', 'הזמנה שלך מוכנה למשלוח', config.NOT_PHISHING),
        ('שלום', 'זה דחוף, בבקשה לקרוא.', config.PROBABLY_NOT_PHISHING),
    ])
    def test_scores(self, subject, body, expected):
        result = run('Suspicious wording', subject=subject, body=body)
        assert result.score == expected, result.details

    def test_html_tags_are_ignored_and_scripts_skipped(self):
        result = run('Suspicious wording', body='plain', html=(
            '<html><body><p>Please <b>verify</b> your account</p>'
            '<script>claim your prize</script></body></html>'))
        assert result.details['categories'] == ['credentials']

    def test_details_do_not_contain_the_text(self):
        result = run('Suspicious wording',
                     body=f'{SECRET_BODY} urgent verify your account')
        assert SECRET_BODY not in json.dumps(result.as_dict())

    def test_text_beyond_the_cap_is_not_read(self, monkeypatch):
        monkeypatch.setattr(config, 'MAX_WORDING_CHARS', 50)
        result = run('Suspicious wording',
                     body='x ' * 40 + 'verify your account',
                     html='<p>claim your prize</p>')
        assert result.score == config.NOT_PHISHING


# =========================================================================
# Indicator: Attachment analysis
# =========================================================================

class TestAttachmentAnalysis:

    @staticmethod
    def attach(filename, data=b'data', content_type='application/pdf'):
        return run('Attachment analysis',
                   attachments=[(filename, data, content_type)])

    def test_clean_attachment(self):
        result = self.attach('notes.pdf', b'%PDF-1.4')
        assert result.score == config.NOT_PHISHING

    def test_no_attachments(self):
        assert run('Attachment analysis').score == config.NOT_PHISHING

    def test_double_extension(self):
        result = self.attach('invoice.pdf.exe', b'MZ' + bytes(100))
        assert result.score == config.PHISHING
        assert ('attachment-anomaly:filename-double-extension'
                in result.reasons)

    @pytest.mark.parametrize('filename', ['setup.exe', 'run.bat',
                                          'macro.vbs', 'script.js'])
    def test_executable_extensions(self, filename):
        result = self.attach(filename, content_type='application/'
                             'octet-stream')
        assert 'attachment-executable' in result.reasons
        assert result.score == config.PHISHING

    def test_mime_mismatch(self):
        result = self.attach('photo.png', content_type='application/pdf')
        assert result.reasons == ('attachment-mime-mismatch',)
        assert result.score == config.PROBABLY_PHISHING

    @pytest.mark.parametrize('filename, content_type', [
        ('invoice.pdf', 'application/x-msdownload'),
        ('invoice.pdf', 'application/zip'),
        ('report.docx', 'text/html'),
    ])
    def test_risky_declared_type_mismatch(self, filename, content_type):
        result = self.attach(filename, content_type=content_type)
        assert 'attachment-mime-mismatch' in result.reasons

    @pytest.mark.parametrize('filename, content_type', [
        ('report.zip', 'application/zip'),
        ('report.zip', 'application/x-zip-compressed'),
        ('page.html', 'text/html'),
    ])
    def test_risky_type_matching_its_extension(self, filename,
                                               content_type):
        result = self.attach(filename, content_type=content_type)
        assert 'attachment-mime-mismatch' not in result.reasons

    def test_octet_stream_is_not_a_mismatch(self):
        result = self.attach('photo.png',
                             content_type='application/octet-stream')
        assert result.score == config.NOT_PHISHING

    def test_macro_document(self):
        result = self.attach('report.docm', content_type='application/'
                             'vnd.ms-word.document.macroEnabled.12')
        assert 'attachment-macro-document' in result.reasons
        assert result.score == config.PROBABLY_PHISHING

    def test_hash_is_offered_for_blocklisting(self):
        data = b'MZ' + bytes(100)
        result = self.attach('setup.exe', data, 'application/octet-stream')
        assert result.details['block'] == [
            {'kind': 'hash', 'value': hashlib.sha256(data).hexdigest()}]

    # --- Zip files: metadata only ------------------------------------

    def zip_attach(self, data, name='files.zip'):
        return self.attach(name, data, 'application/zip')

    def test_clean_zip(self):
        result = self.zip_attach(zip_bytes({'notes.txt': b'hello'}))
        assert result.score == config.NOT_PHISHING

    def test_encrypted_zip(self):
        result = self.zip_attach(zip_bytes({'a.txt': b'x'}, encrypted=True))
        assert 'zip-encrypted' in result.reasons
        assert result.score == config.PHISHING

    def test_zip_with_executable(self):
        result = self.zip_attach(zip_bytes({'setup.exe': b'MZ'}))
        assert 'zip-contains-executable' in result.reasons
        assert result.score == config.PHISHING

    def test_zip_bomb_by_ratio(self):
        result = self.zip_attach(zip_bytes({'big.bin': bytes(2_000_000)}))
        assert 'zip-bomb-suspect' in result.reasons
        assert result.score == config.PHISHING

    def test_zip_bomb_by_entry_count(self, monkeypatch):
        monkeypatch.setattr(config, 'MAX_ZIP_ENTRIES', 10)
        entries = {f'f{i}.txt': b'x' for i in range(11)}
        result = self.zip_attach(zip_bytes(entries))
        assert 'zip-bomb-suspect' in result.reasons

    def test_unreadable_zip(self):
        result = self.zip_attach(b'this is not a zip')
        assert result.reasons == ('zip-unreadable',)
        assert result.score == config.PROBABLY_PHISHING

    def test_zip_over_size_limit_is_not_opened(self, monkeypatch):
        data = zip_bytes({'a.txt': b'hello' * 50})
        monkeypatch.setattr(config, 'MAX_ZIP_INSPECT_BYTES', 100)

        def boom(*args, **kwargs):
            raise AssertionError('the zip must not be opened')

        monkeypatch.setattr(indicators.zipfile, 'ZipFile', boom)
        result = self.zip_attach(data)
        assert result.reasons == ('attachment-too-large-to-inspect',)
        assert result.score == config.NOT_PHISHING

    def test_zip_content_is_never_read(self, monkeypatch):
        encrypted_zip = zip_bytes({'a.txt': b'x'}, encrypted=True)
        bomb_zip = zip_bytes({'big.bin': bytes(2_000_000)})

        def boom(*args, **kwargs):
            raise AssertionError('zip data must not be read')

        for method in ('read', 'open', 'extract', 'extractall', 'testzip'):
            monkeypatch.setattr(zipfile.ZipFile, method, boom)
        encrypted = self.zip_attach(encrypted_zip)
        bomb = self.zip_attach(bomb_zip)
        assert encrypted.score == bomb.score == config.PHISHING


# =========================================================================
# Indicator: Sender history, and the blocklist
# =========================================================================

class TestHistory:

    @staticmethod
    def history(reputation):
        store = InMemoryHistoryStore()
        if reputation:
            store.reputation['example.com'] = reputation
        return run('Sender history', store=store)

    @staticmethod
    def rep(legit=0, phishing=0):
        return Reputation(datetime.now(timezone.utc), legit, phishing)

    def test_first_seen(self):
        result = self.history(None)
        assert result.reasons == ('sender-first-seen',)
        assert result.score == config.PROBABLY_PHISHING

    def test_allowlisted(self):
        result = self.history(self.rep(legit=config.ALLOWLIST_MIN_LEGIT))
        assert result.reasons == ('sender-allowlisted',)
        assert result.score == config.NOT_PHISHING

    def test_known_sender(self):
        result = self.history(self.rep(legit=1))
        assert result.score == config.PROBABLY_NOT_PHISHING

    def test_mostly_phishing(self):
        result = self.history(self.rep(legit=1, phishing=2))
        assert result.reasons == ('sender-mostly-phishing',)
        assert result.score == config.PHISHING

    # --- Blocklist: checked before every indicator ---------------------

    @staticmethod
    def no_indicators(monkeypatch):
        def boom(self):
            raise AssertionError('indicators must not run')

        monkeypatch.setattr(Indicators, 'run_all', boom)

    @pytest.mark.parametrize('kind, value, body', [
        ('domain', 'evil.example', 'visit https://login.evil.example/a'),
        ('ip', '45.83.64.9', 'visit http://45.83.64.9/login'),
        ('domain', 'blocked.example', 'nothing here'),
    ])
    def test_blocklist_hit_skips_the_indicators(self, monkeypatch, kind,
                                                value, body):
        store = InMemoryHistoryStore()
        store.add_to_blocklist(kind, value, {'saved': 'report'})
        sender = ('Bob <bob@blocked.example>' if value ==
                  'blocked.example' else 'Alice <alice@example.com>')
        self.no_indicators(monkeypatch)
        report = analyzer(make_email(body=body, sender=sender),
                          store).analyze()
        assert report['verdict'] == config.BLOCKLIST
        assert report['verdict_name'] == 'BLOCKLIST'
        assert report['blocklisted'] == [{'kind': kind, 'value': value}]
        assert report['indicators'] == {'saved': 'report'}

    def test_blocklisted_attachment_hash(self, monkeypatch):
        data = b'MZ' + bytes(50)
        store = InMemoryHistoryStore()
        store.add_to_blocklist('hash', hashlib.sha256(data).hexdigest())
        self.no_indicators(monkeypatch)
        report = analyzer(make_email(attachments=[
            ('a.bin', data, 'application/octet-stream')]), store).analyze()
        assert report['verdict'] == config.BLOCKLIST
        assert report['indicators'] is None  # added without a report

    def test_blocklisted_link_does_not_count_against_the_sender(self):
        store = InMemoryHistoryStore()
        store.add_to_blocklist('domain', 'evil.example')
        report = analyzer(make_email(
            body='fwd: https://login.evil.example/a'), store).analyze()
        assert report['verdict'] == config.BLOCKLIST
        assert 'example.com' not in store.reputation

    def test_blocklisted_sender_is_recorded(self):
        store = InMemoryHistoryStore()
        store.add_to_blocklist('domain', 'blocked.example')
        analyzer(make_email(sender='Bob <bob@blocked.example>'),
                 store).analyze()
        assert store.reputation['blocked.example'].phishing_count == 1

    def test_received_ips_are_not_looked_up(self):
        store = InMemoryHistoryStore()
        store.add_to_blocklist('ip', '54.240.3.10')  # in the Received chain
        report = analyzer(SAMPLE_WOLT.read_text(encoding='utf-8'),
                          store).analyze()
        assert report['verdict'] != config.BLOCKLIST

    def test_punycode_link_and_unicode_from_share_an_entry(self):
        punycode = 'pаypal.com'.encode('idna').decode()
        store = InMemoryHistoryStore()
        store.add_to_blocklist('domain', 'pаypal.com')
        report = analyzer(make_email(body=f'see http://{punycode}/x'),
                          store).analyze()
        assert report['blocklisted'] == [{'kind': 'domain',
                                          'value': 'pаypal.com'}]

    def test_second_email_shows_the_saved_indicators(self):
        store = InMemoryHistoryStore()
        first = analyzer(PHISHING_EMAIL, store).analyze()
        assert first['verdict'] == config.PHISHING
        second = analyzer(make_email(
            body='click http://45.83.64.9/other'), store).analyze()
        assert second['verdict'] == config.BLOCKLIST
        assert second['indicators'] == first['indicators']


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
        return analyzer(make_email()).risk_score(results)

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

PHISHING_EMAIL = make_email(
    sender='"PayPal" <service@paypa1.com>',
    subject='דחוף: אמת את החשבון',
    body=('Urgent! Verify your account now or your account will be '
          'suspended: http://45.83.64.9/login '
          'https://a.b.c.d.google.com:8443/x'),
    attachments=[('invoice.pdf.exe', b'MZ' + bytes(100),
                  'application/pdf')])


class TestAnalyze:

    def test_real_email_is_not_phishing_and_grows_the_legit_list(self):
        store = InMemoryHistoryStore()
        report = analyzer(SAMPLE_WOLT.read_text(encoding='utf-8'),
                          store).analyze()
        assert report['verdict'] == config.NOT_PHISHING
        assert 'wolt.com' in store.legit
        assert store.reputation['wolt.com'].legit_count == 1

    def test_phishing_email_and_its_blocklisting(self):
        store = InMemoryHistoryStore()
        report = analyzer(PHISHING_EMAIL, store).analyze()
        assert report['verdict'] == config.PHISHING
        for name in ('Spoofed sender', 'Suspicious links',
                     'Attachment analysis', 'Suspicious wording'):
            assert report['indicators'][name]['score'] >= (
                config.PROBABLY_PHISHING)
        assert ('ip', '45.83.64.9') in store.blocklist
        assert ('hash', hashlib.sha256(b'MZ' + bytes(100)).hexdigest()
                ) in store.blocklist
        # a legit domain is never blocklisted, nor is the sender's
        assert ('domain', 'google.com') not in store.blocklist
        assert ('domain', 'paypa1.com') not in store.blocklist
        assert store.reputation['paypa1.com'].phishing_count == 1

    def test_unauthenticated_message_does_not_build_a_good_name(self):
        store = InMemoryHistoryStore()
        report = analyzer(make_email(sender='Carl <carl@example.org>'),
                          store).analyze()
        assert report['verdict'] <= config.PROBABLY_NOT_PHISHING
        assert store.reputation['example.org'].legit_count == 0
        assert 'example.org' not in store.legit

    def test_authenticated_message_counts_as_legit(self):
        store = InMemoryHistoryStore()
        analyzer(make_email(auth_results=[ALL_PASS],
                            sender='Carl <carl@example.org>'),
                 store).analyze()
        assert store.reputation['example.org'].legit_count == 1
        assert 'example.org' in store.legit

    def test_authenticated_typosquat_is_never_learned(self):
        store = InMemoryHistoryStore()
        report = analyzer(make_email(auth_results=[ALL_PASS],
                                     sender='PayPal <service@paypal.co>'),
                          store).analyze()
        assert report['verdict'] >= config.PROBABLY_PHISHING
        assert 'paypal.co' not in store.legit

    def test_authenticated_other_tld_without_brand_name_is_not_learned(
            self):
        store = InMemoryHistoryStore()
        analyzer(make_email(auth_results=[ALL_PASS],
                            sender='Service <service@paypal.co>'),
                 store).analyze()
        assert 'paypal.co' not in store.legit

    def test_legit_list_is_read_once_per_email(self):
        calls = []

        class CountingStore(InMemoryHistoryStore):
            def get_legit_domains(self):
                calls.append(1)
                return super().get_legit_domains()

        analyzer(PHISHING_EMAIL, CountingStore()).analyze()
        assert len(calls) == 1

    def test_report_can_be_a_json(self):
        report = analyzer(PHISHING_EMAIL).analyze()
        assert json.loads(json.dumps(report))['verdict'] == config.PHISHING

    def test_registry(self):
        assert 'Sender Authentication' in INDICATOR_MAP
        assert len(INDICATOR_MAP) == 6

    def test_run_all_returns_results_for_every_indicator(self):
        results = analyzer(make_email(auth_results=[ALL_PASS])).run_all()
        assert set(results) == set(INDICATOR_MAP)
        assert results['Sender Authentication'].score == config.NOT_PHISHING


# =========================================================================
# Logging
# =========================================================================

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
        analyzer_ = analyzer(make_email(auth_results=[
            'mx.google.com; spf=fail; dkim=fail; dmarc=fail']))
        with caplog.at_level(logging.INFO, logger='logic'):
            analyzer_.analyze()
        info = [r for r in caplog.records if r.levelno == logging.INFO]
        assert len(info) == 1
        assert 'from_domain=example.com' in info[0].getMessage()
        assert 'verdict=' in info[0].getMessage()

    def test_body_and_full_address_are_not_logged(self, caplog):
        analyzer_ = analyzer(make_email(auth_results=[ALL_PASS]))
        with caplog.at_level(logging.DEBUG):
            analyzer_.analyze()
        assert caplog.records
        assert SECRET_BODY not in caplog.text
        assert 'alice@example.com' not in caplog.text

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

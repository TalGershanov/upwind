"""Phishing indicators and the weighted risk score.

Each indicator is a method of :class:`Indicators`, registered under a
display name with :func:`register_indicator` (open-closed: a new
indicator is a new method plus a weight in ``config``). Indicators work
on the dict returned by :func:`logic.email_parser.parse_email` and read
history through the injected :class:`HistoryStore`.
"""

import base64
import binascii
import io
import ipaddress
import logging
import mimetypes
import re
import unicodedata
import weakref
import zipfile
from dataclasses import dataclass, field
from email.utils import parseaddr
from functools import cached_property
from html.parser import HTMLParser
from pathlib import Path, PurePosixPath
from typing import Optional
from urllib.parse import urlsplit

import eml_parser.constants
import eml_parser.decode
import eml_parser.regexes
from publicsuffixlist import PublicSuffixList

from logic import config
from logic.history_store import HistoryStore

logger = logging.getLogger(__name__)

INDICATOR_MAP = {}

_PSL = PublicSuffixList()
_EXECUTABLE_EXTENSIONS = eml_parser.constants.EXECUTABLE_EXTENSIONS
_NIQQUD_RE = re.compile('[֑-ׇ]')
_PUNCT_RE = re.compile(r'[^\w\s]|_')
_STRONG_URL_FLAGS = ('url-ip-host', 'url-userinfo')
# Flags about the host itself; only these may blocklist a link domain
# (userinfo, port or extra subdomains can be put on any domain).
_HOST_URL_FLAGS = ('url-ip-host', 'url-cheap-tld', 'url-punycode')
# Character swaps that look alike (w0lt, gmaiI); short brands only match
# a look-alike through one of these.
_LOOKALIKE_CHARS = frozenset(frozenset(pair) for pair in (
    '0o', '1l', '1i', 'il', '5s', '3e', '4a', '8b', '9g', 'uv'))
# Brand index per store, cleared when this module adds a legit domain.
_LEGIT_INDEX_CACHE = weakref.WeakKeyDictionary()
_AUTH_RESULT_RE = eml_parser.regexes.authentication_result_regex
# Different names for the same type, mapped to the one mimetypes guesses.
_MIME_ALIASES = {
    'application/x-zip-compressed': 'application/zip',
    'application/x-msdos-program': 'application/x-msdownload',
    'application/x-dosexec': 'application/x-msdownload',
    'application/vnd.microsoft.portable-executable':
        'application/x-msdownload',
    'application/javascript': 'text/javascript',
    'application/vnd.rar': 'application/x-rar-compressed',
}


def register_indicator(name):
    """Register the decorated method in ``INDICATOR_MAP`` as ``name``."""
    def decorator(func):
        INDICATOR_MAP[name] = func
        return func
    return decorator


@dataclass(frozen=True)
class IndicatorResult:
    """What one indicator found.

    ``score`` is a verdict from ``config``; ``reasons`` are short codes;
    ``details`` holds data for the report (never the email text).
    """

    score: int
    reasons: tuple = ()
    details: dict = field(default_factory=dict, compare=False)

    def as_dict(self) -> dict:
        return {'score': self.score, 'reasons': list(self.reasons),
                'details': self.details}


# --- Helpers ---------------------------------------------------------------

def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def _blockable_host(host: str) -> bool:
    """Whether a link host may be blocklisted.

    Not shorteners (shared by everyone) and not private, loopback or
    reserved IPs, which also show up in the Received chain of
    legitimate mail.
    """
    if _is_ip(host):
        return ipaddress.ip_address(host).is_global
    return _registered_domain(host) not in config.URL_SHORTENERS


def _split_host(host: str) -> tuple:
    """Return ``(sub_labels, label, public_suffix)`` of a host name."""
    host = host.lower().strip('.')
    suffix = _PSL.publicsuffix(host) or host.rsplit('.', 1)[-1]
    rest = host[:-len(suffix)].rstrip('.') if host.endswith(suffix) else host
    labels = rest.split('.') if rest else []
    return labels[:-1], (labels[-1] if labels else ''), suffix


def _registered_domain(host: str) -> str:
    """``mail.bank.co.uk`` -> ``bank.co.uk`` (IP addresses unchanged)."""
    host = host.lower().strip('.')
    if _is_ip(host):
        return host
    _, label, suffix = _split_host(host)
    return f'{label}.{suffix}' if label else host


def _normalize_domain(domain: str) -> str:
    """Punycode to Unicode, then lower-case."""
    labels = []
    for label in domain.lower().split('.'):
        if label.startswith('xn--'):
            try:
                label = label.encode('ascii').decode('idna')
            except UnicodeError:
                pass
        labels.append(label)
    return '.'.join(labels).lower()


def _edit_distance(a: str, b: str) -> int:
    """Levenshtein distance."""
    previous = list(range(len(b) + 1))
    for i, char_a in enumerate(a, 1):
        current = [i]
        for j, char_b in enumerate(b, 1):
            current.append(min(previous[j] + 1, current[j - 1] + 1,
                               previous[j - 1] + (char_a != char_b)))
        previous = current
    return previous[-1]


def _normalize_text(text: str) -> str:
    """Lower-case, no Hebrew niqqud, no punctuation, single spaces."""
    text = unicodedata.normalize('NFKC', text).lower()
    text = _NIQQUD_RE.sub('', text)
    return ' '.join(_PUNCT_RE.sub(' ', text).split())


_PHRASES = tuple((category, _normalize_text(phrase))
                 for category, phrases in config.SUSPICIOUS_PHRASES.items()
                 for phrase in phrases)


class _TextExtractor(HTMLParser):
    """Collect the visible text of an HTML (or plain text) body."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts = []
        self._skip = 0

    def handle_starttag(self, tag, attrs):
        if tag in ('script', 'style'):
            self._skip += 1

    def handle_endtag(self, tag):
        if tag in ('script', 'style') and self._skip:
            self._skip -= 1

    def handle_data(self, data):
        if not self._skip:
            self.parts.append(data)


def _visible_text(content: str) -> str:
    extractor = _TextExtractor()
    extractor.feed(content)
    extractor.close()
    return ' '.join(extractor.parts)


def _declared_type(attachment: dict) -> str:
    types = attachment.get('content_header', {}).get('content-type') or ['']
    return types[0].split(';')[0].strip().lower()


def _scan_zip(attachment: dict) -> tuple:
    """Check a zip by its metadata only: nothing is decompressed.

    Returns ``(score, reasons)``. Zips above the size limit are not
    opened at all.
    """
    raw = attachment.get('raw')
    limit = config.MAX_ZIP_INSPECT_BYTES
    if (attachment.get('size') or 0) > limit or (
            raw and len(raw) * 3 // 4 > limit):
        return config.NOT_PHISHING, ['attachment-too-large-to-inspect']
    if not raw:
        return config.NOT_PHISHING, []
    try:
        with zipfile.ZipFile(io.BytesIO(base64.b64decode(raw))) as archive:
            infos = archive.infolist()
    except (zipfile.BadZipFile, ValueError, binascii.Error):
        return config.PROBABLY_PHISHING, ['zip-unreadable']

    reasons = []
    if any(info.flag_bits & 0x1 for info in infos):
        reasons.append('zip-encrypted')
    if any(PurePosixPath(info.filename).suffix.lower().lstrip('.')
           in _EXECUTABLE_EXTENSIONS for info in infos):
        reasons.append('zip-contains-executable')
    total = sum(info.file_size for info in infos)
    if (len(infos) > config.MAX_ZIP_ENTRIES
            or total > config.MAX_ZIP_UNCOMPRESSED_BYTES
            or any(info.file_size >= config.ZIP_RATIO_MIN_BYTES
                   and info.file_size / max(info.compress_size, 1)
                   > config.MAX_ZIP_RATIO for info in infos)):
        reasons.append('zip-bomb-suspect')
    return (config.PHISHING if reasons else config.NOT_PHISHING), reasons


def _scan_attachment(attachment: dict) -> tuple:
    """Return ``(score, reasons)`` for one attachment."""
    score, reasons = config.NOT_PHISHING, []
    for code in attachment.get('anomaly') or []:
        reasons.append(f'attachment-anomaly:{code}')
        score = config.PHISHING

    filename = attachment.get('filename') or ''
    extension = Path(filename).suffix.lower().lstrip('.')
    if extension in _EXECUTABLE_EXTENSIONS:
        reasons.append('attachment-executable')
        score = config.PHISHING
    if extension in config.MACRO_EXTENSIONS:
        reasons.append('attachment-macro-document')
        score = max(score, config.PROBABLY_PHISHING)

    declared = _declared_type(attachment)
    guessed = mimetypes.guess_type(filename)[0]
    canonical = _MIME_ALIASES.get(declared, declared)
    if declared and guessed and declared != 'application/octet-stream' and (
            declared.split('/')[0] != guessed.split('/')[0]
            or (declared in config.RISKY_MIME_TYPES
                and canonical != _MIME_ALIASES.get(guessed, guessed))):
        reasons.append('attachment-mime-mismatch')
        score = max(score, config.PROBABLY_PHISHING)

    if extension == 'zip' or declared in ('application/zip',
                                          'application/x-zip-compressed'):
        zip_score, zip_reasons = _scan_zip(attachment)
        reasons += zip_reasons
        score = max(score, zip_score)
    return score, reasons


# --- Indicators -------------------------------------------------------------

class Indicators:
    """Runs the indicators on one parsed email (eml_parser's dict)."""

    def __init__(self, email: dict, store: HistoryStore):
        self.email = email
        self.store = store

    # --- Values read from the email ----------------------------------------

    @cached_property
    def _header(self) -> dict:
        return self.email['header']

    @cached_property
    def _from_host(self) -> Optional[str]:
        address = self._header.get('from') or ''
        domain = address.rpartition('@')[2].strip().lower()
        return _normalize_domain(domain) if domain else None

    @cached_property
    def _from_registered(self) -> Optional[str]:
        return _registered_domain(self._from_host) if self._from_host \
            else None

    @cached_property
    def _urls(self) -> list:
        """``(url, parts, host)`` for each distinct URL, up to a limit.

        Links without a scheme (``www.example.com/x``) are read as
        ``http://``. ``host`` is normalized like the From domain
        (punycode to Unicode, lower-case), so blocklist keys match.
        """
        candidates = (
            url if with_scheme else f'http://{url}'
            for body in self.email.get('body', [])
            for key, with_scheme in (('uri', True), ('uri_noscheme', False))
            for url in body.get(key, []))
        seen, urls = set(), []
        for url in candidates:
            if len(urls) >= config.MAX_URLS_ANALYZED:
                break
            if url in seen:
                continue
            seen.add(url)
            try:
                parts = urlsplit(url)
                host = parts.hostname
            except ValueError:
                continue
            if host:
                urls.append((url, parts, _normalize_domain(host)))
        return urls

    @cached_property
    def _attachments(self) -> list:
        return self.email.get('attachment') or []

    @cached_property
    def _legit_index(self) -> tuple:
        """``(registered legit domains, {brand label: {domains}})``.

        Built once per store from the seed and the history store.
        """
        cached = _LEGIT_INDEX_CACHE.get(self.store)
        if cached is not None:
            return cached
        domains = set(config.LEGIT_DOMAINS_SEED)
        domains |= set(self.store.get_legit_domains())
        registered = {_registered_domain(domain) for domain in domains}
        brands = {}
        for domain in registered:
            brands.setdefault(_split_host(domain)[1], set()).add(domain)
        _LEGIT_INDEX_CACHE[self.store] = registered, brands
        return registered, brands

    # --- Sender Authentication ---------------------------------------------

    @register_indicator('Sender Authentication')
    def detect_sender_impersonation(self) -> IndicatorResult:
        """Score the SPF, DKIM and DMARC results found in the email.

        Only the topmost ``Authentication-Results`` header is read, and
        only if a trusted receiving server added it
        (``config.TRUSTED_AUTHSERV_IDS``): the sender can write any
        header below it, so results are never mixed across headers.
        """
        headers = self._header.get('header', {}).get(
            'authentication-results', [])
        results = {'spf': 'none', 'dkim': 'none', 'dmarc': 'none'}
        trust_reasons = ()
        if not headers:
            trust_reasons = ('auth-missing',)
        else:
            top = eml_parser.decode.noparenthesis(str(headers[0]), ' ')
            # authserv-id is the first token; an RFC 8601 version may follow.
            server = (top.split(';', 1)[0].split() or [''])[0].lower()
            if server not in config.TRUSTED_AUTHSERV_IDS:
                trust_reasons = ('auth-untrusted-server',)
            else:
                found = {}
                for method, value in _AUTH_RESULT_RE.findall(top):
                    method, value = method.lower(), value.lower()
                    # Any passing result wins (e.g. one of several DKIM
                    # signatures); otherwise the first one is kept.
                    if method not in found or value == 'pass':
                        found[method] = value
                results = {check: found.get(check, 'none')
                           for check in results}
        reasons = trust_reasons + tuple(
            f'{check}-{value}' for check, value in results.items()
            if value != 'pass')
        return IndicatorResult(score_sender_auth(**results), reasons,
                               results)

    # --- Suspicious links ----------------------------------------------------

    @staticmethod
    def _url_flags(parts, host: str) -> list:
        flags = []
        if _is_ip(host):
            flags.append('url-ip-host')
        else:
            sub_labels, _, suffix = _split_host(host)
            if _registered_domain(host) in config.URL_SHORTENERS:
                flags.append('url-shortener')
            if suffix.rsplit('.', 1)[-1] in config.CHEAP_TLDS:
                flags.append('url-cheap-tld')
            if len(sub_labels) > config.MAX_SUBDOMAINS:
                flags.append('url-many-subdomains')
            raw_host = parts.hostname or host
            if not raw_host.isascii() or any(
                    label.startswith('xn--') for label in raw_host.split('.')):
                flags.append('url-punycode')  # internationalized host
        if parts.username is not None:
            flags.append('url-userinfo')
        try:
            if parts.port not in (None, 80, 443):
                flags.append('url-port')
        except ValueError:
            flags.append('url-port')
        return flags

    @register_indicator('Suspicious links')
    def detect_suspicious_links(self) -> IndicatorResult:
        """Static checks on every URL: IP hosts, shorteners, cheap TLDs..."""
        score, reasons, flagged, block = config.NOT_PHISHING, set(), [], []
        for url, parts, host in self._urls:
            flags = self._url_flags(parts, host)
            if not flags:
                continue
            strong = any(flag in _STRONG_URL_FLAGS for flag in flags)
            url_score = (config.PHISHING if strong or len(flags) >= 2
                         else config.PROBABLY_PHISHING)
            score = max(score, url_score)
            reasons.update(flags)
            if len(flagged) < config.MAX_REPORTED_URLS:
                flagged.append({'url': url[:200], 'flags': flags})
            if (url_score == config.PHISHING and _blockable_host(host)
                    and any(flag in _HOST_URL_FLAGS for flag in flags)):
                block.append({'kind': 'ip' if _is_ip(host) else 'domain',
                              'value': _registered_domain(host)})
        return IndicatorResult(score, tuple(sorted(reasons)),
                               {'url_count': len(self._urls),
                                'flagged_urls': flagged, 'block': block})

    # --- Spoofed sender ------------------------------------------------------

    def _brand_match(self, brand: str, label: str, tokens: set,
                     parts: set) -> Optional[str]:
        """Why ``label`` looks like the legit ``brand``, or ``None``."""
        if label == brand:
            return 'brand-other-tld'  # same name, different suffix
        # A long brand may start any label or '-' part (appleid-verify,
        # mizrahi-tefahot-secure) but not sit inside a word (purchase).
        host = self._from_host
        if brand in tokens or (len(brand) >= 5 and (
                host.startswith(brand) or f'.{brand}' in host
                or f'-{brand}' in host)):
            return 'brand-in-domain'
        if len(brand) >= config.SPOOF_MIN_LOOKALIKE_LEN:
            limit = (1 if len(brand) <= config.SPOOF_SHORT_LABEL
                     else config.SPOOF_MAX_EDIT_DISTANCE)
            if any(abs(len(part) - len(brand)) <= limit
                   and 1 <= _edit_distance(part, brand) <= limit
                   for part in parts):
                return 'lookalike-domain'
        elif len(brand) >= config.SPOOF_MIN_BRAND_LEN:
            for part in parts:
                diffs = [frozenset(pair) for pair in zip(part, brand)
                         if pair[0] != pair[1]]
                if (len(part) == len(brand) and len(diffs) == 1
                        and diffs[0] in _LOOKALIKE_CHARS):
                    return 'lookalike-domain'
        return None

    @register_indicator('Spoofed sender')
    def detect_spoofed_sender(self) -> IndicatorResult:
        """Look-alikes of known domains: containment, then edit distance.

        The domain is turned from punycode to Unicode and lower-cased,
        split into tokens, and compared with the legit brand labels.
        """
        if not self._from_host:
            return IndicatorResult(config.PROBABLY_PHISHING,
                                   ('from-missing',))
        registered = self._from_registered
        label = _split_host(self._from_host)[1]
        legit, brands = self._legit_index
        reasons, matched, score = set(), set(), config.NOT_PHISHING

        raw_from = (self._header.get('header', {}).get('from') or [''])[0]
        words = [w for w in re.split(r'[\W_]+',
                                     parseaddr(raw_from)[0].lower()) if w]
        # Whole words, or up to 3 adjacent words joined ("Bank of America").
        display = {''.join(words[i:i + n]) for n in (1, 2, 3)
                   for i in range(len(words) - n + 1)}
        for brand, domains in brands.items():
            plain = re.sub(r'[\W_]', '', brand)
            if (len(plain) >= config.SPOOF_MIN_BRAND_LEN
                    and plain in display and registered not in domains
                    # a brand's own legit domain (facebookmail.com)
                    and not (registered in legit
                             and label.startswith(brand))):
                reasons.add('display-name-brand')
                matched.add(brand)
                score = config.PROBABLY_PHISHING

        if registered not in legit:
            from_domain = (self._header.get('from') or '').rpartition(
                '@')[2].strip().lower()
            if not from_domain.isascii() or any(
                    label.startswith('xn--')
                    for label in from_domain.split('.')):
                reasons.add('from-punycode')  # internationalized domain
                score = max(score, config.PROBABLY_PHISHING)
            tokens = set(re.split(r'[.\-]', self._from_host))
            parts = {label, *label.split('-')}
            for brand in brands:
                reason = self._brand_match(brand, label, tokens, parts)
                if reason:
                    reasons.add(reason)
                    matched.add(brand)
                    score = max(score, config.PROBABLY_PHISHING
                                if reason == 'brand-other-tld'
                                else config.PHISHING)
        # A brand in the display name sent from that brand's name under
        # another suffix ("PayPal" <x@paypal.co>) is an impersonation.
        if {'brand-other-tld', 'display-name-brand'} <= reasons:
            score = config.PHISHING
        return IndicatorResult(score, tuple(sorted(reasons)),
                               {'sender_domain': registered,
                                'similar_to': sorted(matched)[:5]})

    # --- Suspicious wording --------------------------------------------------

    @register_indicator('Suspicious wording')
    def detect_suspicious_wording(self) -> IndicatorResult:
        """Match a static, normalized phrase map (English and Hebrew)."""
        limit = config.MAX_WORDING_CHARS
        texts = [self._header.get('subject') or '']
        length = len(texts[0])
        for body in self.email.get('body', []):
            if length >= limit:
                break  # the cap bounds the HTML parsing too
            texts.append(_visible_text((body.get('content') or '')[:limit]))
            length += len(texts[-1]) + 1
        text = _normalize_text(' '.join(texts)[:limit])
        padded = f' {text} '
        hits = {(category, phrase) for category, phrase in _PHRASES
                if f' {phrase} ' in padded}
        categories = {category for category, _ in hits}
        if len(categories) >= 3 or len(hits) >= 5:
            score = config.PHISHING
        elif len(categories) == 2:
            score = config.PROBABLY_PHISHING
        elif hits:
            score = config.PROBABLY_NOT_PHISHING
        else:
            score = config.NOT_PHISHING
        return IndicatorResult(score,
                               tuple(f'wording-{c}'
                                     for c in sorted(categories)),
                               {'categories': sorted(categories),
                                'hits': len(hits)})

    # --- Attachment analysis -------------------------------------------------

    @register_indicator('Attachment analysis')
    def attachment_analysis(self) -> IndicatorResult:
        """Executables, double extensions, MIME mismatch and risky zips."""
        score, reasons, flagged, block = config.NOT_PHISHING, set(), [], []
        for attachment in self._attachments:
            att_score, att_reasons = _scan_attachment(attachment)
            if not att_reasons:
                continue
            score = max(score, att_score)
            reasons.update(att_reasons)
            flagged.append({'filename': (attachment.get('filename')
                                         or '')[:100],
                            'reasons': att_reasons})
            sha256 = attachment.get('hash', {}).get('sha256')
            if att_score == config.PHISHING and sha256:
                block.append({'kind': 'hash', 'value': sha256})
        return IndicatorResult(score, tuple(sorted(reasons)),
                               {'attachment_count': len(self._attachments),
                                'flagged': flagged, 'block': block})

    # --- Sender history ------------------------------------------------------

    @register_indicator('Sender history')
    def sender_history(self) -> IndicatorResult:
        """Reputation of the sender domain from the history store."""
        domain = self._from_registered
        if not domain:
            return IndicatorResult(config.PROBABLY_PHISHING,
                                   ('sender-unknown',))
        reputation = self.store.get_reputation(domain)
        if reputation is None:
            return IndicatorResult(config.PROBABLY_PHISHING,
                                   ('sender-first-seen',))
        if reputation.phishing_count > reputation.legit_count:
            score, reason = config.PHISHING, 'sender-mostly-phishing'
        elif (reputation.phishing_count == 0
              and reputation.legit_count >= config.ALLOWLIST_MIN_LEGIT):
            score, reason = config.NOT_PHISHING, 'sender-allowlisted'
        else:
            score, reason = config.PROBABLY_NOT_PHISHING, 'sender-known'
        return IndicatorResult(score, (reason,),
                               {'legit_count': reputation.legit_count,
                                'phishing_count': reputation.phishing_count})

    # --- Running everything --------------------------------------------------

    def run_all(self) -> dict:
        """Return ``{indicator name: IndicatorResult}``."""
        return {name: func(self) for name, func in INDICATOR_MAP.items()}

    def risk_score(self, results: dict) -> tuple:
        """Combine the indicator results into ``(verdict, score)``.

        A weighted average (by severity), plus a bonus for each pair of
        indicators that both raise suspicion, with a floor so one strong
        signal is not diluted.
        """
        weights = {name: config.INDICATOR_WEIGHTS.get(name, 0)
                   for name in results}
        total = sum(weights.values())
        if not total:
            return config.NOT_PHISHING, float(config.NOT_PHISHING)
        score = sum(weights[name] * results[name].score
                    for name in results) / total
        for first, second in config.AMPLIFY_PAIRS:
            if (first in results and second in results
                    and results[first].score >= config.PROBABLY_PHISHING
                    and results[second].score >= config.PROBABLY_PHISHING):
                score += config.AMPLIFY_BONUS
        if any(name in results and results[name].score == config.PHISHING
               for name in config.STRONG_SIGNAL_INDICATORS):
            score = max(score, config.VERDICT_THRESHOLDS[1][0])
        score = min(score, float(config.PHISHING))
        for upper, verdict in config.VERDICT_THRESHOLDS:
            if score < upper:
                return verdict, round(score, 2)
        return config.PHISHING, round(score, 2)

    # --- Blocklist, analysis and recording ---------------------------------

    def check_blocklist(self) -> list:
        """Return the blocklist entries matching this email, if any.

        Runs before the indicators: the From domain, link hosts and
        attachment hashes are looked up in the history store. Received
        IPs are not: IP entries come from links, and a relay IP is
        shared by legitimate mail.
        """
        candidates = []
        if self._from_registered:
            candidates.append(('domain', self._from_registered))
        for _, _, host in self._urls:
            candidates.append(('ip', host) if _is_ip(host)
                              else ('domain', _registered_domain(host)))
        candidates +=[('hash', att['hash']['sha256'])
                       for att in self._attachments
                       if att.get('hash', {}).get('sha256')]
        entries = []
        for kind, value in dict.fromkeys(candidates):
            entry = self.store.get_blocklist_entry(kind, value)
            if entry is not None:
                entries.append(entry)
        return entries

    def analyze(self) -> dict:
        """Analyse the email and return a report that can be a JSON.

        ``{verdict, verdict_name, score, indicators}``; for a blocklist
        hit the indicators are the ones saved with the entry.
        """
        message_id = self._header.get('header', {}).get(
            'message-id', [None])[0]
        entries = self.check_blocklist()
        if entries:
            report = next((e.report for e in entries if e.report), None)
            # Only a blocklisted sender counts against the sender: a
            # quoted or forwarded bad link must not ruin its name.
            if any((e.kind, e.value) == ('domain', self._from_registered)
                   for e in entries):
                self._record(config.BLOCKLIST, False)
            logger.info('Analysis message_id=%s from_domain=%s '
                        'verdict=BLOCKLIST matched=%d', message_id,
                        self._from_registered, len(entries))
            return {'verdict': config.BLOCKLIST,
                    'verdict_name': config.VERDICT_NAMES[config.BLOCKLIST],
                    'score': float(config.BLOCKLIST),
                    'blocklisted': [{'kind': e.kind, 'value': e.value}
                                    for e in entries],
                    'indicators': report}

        results = self.run_all()
        verdict, score = self.risk_score(results)
        report = {'verdict': verdict,
                  'verdict_name': config.VERDICT_NAMES[verdict],
                  'score': score,
                  'indicators': {name: result.as_dict()
                                 for name, result in results.items()}}
        self._record(verdict, self._fully_authenticated(results),
                     report['indicators'], results)
        logger.info('Analysis message_id=%s from_domain=%s verdict=%s '
                    'score=%s indicators=%s', message_id,
                    self._from_registered, report['verdict_name'], score,
                    {name: r.score for name, r in results.items()})
        return report

    @staticmethod
    def _fully_authenticated(results: dict) -> bool:
        auth = results['Sender Authentication'].details
        return (auth['spf'], auth['dkim'], auth['dmarc']) == (
            'pass', 'pass', 'pass')

    def _record(self, verdict: int, fully_authenticated: bool,
                indicators: Optional[dict] = None,
                results: Optional[dict] = None) -> None:
        """Update the history store with the outcome.

        The legit list and the legit count only grow for fully
        authenticated senders, so a forged From can't build a good name,
        and the legit list never learns a look-alike of a known brand.
        """
        domain = self._from_registered
        if domain:
            self.store.record_message(domain, verdict, fully_authenticated)
            if (verdict == config.NOT_PHISHING and fully_authenticated
                    and results and results['Spoofed sender'].score
                    == config.NOT_PHISHING):
                self.store.add_legit_domain(domain)
                _LEGIT_INDEX_CACHE.pop(self.store, None)
        if verdict != config.PHISHING or not results:
            return
        legit = self._legit_index[0]
        for name in ('Suspicious links', 'Attachment analysis'):
            for item in results[name].details.get('block', []):
                if item['kind'] != 'domain' or item['value'] not in legit:
                    self.store.add_to_blocklist(item['kind'], item['value'],
                                                indicators)


def score_sender_auth(spf: str, dkim: str, dmarc: str) -> int:
    """Map SPF, DKIM and DMARC results to a verdict from ``config``.

    SPF and DKIM complement each other: forwarding breaks SPF but keeps
    DKIM, so a single SPF failure is never enough for ``PHISHING``.
    """
    authenticated = 'pass' in (spf, dkim)
    if dmarc == 'pass':
        return config.NOT_PHISHING
    if dmarc == 'fail':
        if not authenticated:
            return config.PHISHING
        return config.PROBABLY_PHISHING
    # No usable DMARC result from here on.
    if authenticated:
        return config.PROBABLY_NOT_PHISHING
    if {spf, dkim} & {'fail', 'softfail', 'permerror'}:
        return config.PROBABLY_PHISHING
    if spf == dkim == dmarc == 'none':
        return config.PROBABLY_PHISHING  # no authentication at all
    return config.PROBABLY_NOT_PHISHING  # only temperror / neutral

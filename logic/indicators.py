"""The phishing indicators and the analysis that runs them.

An indicator is a function ``(EmailContext) -> IndicatorResult`` registered
with ``@indicator(name, weight)``. To add one, write another decorated
function below: nothing else (registry, analysis, scoring, config) has to
change.
"""

import logging
import re
import unicodedata
from dataclasses import dataclass, field
from functools import cached_property
from typing import Optional
from urllib.parse import urlsplit

import eml_parser.decode
import eml_parser.regexes

from dal.history_store import HistoryStore
from logic import config, email_parser
from logic.attachments import scan_attachment
from logic.domains import (edit_distance, is_internationalized, is_ip,
                           legit_index, normalize_domain, registered_domain,
                           split_host)
from logic.scoring import risk_score

logger = logging.getLogger(__name__)

REGISTRY = {}  # indicator name -> (function, weight)

_NIQQUD_RE = re.compile('[֑-ׇ]')
_PUNCT_RE = re.compile(r'[^\w\s]|_')
_STRONG_URL_FLAGS = ('url-ip-host', 'url-userinfo')
_AUTH_RESULT_RE = eml_parser.regexes.authentication_result_regex


def indicator(name: str, weight: float):
    """Register the decorated function as the indicator ``name``.

    Weights are relative: the verdict uses the weighted average.
    """
    def decorator(func):
        REGISTRY[name] = (func, weight)
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


def collect(findings) -> tuple:
    """Merge ``(score, reasons, report entry)`` findings of flagged items.

    Returns ``(highest score, sorted reasons, report entries)`` with the
    entries capped at ``config.REPORT_LIMIT``.
    """
    score, reasons, entries = config.NOT_PHISHING, set(), []
    for item_score, item_reasons, entry in findings:
        score = max(score, item_score)
        reasons.update(item_reasons)
        if len(entries) < config.REPORT_LIMIT:
            entries.append(entry)
    return score, tuple(sorted(reasons)), entries


class EmailContext:
    """One parsed email (eml_parser's dict) and values derived from it."""

    def __init__(self, email: dict, store: HistoryStore):
        self.email = email
        self.store = store

    @cached_property
    def from_host(self) -> Optional[str]:
        domain = email_parser.sender_domain(self.email)
        return normalize_domain(domain) if domain else None

    @cached_property
    def from_registered(self) -> Optional[str]:
        return registered_domain(self.from_host) if self.from_host else None

    @cached_property
    def urls(self) -> list:
        """``(url, parts, host)`` for each distinct URL, up to a limit.

        Links without a scheme (``www.example.com/x``) are read as
        ``http://``. ``host`` is normalized like the From domain
        (punycode to Unicode, lower-case).
        """
        seen, urls = set(), []
        for url in email_parser.body_urls(self.email):
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
                urls.append((url, parts, normalize_domain(host)))
        return urls

    @cached_property
    def attachments(self) -> list:
        return email_parser.attachments(self.email)

    @cached_property
    def auth(self) -> tuple:
        """``({'spf', 'dkim', 'dmarc': result}, trust reasons)``.

        Only the topmost ``Authentication-Results`` header is read, and
        only if a trusted receiving server added it
        (``config.TRUSTED_AUTHSERV_IDS``): the sender can write any
        header below it, so results are never mixed across headers.
        """
        headers = email_parser.header(self.email, 'authentication-results')
        results = {'spf': 'none', 'dkim': 'none', 'dmarc': 'none'}
        if not headers:
            return results, ('auth-missing',)
        top = eml_parser.decode.noparenthesis(str(headers[0]), ' ')
        # authserv-id is the first token; an RFC 8601 version may follow.
        server = (top.split(';', 1)[0].split() or [''])[0].lower()
        if server not in config.TRUSTED_AUTHSERV_IDS:
            return results, ('auth-untrusted-server',)
        found = {}
        for method, value in _AUTH_RESULT_RE.findall(top):
            method, value = method.lower(), value.lower()
            # Any passing result wins (e.g. one of several DKIM
            # signatures); otherwise the first one is kept.
            if method not in found or value == 'pass':
                found[method] = value
        return {check: found.get(check, 'none') for check in results}, ()

    @property
    def fully_authenticated(self) -> bool:
        """SPF, DKIM and DMARC all passed."""
        return set(self.auth[0].values()) == {'pass'}


# --- Sender Authentication ---------------------------------------------------

def score_sender_auth(spf: str, dkim: str, dmarc: str) -> int:
    """Map SPF, DKIM and DMARC results to a verdict from ``config``.

    SPF and DKIM complement each other: forwarding breaks SPF but keeps
    DKIM, so a single SPF failure is never enough for ``PHISHING``.
    """
    authenticated = 'pass' in (spf, dkim)
    if dmarc == 'pass':
        return config.NOT_PHISHING
    if dmarc == 'fail':
        return (config.PROBABLY_PHISHING if authenticated
                else config.PHISHING)
    # No usable DMARC result from here on.
    if authenticated:
        return config.PROBABLY_NOT_PHISHING
    if {spf, dkim} & {'fail', 'softfail', 'permerror'}:
        return config.PROBABLY_PHISHING
    if spf == dkim == dmarc == 'none':
        return config.PROBABLY_PHISHING  # no authentication at all
    return config.PROBABLY_NOT_PHISHING  # only temperror / neutral


@indicator('Sender Authentication', weight=0.20)
def sender_authentication(ctx: EmailContext) -> IndicatorResult:
    """Score the SPF, DKIM and DMARC results found in the email."""
    results, trust_reasons = ctx.auth
    reasons = trust_reasons + tuple(
        f'{check}-{value}' for check, value in results.items()
        if value != 'pass')
    return IndicatorResult(score_sender_auth(**results), reasons, results)


# --- Suspicious links ----------------------------------------------------------

def _url_flags(parts, host: str) -> list:
    flags = []
    if is_ip(host):
        flags.append('url-ip-host')
    else:
        sub_labels, _, suffix = split_host(host)
        if registered_domain(host) in config.URL_SHORTENERS:
            flags.append('url-shortener')
        if suffix.rsplit('.', 1)[-1] in config.CHEAP_TLDS:
            flags.append('url-cheap-tld')
        if len(sub_labels) > config.MAX_SUBDOMAINS:
            flags.append('url-many-subdomains')
        if is_internationalized(parts.hostname or host):
            flags.append('url-punycode')
    if parts.username is not None:
        flags.append('url-userinfo')
    try:
        if parts.port not in (None, 80, 443):
            flags.append('url-port')
    except ValueError:
        flags.append('url-port')
    return flags


@indicator('Suspicious links', weight=0.20)
def suspicious_links(ctx: EmailContext) -> IndicatorResult:
    """Static checks on every URL: IP hosts, shorteners, cheap TLDs..."""
    def findings():
        for url, parts, host in ctx.urls:
            flags = _url_flags(parts, host)
            if flags:
                strong = any(flag in _STRONG_URL_FLAGS for flag in flags)
                score = (config.PHISHING if strong or len(flags) >= 2
                         else config.PROBABLY_PHISHING)
                yield score, flags, {'url': url[:config.REPORT_CHARS],
                                     'flags': flags}

    score, reasons, flagged = collect(findings())
    return IndicatorResult(score, reasons, {'url_count': len(ctx.urls),
                                            'flagged_urls': flagged})


# --- Spoofed sender ------------------------------------------------------------

def _contains_brand(host: str, brand: str, tokens: set) -> bool:
    """A long brand may start any label or '-' part (appleid-verify,
    mizrahi-tefahot-secure) but not sit inside a word (purchase)."""
    return brand in tokens or (
        len(brand) >= config.SPOOF_MIN_PREFIX_LEN and (
            host.startswith(brand) or f'.{brand}' in host
            or f'-{brand}' in host))


def _is_lookalike(brand: str, parts: set) -> bool:
    limit = config.SPOOF_MAX_EDIT_DISTANCE
    return len(brand) >= config.SPOOF_MIN_FUZZY_LEN and any(
        abs(len(part) - len(brand)) <= limit
        and 1 <= edit_distance(part, brand) <= limit for part in parts)


@indicator('Spoofed sender', weight=0.25)
def spoofed_sender(ctx: EmailContext) -> IndicatorResult:
    """Look-alikes of known domains: containment, then edit distance.

    The domain is turned from punycode to Unicode and lower-cased,
    split into tokens, and compared with the legit brand labels.
    """
    if not ctx.from_host:
        return IndicatorResult(config.PROBABLY_PHISHING, ('from-missing',))
    host, registered = ctx.from_host, ctx.from_registered
    label = split_host(host)[1]
    legit, brands = legit_index()
    reasons, matched, score = set(), set(), config.NOT_PHISHING

    words = set(re.split(r'[\W_]+', email_parser.display_name(
        ctx.email).lower()))
    for brand, domains in brands.items():
        plain = re.sub(r'[\W_]', '', brand)
        if (len(plain) >= config.SPOOF_MIN_BRAND_LEN
                and plain in words and registered not in domains
                # a brand's own legit domain (facebookmail.com)
                and not (registered in legit and label.startswith(brand))):
            reasons.add('display-name-brand')
            matched.add(brand)
            score = config.PROBABLY_PHISHING

    if registered not in legit:
        if is_internationalized(email_parser.sender_domain(ctx.email)):
            reasons.add('from-punycode')
            score = max(score, config.PROBABLY_PHISHING)
        tokens = set(re.split(r'[.\-]', host))
        parts = {label, *label.split('-')}
        for brand in brands:
            if label == brand:
                reason = 'brand-other-tld'  # same name, different suffix
            elif _contains_brand(host, brand, tokens):
                reason = 'brand-in-domain'
            elif _is_lookalike(brand, parts):
                reason = 'lookalike-domain'
            else:
                continue
            reasons.add(reason)
            matched.add(brand)
            score = max(score, config.PROBABLY_PHISHING
                        if reason == 'brand-other-tld' else config.PHISHING)
    # A brand in the display name sent from that brand's name under
    # another suffix ("PayPal" <x@paypal.co>) is an impersonation.
    if {'brand-other-tld', 'display-name-brand'} <= reasons:
        score = config.PHISHING
    return IndicatorResult(score, tuple(sorted(reasons)),
                           {'sender_domain': registered,
                            'similar_to': sorted(matched)[:config.REPORT_LIMIT]})


# --- Suspicious wording --------------------------------------------------------

def _normalize_text(text: str) -> str:
    """Lower-case, no Hebrew niqqud, no punctuation, single spaces."""
    text = unicodedata.normalize('NFKC', text).lower()
    text = _NIQQUD_RE.sub('', text)
    return ' '.join(_PUNCT_RE.sub(' ', text).split())


_PHRASES = tuple((category, _normalize_text(phrase))
                 for category, phrases in config.SUSPICIOUS_PHRASES.items()
                 for phrase in phrases)


@indicator('Suspicious wording', weight=0.10)
def suspicious_wording(ctx: EmailContext) -> IndicatorResult:
    """Match a static, normalized phrase map (English and Hebrew)."""
    limit = config.MAX_WORDING_CHARS
    texts = [email_parser.subject(ctx.email)]
    length = len(texts[0])
    bodies = email_parser.body_texts(ctx.email, limit)
    while length < limit:  # the cap bounds the HTML parsing too
        body_text = next(bodies, None)
        if body_text is None:
            break
        texts.append(body_text)
        length += len(body_text) + 1
    padded = f' {_normalize_text(" ".join(texts)[:limit])} '
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
                           tuple(f'wording-{c}' for c in sorted(categories)),
                           {'categories': sorted(categories),
                            'hits': len(hits)})


# --- Attachment analysis -------------------------------------------------------

@indicator('Attachment analysis', weight=0.20)
def attachment_analysis(ctx: EmailContext) -> IndicatorResult:
    """Executables, double extensions, MIME mismatch and risky zips."""
    def findings():
        for attachment in ctx.attachments:
            score, reasons = scan_attachment(attachment)
            if reasons:
                name = (attachment.get('filename') or '')[:config.REPORT_CHARS]
                yield score, reasons, {'filename': name, 'reasons': reasons}

    score, reasons, flagged = collect(findings())
    return IndicatorResult(score, reasons,
                           {'attachment_count': len(ctx.attachments),
                            'flagged': flagged})


# --- Sender history ------------------------------------------------------------

@indicator('Sender history', weight=0.05)
def sender_history(ctx: EmailContext) -> IndicatorResult:
    """Reputation of the sender domain from the history store."""
    domain = ctx.from_registered
    if not domain:
        return IndicatorResult(config.PROBABLY_PHISHING, ('sender-unknown',))
    reputation = ctx.store.get_reputation(domain)
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


# --- Analysis --------------------------------------------------------------------

def run_all(ctx: EmailContext) -> dict:
    """Return ``{indicator name: IndicatorResult}`` for every indicator."""
    return {name: func(ctx) for name, (func, _) in REGISTRY.items()}


def analyze(email: dict, store: HistoryStore) -> dict:
    """Analyse the parsed email and return a report that can be a JSON.

    ``{verdict, verdict_name, score, indicators}``. A sender on the
    blocklist is not analysed: the indicators are the ones saved with the
    entry.
    """
    ctx = EmailContext(email, store)
    message_id = (email_parser.header(email, 'message-id') or [None])[0]
    entry = (store.get_blocked(ctx.from_registered)
             if ctx.from_registered else None)
    if entry is not None:
        _record(ctx, config.BLOCKLIST)
        logger.info('Analysis message_id=%s from_domain=%s '
                    'verdict=BLOCKLIST', message_id, ctx.from_registered)
        return {'verdict': config.BLOCKLIST,
                'verdict_name': config.VERDICT_NAMES[config.BLOCKLIST],
                'score': float(config.BLOCKLIST),
                'blocklisted': [{'kind': 'domain', 'value': entry.domain}],
                'indicators': entry.report}

    results = run_all(ctx)
    verdict, score = risk_score(
        results, {name: weight for name, (_, weight) in REGISTRY.items()})
    report = {'verdict': verdict, 'verdict_name': config.VERDICT_NAMES[verdict],
              'score': score,
              'indicators': {name: result.as_dict()
                             for name, result in results.items()}}
    _record(ctx, verdict, report['indicators'])
    logger.info('Analysis message_id=%s from_domain=%s verdict=%s '
                'score=%s indicators=%s', message_id, ctx.from_registered,
                report['verdict_name'], score,
                {name: r.score for name, r in results.items()})
    return report


def _record(ctx: EmailContext, verdict: int,
            indicators: Optional[dict] = None) -> None:
    """Update the sender's reputation, and blocklist it if it earned that.

    The legit count only grows for fully authenticated senders, so a
    forged From can't build a good name. A sender is blocklisted once it
    has ``config.BLOCKLIST_MIN_PHISHING`` phishing messages and more of
    them than legit ones, unless it is a known-legit domain (popular
    domains can be forged in the From line).
    """
    domain = ctx.from_registered
    if not domain:
        return
    ctx.store.record_message(
        domain,
        legit=ctx.fully_authenticated and verdict == config.NOT_PHISHING,
        phishing=verdict >= config.PROBABLY_PHISHING)
    if indicators is None or verdict < config.PROBABLY_PHISHING:
        return
    reputation = ctx.store.get_reputation(domain)
    if (reputation is not None
            and reputation.phishing_count >= config.BLOCKLIST_MIN_PHISHING
            and reputation.phishing_count > reputation.legit_count
            and domain not in legit_index()[0]):
        ctx.store.add_blocked(domain, indicators)

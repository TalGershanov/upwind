"""Host and domain helpers shared by the indicators."""

import functools
import ipaddress
import logging

from publicsuffixlist import PublicSuffixList

from logic import config

logger = logging.getLogger(__name__)
_PSL = PublicSuffixList()


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def split_host(host: str) -> tuple:
    """Return ``(sub_labels, label, public_suffix)`` of a host name."""
    host = host.lower().strip('.')
    suffix = _PSL.publicsuffix(host) or host.rsplit('.', 1)[-1]
    rest = host[:-len(suffix)].rstrip('.') if host.endswith(suffix) else host
    labels = rest.split('.') if rest else []
    return labels[:-1], (labels[-1] if labels else ''), suffix


def registered_domain(host: str) -> str:
    """``mail.bank.co.uk`` -> ``bank.co.uk`` (IP addresses unchanged)."""
    host = host.lower().strip('.')
    if is_ip(host):
        return host
    _, label, suffix = split_host(host)
    return f'{label}.{suffix}' if label else host


def normalize_domain(domain: str) -> str:
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


def is_internationalized(host: str) -> bool:
    """Non-ASCII or punycode (``xn--``) host name."""
    return not host.isascii() or any(
        label.startswith('xn--') for label in host.split('.'))


@functools.cache
def legit_index() -> tuple:
    """``(registered legit domains, {brand label: {domains}})``.

    Brands come only from ``config.LEGIT_DOMAINS_SEED``. The popular
    domains (Tranco) are legit too, but are not brands: thousands of
    ordinary words would otherwise match as look-alikes.
    """
    seed = {registered_domain(domain)
            for domain in config.LEGIT_DOMAINS_SEED}
    brands = {}
    for domain in seed:
        brands.setdefault(split_host(domain)[1], set()).add(domain)
    return frozenset(seed | load_top_domains()), brands


@functools.cache
def load_top_domains(path: str = config.TRANCO_FILE) -> frozenset:
    """Return the popular registered domains in ``path`` (Tranco list).

    One domain per line; blank lines and ``#`` comments are ignored. A
    missing or unreadable file gives an empty set (logged as an error),
    so analysis keeps working without it. The file is read once.
    """
    try:
        with open(path, encoding='utf-8') as f:
            lines = [line.strip().lower() for line in f]
    except OSError:
        logger.error('Popular-domains file %s could not be read', path)
        return frozenset()
    return frozenset(line for line in lines
                     if line and not line.startswith('#'))

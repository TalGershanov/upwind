"""Turn the content of an email text file into eml_parser's dict.

The API endpoint reads the uploaded text file and calls
:func:`parse_email`; the returned dict can be serialised to JSON. The
accessors below are the only code that reads that dict: the indicators
call them instead of digging into it.
"""

import logging
from email.utils import parseaddr
from html.parser import HTMLParser
from typing import Iterator, Union

import eml_parser

logger = logging.getLogger(__name__)

_PARSER = eml_parser.EmlParser(include_raw_body=True,
                               include_attachment_data=True)


class EmailParseError(ValueError):
    """Raised when the input cannot be parsed as an email."""


def parse_email(content: Union[str, bytes]) -> dict:
    """Parse the email text (or raw bytes) with eml_parser.

    Raises:
        EmailParseError: if the input is empty, not text, or has no
            headers.
    """
    if isinstance(content, str):
        content = content.encode('utf-8')
    if not isinstance(content, (bytes, bytearray)) or not content.strip():
        logger.warning('Rejected email input: empty or not text (%s)',
                       type(content).__name__)
        raise EmailParseError('email must be non-empty text')
    try:
        parsed = _PARSER.decode_email_bytes(bytes(content))
    except Exception as exc:  # eml_parser can raise many types
        logger.exception('eml_parser failed on a %d-byte email',
                         len(content))
        raise EmailParseError(f'could not parse email: {exc}') from exc

    if not parsed.get('header', {}).get('header'):
        logger.warning('Rejected email input: no headers found')
        raise EmailParseError('email has no headers')
    return parsed


# --- Accessors on the parsed email ------------------------------------------

def header(email: dict, name: str) -> list:
    """Raw values of header ``name`` (lower-case), topmost first."""
    return email['header']['header'].get(name) or []


def sender_domain(email: dict) -> str:
    """Domain of the From address, lower-cased ('' if none)."""
    address = email['header'].get('from') or ''
    return address.rpartition('@')[2].strip().lower()


def display_name(email: dict) -> str:
    """Display name of the From header ('' if none)."""
    return parseaddr((header(email, 'from') or [''])[0])[0]


def subject(email: dict) -> str:
    return email['header'].get('subject') or ''


def body_texts(email: dict, max_chars: int) -> Iterator[str]:
    """Visible text of each body, each cut to ``max_chars`` first.

    A generator, so a caller that has read enough stops the HTML
    parsing of the remaining bodies.
    """
    for body in email.get('body', []):
        yield _visible_text((body.get('content') or '')[:max_chars])


def body_urls(email: dict) -> Iterator[str]:
    """Raw link strings; links without a scheme get ``http://``."""
    for body in email.get('body', []):
        yield from body.get('uri', [])
        for url in body.get('uri_noscheme', []):
            yield f'http://{url}'


def attachments(email: dict) -> list:
    return email.get('attachment') or []


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

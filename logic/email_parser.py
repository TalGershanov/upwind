"""Turn the content of an email text file into eml_parser's dict.

The API endpoint reads the uploaded text file and calls
:func:`parse_email`; the indicators work on the returned dict, which
can be serialised to JSON.
"""

import logging
from typing import Union

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

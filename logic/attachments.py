"""Static checks on one parsed attachment (nothing is executed)."""

import base64
import binascii
import io
import mimetypes
import zipfile
from pathlib import Path, PurePosixPath

import eml_parser.constants

from logic import config

EXECUTABLE_EXTENSIONS = eml_parser.constants.EXECUTABLE_EXTENSIONS
_ZIP_TYPES = ('application/zip', 'application/x-zip-compressed')


def _declared_type(attachment: dict) -> str:
    types = attachment.get('content_header', {}).get('content-type') or ['']
    return types[0].split(';')[0].strip().lower()


def _mime_mismatch(declared: str, filename: str) -> bool:
    """Whether the declared type contradicts the one the extension implies."""
    guessed = mimetypes.guess_type(filename)[0]
    if not declared or not guessed or declared == 'application/octet-stream':
        return False
    if declared.split('/')[0] != guessed.split('/')[0]:
        return True
    families = config.MIME_FAMILIES
    return (declared in families
            and families[declared] != families.get(guessed, guessed))


def _scan_zip(attachment: dict) -> tuple:
    """Check a zip by its metadata only: nothing is decompressed.

    Returns ``(score, reasons)``.
    """
    raw = attachment.get('raw')
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
           in EXECUTABLE_EXTENSIONS for info in infos):
        reasons.append('zip-contains-executable')
    total = sum(info.file_size for info in infos)
    if (len(infos) > config.MAX_ZIP_ENTRIES
            or total > config.MAX_ZIP_UNCOMPRESSED_BYTES
            or any(info.file_size >= config.ZIP_RATIO_MIN_BYTES
                   and info.file_size / max(info.compress_size, 1)
                   > config.MAX_ZIP_RATIO for info in infos)):
        reasons.append('zip-bomb-suspect')
    return (config.PHISHING if reasons else config.NOT_PHISHING), reasons


def scan_attachment(attachment: dict) -> tuple:
    """Return ``(score, reasons)`` for one attachment."""
    score, reasons = config.NOT_PHISHING, []
    for code in attachment.get('anomaly') or []:
        reasons.append(f'attachment-anomaly:{code}')
        score = config.PHISHING

    filename = attachment.get('filename') or ''
    extension = Path(filename).suffix.lower().lstrip('.')
    if extension in EXECUTABLE_EXTENSIONS:
        reasons.append('attachment-executable')
        score = config.PHISHING
    if extension in config.MACRO_EXTENSIONS:
        reasons.append('attachment-macro-document')
        score = max(score, config.PROBABLY_PHISHING)

    declared = _declared_type(attachment)
    if _mime_mismatch(declared, filename):
        reasons.append('attachment-mime-mismatch')
        score = max(score, config.PROBABLY_PHISHING)

    if extension == 'zip' or declared in _ZIP_TYPES:
        zip_score, zip_reasons = _scan_zip(attachment)
        reasons += zip_reasons
        score = max(score, zip_score)
    return score, reasons

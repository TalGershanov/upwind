import os

# FINAL SCORE

BLOCKLIST = 5
PHISHING = 4
PROBABLY_PHISHING = 3
PROBABLY_NOT_PHISHING = 2
NOT_PHISHING = 1

# INDICATOR WEIGHT

# LOGGING
LOG_LEVEL = os.environ.get('PHISHING_LOG_LEVEL', 'INFO')
LOG_FILE = os.environ.get('PHISHING_LOG_FILE', 'logs/phishing.log')
LOG_MAX_BYTES = 5_000_000  # per file
LOG_BACKUP_COUNT = 3  # total on disk: 5 MB x (3 + 1) = 20 MB max
LOG_MAX_MESSAGE_CHARS = 1000

VERDICT_NAMES = {
    BLOCKLIST: 'BLOCKLIST',
    PHISHING: 'PHISHING',
    PROBABLY_PHISHING: 'PROBABLY_PHISHING',
    PROBABLY_NOT_PHISHING: 'PROBABLY_NOT_PHISHING',
    NOT_PHISHING: 'NOT_PHISHING',
}

# RISK SCORING
# Weight per registered indicator, by severity. Must add up to 1.
INDICATOR_WEIGHTS = {
    'Sender Authentication': 0.20,
    'Spoofed sender': 0.25,
    'Suspicious links': 0.20,
    'Attachment analysis': 0.20,
    'Suspicious wording': 0.10,
    'Sender history': 0.05,
}
# When both indicators of a pair are at least PROBABLY_PHISHING, the
# suspicion amplifies: AMPLIFY_BONUS is added to the weighted score.
AMPLIFY_PAIRS = (
    ('Sender Authentication', 'Spoofed sender'),
    ('Spoofed sender', 'Suspicious links'),
    ('Suspicious links', 'Suspicious wording'),
    ('Attachment analysis', 'Suspicious wording'),
    ('Sender Authentication', 'Suspicious links'),
)
AMPLIFY_BONUS = 0.5
# One PHISHING from these indicators keeps the verdict at least at
# PROBABLY_PHISHING, so a strong signal is not diluted by the average.
STRONG_SIGNAL_INDICATORS = ('Suspicious links', 'Attachment analysis',
                            'Spoofed sender')
# (upper bound of the weighted score, verdict); the last one is open.
VERDICT_THRESHOLDS = (
    (1.75, NOT_PHISHING),
    (2.5, PROBABLY_NOT_PHISHING),
    (3.25, PROBABLY_PHISHING),
)

# SENDER AUTHENTICATION
# Only the topmost Authentication-Results header is used, and only when
# it was added by one of these servers (its authserv-id): any header
# below it, or from another server, may have been written by the sender.
TRUSTED_AUTHSERV_IDS = frozenset(
    server.strip() for server in os.environ.get(
        'PHISHING_TRUSTED_AUTHSERV_IDS', 'mx.google.com').lower().split(',')
    if server.strip())

# SENDER HISTORY
ALLOWLIST_MIN_LEGIT = 3  # authenticated legit messages to be allowlisted

# SUSPICIOUS LINKS
MAX_URLS_ANALYZED = 500
MAX_REPORTED_URLS = 10
MAX_SUBDOMAINS = 3
URL_SHORTENERS = frozenset("""
    bit.ly tinyurl.com t.co goo.gl ow.ly is.gd cutt.ly rebrand.ly
    shorturl.at tiny.cc buff.ly bl.ink rb.gy t.ly s.id v.gd lnkd.in
    clck.ru shorte.st adf.ly tr.ee qr.net x.co
""".split())
CHEAP_TLDS = frozenset("""
    xyz top tk ml ga cf gq zip mov click link loan work rest fit icu buzz
    cyou cfd sbs monster quest bid win men party review stream download
    racing accountant science date cricket gdn country kim
""".split())

# SPOOFED SENDER
SPOOF_MIN_BRAND_LEN = 4  # shorter brands only match as a whole token
SPOOF_SHORT_LABEL = 5  # labels up to this length allow 1 edit
SPOOF_MAX_EDIT_DISTANCE = 2  # longer labels allow this many edits
SPOOF_MIN_LOOKALIKE_LEN = 6  # shorter brands get no edit-distance match
# Well-known domains; the history store adds the ones seen to be legit.
LEGIT_DOMAINS_SEED = frozenset("""
    google.com gmail.com paypal.com microsoft.com outlook.com hotmail.com
    apple.com icloud.com amazon.com facebook.com instagram.com netflix.com
    linkedin.com twitter.com dropbox.com wolt.com ebay.com adobe.com
    docusign.com dhl.com fedex.com ups.com usps.com chase.com
    wellsfargo.com bankofamerica.com citibank.com hsbc.com whatsapp.com
    telegram.org yahoo.com leumi.co.il bankhapoalim.co.il
    discountbank.co.il mizrahi-tefahot.co.il isracard.co.il
    cal-online.co.il israelpost.co.il bezeq.co.il cellcom.co.il
    partner.co.il facebookmail.com googlemail.com
""".split())

# SUSPICIOUS WORDING (normalized at import: lower-case, no punctuation)
MAX_WORDING_CHARS = 200_000
SUSPICIOUS_PHRASES = {
    'urgency': [
        'urgent', 'immediately', 'act now', 'within 24 hours',
        'final notice', 'last warning', 'action required',
        'expires today',
        'דחוף', 'מיידי', 'מיד', 'פעולה נדרשת', 'תוך 24 שעות',
        'התראה אחרונה',
    ],
    'credentials': [
        'verify your account', 'confirm your identity',
        'update your password', 'reset your password',
        'log in to your account', 'confirm your account',
        'validate your account', 'security check',
        'אמת את החשבון', 'אימות החשבון', 'אשר את הזהות',
        'עדכן את הסיסמה', 'התחבר לחשבון שלך',
    ],
    'payment': [
        'update your payment', 'payment failed', 'billing information',
        'credit card', 'wire transfer', 'gift card', 'unpaid invoice',
        'bank details',
        'עדכן את פרטי התשלום', 'התשלום נכשל', 'כרטיס אשראי',
        'העברה בנקאית', 'חשבונית שלא שולמה',
    ],
    'threat': [
        'account will be suspended', 'account has been suspended',
        'account will be closed', 'unauthorized activity',
        'suspicious activity', 'legal action',
        'החשבון שלך יושעה', 'החשבון יושעה', 'החשבון שלך ייחסם',
        'פעילות חשודה', 'פעילות לא מורשית', 'תביעה משפטית',
    ],
    'prize': [
        'you have won', 'claim your prize', 'congratulations',
        'free gift', 'lottery', 'inheritance',
        'זכית', 'פרס חינם', 'מזל טוב', 'מתנה חינם', 'הגרלה',
    ],
}

# ATTACHMENTS
MACRO_EXTENSIONS = frozenset(['docm', 'xlsm', 'pptm', 'dotm', 'xlsb'])
# A declared type from this set must match the type of the extension
# (e.g. invoice.pdf declared as an executable is a mismatch).
RISKY_MIME_TYPES = frozenset("""
    application/x-msdownload application/x-msdos-program
    application/x-dosexec application/vnd.microsoft.portable-executable
    application/x-executable application/java-archive application/x-sh
    application/javascript text/javascript application/hta text/html
    application/zip application/x-zip-compressed
    application/x-rar-compressed application/vnd.rar
    application/x-7z-compressed
""".split())
# A zip is opened only below this size, and only its metadata is read.
MAX_ZIP_INSPECT_BYTES = 5 * 1024 * 1024
MAX_ZIP_ENTRIES = 1000
MAX_ZIP_UNCOMPRESSED_BYTES = 100 * 1024 * 1024  # declared sizes, summed
MAX_ZIP_RATIO = 200  # declared size / compressed size, per entry
ZIP_RATIO_MIN_BYTES = 1_000_000  # ignore the ratio of small entries

import os

# FINAL SCORE

BLOCKLIST = 5
PHISHING = 4
PROBABLY_PHISHING = 3
PROBABLY_NOT_PHISHING = 2
NOT_PHISHING = 1

VERDICT_NAMES = {
    BLOCKLIST: 'BLOCKLIST',
    PHISHING: 'PHISHING',
    PROBABLY_PHISHING: 'PROBABLY_PHISHING',
    PROBABLY_NOT_PHISHING: 'PROBABLY_NOT_PHISHING',
    NOT_PHISHING: 'NOT_PHISHING',
}

# RISK SCORING
# Each indicator's weight is set where it is defined (@indicator).
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
# A sender domain (not a known-legit one) is blocklisted once it has this
# many phishing messages, and more of them than legit ones.
BLOCKLIST_MIN_PHISHING = 3

# REPORT (how much of what was found is returned)
REPORT_LIMIT = 10  # flagged URLs / attachments / brands listed
REPORT_CHARS = 200  # characters kept of a reported URL or file name

# SUSPICIOUS LINKS
MAX_URLS_ANALYZED = 500
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
SPOOF_MIN_BRAND_LEN = 4  # shorter brands are not matched in the display name
SPOOF_MIN_PREFIX_LEN = 5  # shorter brands only match as a whole token
SPOOF_MIN_FUZZY_LEN = 6  # look-alike (edit distance) needs a brand this long
SPOOF_MAX_EDIT_DISTANCE = 2  # look-alike: this many edits from the brand
# Well-known brand domains; Tranco's popular domains count as legit too.
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
# A declared type listed here must belong to the same family as the type
# of the file extension (invoice.pdf declared as an executable is a
# mismatch; x-zip-compressed and zip are the same family).
MIME_FAMILIES = {
    'application/x-msdownload': 'exe', 'application/x-msdos-program': 'exe',
    'application/x-dosexec': 'exe', 'application/x-executable': 'exe',
    'application/vnd.microsoft.portable-executable': 'exe',
    'application/java-archive': 'jar', 'application/x-sh': 'sh',
    'application/hta': 'hta', 'text/html': 'html',
    'application/javascript': 'js', 'text/javascript': 'js',
    'application/zip': 'zip', 'application/x-zip-compressed': 'zip',
    'application/x-rar-compressed': 'rar', 'application/vnd.rar': 'rar',
    'application/x-7z-compressed': '7z',
}
# A zip is never decompressed: only its metadata is read.
MAX_ZIP_ENTRIES = 1000
MAX_ZIP_UNCOMPRESSED_BYTES = 100 * 1024 * 1024  # declared sizes, summed
MAX_ZIP_RATIO = 200  # declared size / compressed size, per entry
ZIP_RATIO_MIN_BYTES = 1_000_000  # ignore the ratio of small entries

# KNOWN DOMAINS
# The 10,000 most popular registered domains (Tranco list of 2026-11-05),
# bundled as a static file and never refreshed. They count as legit, but
# are not used as brands for look-alike matching.
TRANCO_FILE = os.path.join(os.path.dirname(__file__), 'data',
                           'tranco_top10k.txt')

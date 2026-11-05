const MAX_BYTES = 5 * 1024 * 1024; // same limit as the server
const ICONS = { PHISHING: '🔴', PROBABLY_PHISHING: '🟠',
                PROBABLY_NOT_PHISHING: '🟡', NOT_PHISHING: '🟢', BLOCKLIST: '⛔' };

// Runs every time an email is opened while the add-on is open.
function onGmailMessageOpen(e) {
  try {
    // Temporary permission to read ONLY the open email.
    GmailApp.setCurrentMessageAccessToken(e.gmail.accessToken);
    const raw = GmailApp.getMessageById(e.gmail.messageId).getRawContent();
    const file = Utilities.newBlob(raw, 'message/rfc822', 'email.eml');
    if (file.getBytes().length > MAX_BYTES) return [textCard('Email is too large (max 5 MB).')];

    const baseUrl = PropertiesService.getScriptProperties().getProperty('API_URL');
    if (!baseUrl) return [textCard('API_URL is not set (Project Settings → Script properties).')];

    // Same request the website sends: multipart form with a "file" field.
    const res = UrlFetchApp.fetch(baseUrl.replace(/\/$/, '') + '/api/analyze', {
      method: 'post', payload: { file: file }, muteHttpExceptions: true });

    let data = {};
    try { data = JSON.parse(res.getContentText()); } catch (_) {}
    if (res.getResponseCode() !== 200) {
      return [textCard('Server error ' + res.getResponseCode() + ': ' + (data.detail || 'no details'))];
    }
    const headers = res.getHeaders();
    return [resultCard(data, headers['X-Instance-Id'] || headers['x-instance-id'])];
  } catch (err) {
    return [textCard('Could not analyze this email: ' + err.message)];
  }
}

function resultCard(data, instance) {
  const section = CardService.newCardSection().setHeader('Indicators');
  if (data.blocklisted) {
    data.blocklisted.forEach(b => section.addWidget(
      CardService.newDecoratedText().setTopLabel('Blocklisted ' + b.kind).setText(esc(b.value))));
  }
  const found = Object.entries(data.indicators || {}).filter(([, v]) => v.score > 0);
  found.forEach(([name, v]) => section.addWidget(CardService.newDecoratedText()
    .setTopLabel(name + ' · score ' + v.score)
    .setText(esc((v.reasons || []).join('\n')) || '—')
    .setWrapText(true)));
  if (!found.length && !data.blocklisted) {
    section.addWidget(CardService.newTextParagraph().setText('No suspicious indicators found.'));
  }
  const card = CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader()
      .setTitle((ICONS[data.verdict_name] || '') + ' ' + data.verdict_name)
      .setSubtitle('Score: ' + data.score))
    .addSection(section);
  if (instance) {
    card.addSection(CardService.newCardSection().addWidget(
      CardService.newTextParagraph().setText('Answered by: ' + esc(instance))));
  }
  return card.build();
}

function textCard(message) {
  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle('Phishing Detector'))
    .addSection(CardService.newCardSection().addWidget(
      CardService.newTextParagraph().setText(esc(message))))
    .build();
}

// Cards render basic HTML, so escape text that comes from emails.
function esc(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

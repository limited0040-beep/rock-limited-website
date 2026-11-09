const { createHash } = require('node:crypto');

const purposes = new Set([
  'Aircraft acquisition', 'Aircraft for sale', 'Aircraft leasing',
  'Business jet brokerage', 'Other aviation inquiry',
]);
const origins = new Set(['https://rocklimitedai.com', 'https://www.rocklimitedai.com']);

module.exports = async function inquiry(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  const { RESEND_API_KEY, INQUIRY_FROM, TURNSTILE_SITE_KEY, TURNSTILE_SECRET_KEY } = process.env;
  const enabled = Boolean(RESEND_API_KEY && INQUIRY_FROM && TURNSTILE_SITE_KEY && TURNSTILE_SECRET_KEY);

  if (req.method === 'GET') {
    return res.status(200).json({ siteKey: enabled ? TURNSTILE_SITE_KEY : null });
  }
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'GET, POST');
    return res.status(405).json({ accepted: false });
  }
  if (!enabled) return res.status(503).json({ accepted: false });
  if (!origins.has(req.headers.origin)) return res.status(403).json({ accepted: false });
  if (req.headers['content-type']?.split(';')[0].trim() !== 'application/json') {
    return res.status(415).json({ accepted: false });
  }

  const body = req.body;
  if (!body || typeof body !== 'object' || Array.isArray(body) ||
      Buffer.byteLength(JSON.stringify(body)) > 16384) {
    return res.status(400).json({ accepted: false });
  }
  const field = (key) => typeof body[key] === 'string' ? body[key].trim() : '';
  const name = field('name');
  const company = field('company');
  const email = field('email');
  const purpose = field('purpose');
  const message = field('message');
  const token = field('token');
  const attempt = field('attempt');

  if (!name || name.length > 120 || company.length > 150 ||
      email.length > 254 || !/^[^\s@,;<>]+@[^\s@,;<>]+\.[^\s@,;<>]+$/.test(email) ||
      !purposes.has(purpose) || !message || message.length > 4000 ||
      !token || token.length > 2048 || !/^[a-f\d-]{36}$/i.test(attempt)) {
    return res.status(400).json({ accepted: false });
  }

  try {
    const verification = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      body: new URLSearchParams({ secret: TURNSTILE_SECRET_KEY, response: token }),
      signal: AbortSignal.timeout(5000),
    });
    if (!verification.ok) return res.status(502).json({ accepted: false });
    const challenge = await verification.json();
    if (!challenge.success || challenge.hostname !== new URL(req.headers.origin).hostname ||
        challenge.action !== 'inquiry') {
      return res.status(403).json({ accepted: false });
    }

    const text = [`Name: ${name}`, `Company: ${company}`, `Business email: ${email}`, '', message].join('\n');
    const fingerprint = createHash('sha256').update(JSON.stringify([purpose, text])).digest('hex');
    const emailResponse = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${RESEND_API_KEY}`,
        'Content-Type': 'application/json',
        'Idempotency-Key': `inquiry-${attempt}-${fingerprint}`,
      },
      body: JSON.stringify({
        from: INQUIRY_FROM, to: ['sales@rocklimitedai.com'], reply_to: email,
        subject: `Rock Limited aviation inquiry — ${purpose}`, text,
      }),
      signal: AbortSignal.timeout(7000),
    });
    if (!emailResponse.ok) return res.status(502).json({ accepted: false });
    const receipt = await emailResponse.json();
    if (typeof receipt.id !== 'string' || !receipt.id) {
      return res.status(502).json({ accepted: false });
    }
    return res.status(200).json({ accepted: true });
  } catch {
    return res.status(502).json({ accepted: false });
  }
};

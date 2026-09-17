const crypto = require('crypto');

const {
  SUPABASE_URL,
  SUPABASE_SERVICE_KEY,
  VERIFY_API_URL,
  VERIFY_API_KEY,
  TELEGRAM_BOT_TOKEN,
  TELEGRAM_MAIN_CHANNEL_ID,
  JWT_SECRET,
  ADMIN_PASSWORD,
} = process.env;

/* ============================================================
   Supabase REST
   ============================================================ */
async function supabaseQuery(path) {
  const res = await fetch(`${SUPABASE_URL}/rest/v1/${path}`, {
    headers: {
      apikey: SUPABASE_SERVICE_KEY,
      Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
      'Content-Type': 'application/json',
    },
  });
  const text = await res.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch {}
  return { ok: res.ok, status: res.status, data };
}

async function supabaseInsert(table, record) {
  const res = await fetch(`${SUPABASE_URL}/rest/v1/${table}`, {
    method: 'POST',
    headers: {
      apikey: SUPABASE_SERVICE_KEY,
      Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
      'Content-Type': 'application/json',
      Prefer: 'return=representation',
    },
    body: JSON.stringify(record),
  });
  const text = await res.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch {}
  return { ok: res.ok, status: res.status, data };
}

async function supabaseUpdate(path, patch) {
  const res = await fetch(`${SUPABASE_URL}/rest/v1/${path}`, {
    method: 'PATCH',
    headers: {
      apikey: SUPABASE_SERVICE_KEY,
      Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
      'Content-Type': 'application/json',
      Prefer: 'return=representation',
    },
    body: JSON.stringify(patch),
  });
  const text = await res.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch {}
  return { ok: res.ok, status: res.status, data };
}

async function supabaseDelete(path) {
  const res = await fetch(`${SUPABASE_URL}/rest/v1/${path}`, {
    method: 'DELETE',
    headers: {
      apikey: SUPABASE_SERVICE_KEY,
      Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
    },
  });
  return { ok: res.ok, status: res.status };
}

/* ============================================================
   Settings helpers
   ============================================================ */
async function getSetting(key, fallback = null) {
  const q = await supabaseQuery(`app_settings?key=eq.${encodeURIComponent(key)}&select=value`);
  const row = q.data?.[0];
  return row ? row.value : fallback;
}

async function setSetting(key, value) {
  const existing = await supabaseQuery(`app_settings?key=eq.${encodeURIComponent(key)}&select=key`);
  if (existing.data && existing.data.length) {
    return supabaseUpdate(`app_settings?key=eq.${encodeURIComponent(key)}`,
      { value: String(value), updated_at: new Date().toISOString() });
  }
  return supabaseInsert('app_settings', { key, value: String(value) });
}

async function getFee() {
  const v = await getSetting('fee', '10000');
  const n = parseFloat(v);
  return isNaN(n) ? 10000 : n;
}

/* ============================================================
   Password hashing (scrypt)
   ============================================================ */
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}

function verifyPassword(password, stored) {
  try {
    const [salt, hash] = String(stored).split(':');
    if (!salt || !hash) return false;
    const test = crypto.scryptSync(password, salt, 64).toString('hex');
    const a = Buffer.from(hash, 'hex');
    const b = Buffer.from(test, 'hex');
    return a.length === b.length && crypto.timingSafeEqual(a, b);
  } catch { return false; }
}

/* ============================================================
   JWT
   ============================================================ */
function b64url(buf) {
  return Buffer.from(buf).toString('base64')
    .replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}
function signJWT(payload, expiresInSec = 3600 * 4) {
  const header = { alg: 'HS256', typ: 'JWT' };
  const now = Math.floor(Date.now() / 1000);
  const full = { ...payload, iat: now, exp: now + expiresInSec };
  const h = b64url(JSON.stringify(header));
  const p = b64url(JSON.stringify(full));
  const sig = crypto.createHmac('sha256', JWT_SECRET).update(`${h}.${p}`).digest();
  return `${h}.${p}.${b64url(sig)}`;
}
function verifyJWT(token) {
  try {
    const [h, p, s] = String(token).split('.');
    if (!h || !p || !s) return null;
    const expected = b64url(crypto.createHmac('sha256', JWT_SECRET).update(`${h}.${p}`).digest());
    const a = Buffer.from(s);
    const b = Buffer.from(expected);
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
    const payload = JSON.parse(Buffer.from(p, 'base64').toString());
    if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) return null;
    return payload;
  } catch { return null; }
}
function requireAdmin(req) {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';
  const payload = verifyJWT(token);
  return payload && (payload.role === 'admin' || payload.role === 'super') ? payload : null;
}
function requireSuper(req) {
  const payload = requireAdmin(req);
  return payload && payload.role === 'super' ? payload : null;
}

/* ============================================================
   Verify.ET
   ============================================================ */
function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

async function _pollStatus(statusUrl) {
  try {
    const url = statusUrl.startsWith('http') ? statusUrl : `https://verify.et${statusUrl}`;
    const res = await fetch(url, { headers: { 'x-api-key': VERIFY_API_KEY } });
    const text = await res.text();
    let data = null;
    try { data = text ? JSON.parse(text) : null; } catch {}
    return { status: res.status, data };
  } catch { return { status: 0, data: null }; }
}

function _interpret(body) {
  if (!body || typeof body !== 'object') return { result: 'service_error', message: "We couldn't read the bank's response." };
  const items = body.data;
  const verification = body.verification || {};
  const item = Array.isArray(items) ? (items[0] || {}) : (items && typeof items === 'object' ? items : {});
  let verified = item.verified;
  if (verified == null) verified = verification.verified;
  const txStatus = item.status || verification.status;
  const pstatus = item.processingStatus || verification.processingStatus;

  if (pstatus === 'failed' || txStatus === 'failed' || txStatus === 'not_found') {
    if (txStatus === 'not_found' || !item || Object.keys(item).length === 0) {
      return { result: 'not_found', message: "We couldn't find a payment with that reference." };
    }
    return { result: 'failed', message: 'The bank shows this transaction as unsuccessful.' };
  }
  if (!verified) return { result: 'pending', message: "The bank hasn't finished confirming this payment yet." };

  const settle = item.settlementAccountMatch || {};
  if (settle.ambiguous) return { result: 'mismatch', message: "We couldn't confirm the recipient account." };
  if (settle.matched === false) return { result: 'mismatch', message: 'Payment was sent to the wrong account.' };

  const amountRaw = item.amount;
  let amount = null;
  if (amountRaw != null) {
    const cleaned = String(amountRaw).replace(/,/g, '').trim();
    const n = parseFloat(cleaned);
    if (!isNaN(n)) amount = n;
  }
  if (amount == null) return { result: 'service_error', message: "We couldn't read the amount from the receipt." };

  return { result: 'success', message: 'Verified', amount, receiver: settle.receiverAccount || item.receiverAccount || null };
}

async function verifyPayment(reference, suffix) {
  if (!VERIFY_API_KEY) return { result: 'service_error', message: 'Verification service not configured.' };
  const url = `${VERIFY_API_URL}?waitMs=5000`;
  const payload = suffix ? { reference, suffix } : { reference };
  const headers = {
    'Content-Type': 'application/json',
    'x-api-key': VERIFY_API_KEY,
    'Idempotency-Key': `abj-${Date.now()}-${reference}`,
  };

  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      const res = await fetch(url, { method: 'POST', headers, body: JSON.stringify(payload), signal: AbortSignal.timeout(7000) });
      const text = await res.text();
      let body = null;
      try { body = text ? JSON.parse(text) : null; } catch {}

      if (res.status === 401) return { result: 'service_error', message: 'Verification service unavailable.' };
      if (res.status === 402 || res.status === 403) return { result: 'service_error', message: 'Verification service unavailable.' };
      if (res.status === 409) return { result: 'duplicate', message: 'This transaction reference has already been used.' };
      if (res.status === 422) return { result: 'invalid', message: "We couldn't read your transaction details." };
      if (res.status === 429) return { result: 'service_error', message: 'Too many attempts. Try again shortly.' };
      if (res.status === 503) return { result: 'service_error', message: 'Bank service is busy. Try again shortly.' };
      if (res.status !== 200 && res.status !== 202) return { result: 'service_error', message: "We couldn't verify your payment." };

      if (res.status === 202) {
        const rid = body?.requestId;
        const links = body?.links || {};
        const statusUrl = links.statusUrl || (rid ? `/api/verify/${rid}` : null);
        if (!statusUrl) return { result: 'pending', message: 'The bank is still confirming.' };
        for (let i = 0; i < 3; i++) {
          await sleep(700);
          const poll = await _pollStatus(statusUrl);
          if (poll.status !== 200 || !poll.data) continue;
          let it = poll.data.data;
          if (Array.isArray(it)) it = it[0];
          if (!it || typeof it !== 'object') continue;
          if (it.processingStatus === 'completed') return _interpret(it);
          if (it.processingStatus === 'failed') return { result: 'failed', message: 'The bank shows this transaction as unsuccessful.' };
        }
        return { result: 'pending', message: 'The bank is still confirming.' };
      }
      return _interpret(body);
    } catch (err) {
      if (attempt === 0) { await sleep(500); continue; }
      return { result: 'service_error', message: 'Network error reaching the bank.' };
    }
  }
  return { result: 'service_error', message: 'Verification failed.' };
}

/* ============================================================
   Telegram invite
   ============================================================ */
async function createTelegramInvite(linkName) {
  const token = process.env.BOT_TOKEN;
  const channelId = process.env.TELEGRAM_MAIN_CHANNEL_ID;
  if (!token || !channelId) throw new Error('Telegram not configured.');
  const url = `https://api.telegram.org/bot${token}/createChatInviteLink`;
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      chat_id: channelId,
      member_limit: 1,
      name: String(linkName).slice(0, 32),
      expire_date: Math.floor(Date.now() / 1000) + 7 * 24 * 3600,
    }),
  });
  const data = await res.json();
  if (!data.ok) throw new Error(data.description || 'Telegram error');
  return data.result;
}

/* ============================================================
   Rate limiting
   ============================================================ */
async function checkRateLimit(ip, maxPerHour = 10) {
  if (!ip || ip === 'unknown') return true;
  const now = new Date();
  const windowStart = new Date(now);
  windowStart.setMinutes(0, 0, 0);
  const q = await supabaseQuery(
    `rate_limits?ip=eq.${encodeURIComponent(ip)}&window_start=eq.${windowStart.toISOString()}&select=count`
  );
  const row = q.data?.[0];
  const count = row?.count || 0;
  if (count >= maxPerHour) return false;
  if (row) {
    await supabaseUpdate(`rate_limits?ip=eq.${encodeURIComponent(ip)}&window_start=eq.${windowStart.toISOString()}`, { count: count + 1 });
  } else {
    await supabaseInsert('rate_limits', { ip, window_start: windowStart.toISOString(), count: 1 });
  }
  return true;
}

/* ============================================================
   Validation
   ============================================================ */
const NAME_RE = /^[A-Za-z][A-Za-z'\-]{1,}\s+[A-Za-z][A-Za-z'\-]{1,}$/;
const ID_RE = /^[A-Za-z]{2,6}[\s\-]?\d{2,8}\s*\/\s*\d{2,4}$/;
const VALID_SEMESTERS = ['First Semester', 'Second Semester'];
const VALID_STREAMS = ['Social Science', 'Natural Science', 'Pre-Engineering & Computing', 'Other Natural Science'];
const VALID_METHODS = ['Telebirr', 'CBE', 'mPesa'];

function validateRegistration(input) {
  const { full_name, id_number, semester, stream, gender, payment_method, transaction_ref, transaction_suffix } = input;
  if (!full_name || typeof full_name !== 'string' || !NAME_RE.test(full_name.trim())) return 'Invalid full name.';
  if (!id_number || typeof id_number !== 'string' || !ID_RE.test(id_number.trim())) return 'Invalid Student ID. Format: RU0562/15';
  if (!VALID_SEMESTERS.includes(semester)) return 'Invalid semester.';
  if (!VALID_STREAMS.includes(stream)) return 'Invalid stream.';
  if (gender !== 'Male' && gender !== 'Female') return 'Invalid gender.';
  if (!VALID_METHODS.includes(payment_method)) return 'Invalid payment method.';
  if (!transaction_ref || typeof transaction_ref !== 'string' || transaction_ref.trim().length < 3) return 'Transaction reference is required.';
  if (transaction_ref.trim().length > 64) return 'Transaction reference is too long.';
  if (transaction_suffix != null && transaction_suffix !== '') {
    if (!/^\d{8}$/.test(String(transaction_suffix))) return 'CBE suffix must be exactly 8 digits.';
  }
  return null;
}

function randomPublicId() {
  const chars = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
  let out = '';
  const bytes = crypto.randomBytes(10);
  for (let i = 0; i < 10; i++) out += chars[bytes[i] % chars.length];
  return 'ABJ-' + out;
}

function getClientIp(req) {
  const fwd = req.headers['x-forwarded-for'] || '';
  return String(fwd).split(',')[0].trim() || req.socket?.remoteAddress || 'unknown';
}

function json(res, status, body) {
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Cache-Control', 'no-store');
  res.status(status).json(body);
}

module.exports = {
  supabaseQuery, supabaseInsert, supabaseUpdate, supabaseDelete,
  getSetting, setSetting, getFee,
  hashPassword, verifyPassword,
  signJWT, verifyJWT, requireAdmin, requireSuper,
  verifyPayment, createTelegramInvite,
  checkRateLimit, validateRegistration, randomPublicId,
  getClientIp, json,
  ADMIN_PASSWORD,
};
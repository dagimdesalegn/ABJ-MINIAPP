const crypto = require('crypto');

const {
  SUPABASE_URL,
  SUPABASE_SERVICE_KEY,
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

async function getPublicSettings() {
  const q = await supabaseQuery('app_settings?select=key,value');
  const s = {};
  (q.data || []).forEach(r => { s[r.key] = r.value; });

  const feeNum = parseFloat(s.fee);
  return {
    fee: isNaN(feeNum) || feeNum <= 0 ? 10000 : feeNum,
    accounts: {
      Telebirr: s.account_telebirr || '',
      CBE: s.account_cbe || '',
      mPesa: s.account_mpesa || '',
    },
    contact: {
      username: s.contact_username || '',
      phone: s.contact_phone || '',
    },
    updated_at: new Date().toISOString(),
  };
}

/* ============================================================
   DYNAMIC CONFIG
   ============================================================ */
let _configCache = null;
let _configCacheTime = 0;
const CONFIG_CACHE_MS = 60 * 1000;

async function getConfig() {
  const now = Date.now();
  if (_configCache && (now - _configCacheTime) < CONFIG_CACHE_MS) return _configCache;

  let s = {};
  try {
    const q = await supabaseQuery('app_settings?select=key,value');
    (q.data || []).forEach(r => { s[r.key] = r.value; });
  } catch {}

  _configCache = {
    tgApiId:      s.tg_api_id     || '',
    tgApiHash:    s.tg_api_hash   || '',
    tgSession:    s.tg_session    || '',
    tgChannelId:  s.tg_channel_id || '',
    tgBotToken:   s.tg_bot_token  || '',
    tgInviteMode: s.tg_invite_mode || 'session',
    verifyApiUrl: s.verify_api_url || '',
    verifyApiKey: s.verify_api_key || '',
  };
  _configCacheTime = now;
  return _configCache;
}

function invalidateConfigCache() {
  _configCache = null;
  _configCacheTime = 0;
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
   Verify.ET — OPTIMIZED
   ============================================================ */
function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

async function _pollStatus(statusUrl, apiKey) {
  try {
    const url = statusUrl.startsWith('http') ? statusUrl : `https://verify.et${statusUrl}`;
    const res = await fetch(url, { headers: { 'x-api-key': apiKey } });
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
  const cfg = await getConfig();
  if (!cfg.verifyApiKey) return { result: 'service_error', message: 'Verification service not configured. Please set it in the admin System tab.' };
  if (!cfg.verifyApiUrl) return { result: 'service_error', message: 'Verification URL not configured. Please set it in the admin System tab.' };

  const attempt = async (waitMs, timeoutMs) => {
    const url = `${cfg.verifyApiUrl}?waitMs=${waitMs}`;
    const headers = {
      'Content-Type': 'application/json',
      'x-api-key': cfg.verifyApiKey,
      'Idempotency-Key': `abj-${Date.now()}-${reference}`,
    };
    const res = await fetch(url, {
      method: 'POST',
      headers,
      body: JSON.stringify(suffix ? { reference, suffix } : { reference }),
      signal: AbortSignal.timeout(timeoutMs),
    });
    const text = await res.text();
    let body = null;
    try { body = text ? JSON.parse(text) : null; } catch {}
    return { status: res.status, body };
  };

  try {
    const r1 = await attempt(10000, 14000);

    if (r1.status === 401 || r1.status === 402 || r1.status === 403) {
      return { result: 'service_error', message: 'Verification service unavailable.' };
    }
    if (r1.status === 409) return { result: 'duplicate', message: 'This transaction reference has already been used.' };
    if (r1.status === 422) return { result: 'invalid', message: "We couldn't read your transaction details." };

    if (r1.status === 429 || r1.status === 503) {
      await sleep(2000);
      const r2 = await attempt(8000, 10000);
      if (r2.status === 200 || r2.status === 202) return await _handleSuccess(r2, cfg);
      return { result: 'service_error', message: 'Bank service is busy. Please upload a screenshot instead.' };
    }

    if (r1.status !== 200 && r1.status !== 202) {
      return { result: 'service_error', message: 'Could not verify your payment. Please upload a screenshot.' };
    }

    return await _handleSuccess(r1, cfg);
  } catch (err) {
    return { result: 'service_error', message: 'Network error reaching the bank. Please upload a screenshot.' };
  }
}

async function _handleSuccess(res, cfg) {
  if (res.status === 200) {
    const interpreted = _interpret(res.body);
    return interpreted;
  }

  const rid = res.body?.requestId;
  const links = res.body?.links || {};
  const statusUrl = links.statusUrl || (rid ? `/api/verify/${rid}` : null);

  if (statusUrl) {
    for (let i = 0; i < 8; i++) {
      await sleep(1200 + i * 150);
      const poll = await _pollStatus(statusUrl, cfg.verifyApiKey);
      if (poll.status !== 200 || !poll.data) continue;
      let it = poll.data.data;
      if (Array.isArray(it)) it = it[0];
      if (!it || typeof it !== 'object') continue;
      if (it.processingStatus === 'completed') return _interpret(it);
      if (it.processingStatus === 'failed') return { result: 'failed', message: 'The bank shows this transaction as unsuccessful.' };
    }
  }
  return { result: 'pending', message: 'The bank is still confirming your payment.' };
}

/* ============================================================
   Telegram — MUTEX LOCK (for session mode)
   ============================================================ */
async function acquireTgLock() {
  try {
    const res = await fetch(`${SUPABASE_URL}/rest/v1/rpc/acquire_tg_lock`, {
      method: 'POST',
      headers: {
        apikey: SUPABASE_SERVICE_KEY,
        Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
        'Content-Type': 'application/json',
      },
      body: '{}',
    });
    const text = await res.text();
    return text.trim() === 'true';
  } catch {
    return false;
  }
}

async function releaseTgLock() {
  try {
    await fetch(`${SUPABASE_URL}/rest/v1/rpc/release_tg_lock`, {
      method: 'POST',
      headers: {
        apikey: SUPABASE_SERVICE_KEY,
        Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
        'Content-Type': 'application/json',
      },
      body: '{}',
    });
  } catch {}
}

async function createInviteViaUser(cfg, { channelId, title, expireDate }) {
  const { TelegramClient, Api } = require('telegram');
  const { StringSession } = require('telegram/sessions');

  const client = new TelegramClient(
    new StringSession(cfg.tgSession),
    Number(cfg.tgApiId),
    cfg.tgApiHash,
    {
      connectionRetries: 3,
      useWSS: true,
      deviceModel: 'ABJ Tutorial',
      systemVersion: 'Vercel',
      appVersion: '1.0.0',
    }
  );

  await client.connect();

  try {
    const entity = await client.getInputEntity(channelId);

    let res;
    try {
      res = await client.invoke(new Api.messages.ExportChatInvite({
        peer: entity,
        expireDate,
        usageLimit: 1,
        title,
      }));
    } catch (e) {
      res = await client.invoke(new Api.messages.ExportChatInvite({
        peer: entity,
        expireDate,
        memberLimit: 1,
        title,
      }));
    }

    const link = res.link || (res.invite && res.invite.link);
    if (!link) throw new Error('Telegram returned no invite link.');
    return { invite_link: link, expire_date: expireDate, member_limit: 1, via: 'user' };
  } finally {
    try { await client.disconnect(); } catch {}
  }
}

/* ============================================================
   Bot-mode invite — pure HTTP, stateless, parallel-safe
   ============================================================ */
async function createBotInvite(cfg, { channelId, title, expireDate }) {
  if (!cfg.tgBotToken) throw new Error('Bot token not configured.');
  if (!channelId) throw new Error('Channel ID not configured.');

  const chatId = String(channelId).trim();

  const res = await fetch(`https://api.telegram.org/bot${cfg.tgBotToken}/createChatInviteLink`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      chat_id: chatId,
      name: title,
      expire_date: expireDate,
      member_limit: 1,
    }),
    signal: AbortSignal.timeout(8000),
  });

  const text = await res.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch {}

  if (!res.ok || !data || !data.ok) {
    const desc = (data && data.description) || `HTTP ${res.status}`;
    if (/not enough rights/i.test(desc)) {
      throw new Error('Bot is not an admin in the channel. Add it as admin with "Invite Users" permission.');
    }
    if (/chat not found/i.test(desc)) {
      throw new Error('Channel ID is wrong or bot is not in the channel.');
    }
    if (/too many requests/i.test(desc)) {
      throw new Error('Telegram rate limit hit — retry in a moment.');
    }
    throw new Error('Bot invite failed: ' + desc);
  }

  return {
    invite_link: data.result.invite_link,
    expire_date: data.result.expire_date,
    member_limit: 1,
    via: 'bot',
  };
}

/* ============================================================
   Unified invite creator — branches on mode
   ============================================================ */
async function createTelegramInvite(linkName) {
  const cfg = await getConfig();
  const mode = (cfg.tgInviteMode || 'session').toLowerCase();

  if (!cfg.tgChannelId) throw new Error('Telegram channel ID not configured. Set it in the admin System tab.');

  const title = String(linkName || 'ABJ').slice(0, 32);
  const expireDate = Math.floor(Date.now() / 1000) + 7 * 24 * 3600;

  /* ---------- BOT MODE ---------- */
  if (mode === 'bot') {
    if (!cfg.tgBotToken) {
      throw new Error('Bot token not configured. Add it in System tab or switch to Session mode.');
    }
    return await createBotInvite(cfg, { channelId: cfg.tgChannelId, title, expireDate });
  }

  /* ---------- SESSION MODE ---------- */
  if (!cfg.tgApiId || !cfg.tgApiHash || !cfg.tgSession) {
    throw new Error('Telegram API credentials not configured. Set API ID, API Hash, and Session in the admin System tab.');
  }

  const start = Date.now();
  const MAX_WAIT = 25000;
  let acquired = false;

  while (Date.now() - start < MAX_WAIT) {
    acquired = await acquireTgLock();
    if (acquired) break;
    await sleep(300 + Math.random() * 400);
  }

  if (!acquired) {
    throw new Error('Telegram is busy. Please try again in a moment.');
  }

  try {
    return await createInviteViaUser(cfg, { channelId: cfg.tgChannelId, title, expireDate });
  } finally {
    await releaseTgLock();
  }
}

/* ============================================================
   Screenshot upload → Supabase Storage
   ============================================================ */
async function uploadScreenshotToStorage(publicId, base64Data, mimeType) {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return { ok: false, error: 'Storage not configured.' };
  const safeId = String(publicId).replace(/[^A-Za-z0-9_-]/g, '');
  const ext = (mimeType || 'image/jpeg').split('/')[1]?.replace('jpeg', 'jpg') || 'jpg';
  const path = `${safeId}-${Date.now()}.${ext}`;

  let buffer;
  try {
    buffer = Buffer.from(String(base64Data).replace(/^data:[^,]+,/, ''), 'base64');
  } catch {
    return { ok: false, error: 'Invalid image data.' };
  }

  if (buffer.length > 3.5 * 1024 * 1024) {
    return { ok: false, error: 'Screenshot too large (max 3.5 MB).' };
  }

  const res = await fetch(`${SUPABASE_URL}/storage/v1/object/screenshots/${path}`, {
    method: 'POST',
    headers: {
      apikey: SUPABASE_SERVICE_KEY,
      Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
      'Content-Type': mimeType || 'image/jpeg',
      'x-upsert': 'true',
    },
    body: buffer,
  });

  if (!res.ok) {
    const t = await res.text();
    return { ok: false, error: 'Storage upload failed: ' + t.slice(0, 120) };
  }

  return {
    ok: true,
    url: `${SUPABASE_URL}/storage/v1/object/public/screenshots/${path}`,
  };
}

/* ============================================================
   Chat media upload → Supabase Storage (chat/ prefix)
   ============================================================ */
async function uploadChatMedia(sessionId, base64Data, mimeType, fileName) {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return { ok: false, error: 'Storage not configured.' };
  const safe = String(sessionId).replace(/[^A-Za-z0-9_-]/g, '').slice(0, 40);
  const ext = (fileName && fileName.split('.').pop()) ||
              (mimeType || 'image/jpeg').split('/')[1]?.replace('jpeg', 'jpg') || 'bin';
  const path = `chat/${safe}-${Date.now()}.${ext}`;

  let buffer;
  try {
    buffer = Buffer.from(String(base64Data).replace(/^data:[^,]+,/, ''), 'base64');
  } catch { return { ok: false, error: 'Invalid file data.' }; }

  if (buffer.length > 50 * 1024 * 1024) return { ok: false, error: 'File too large.' };

  const res = await fetch(`${SUPABASE_URL}/storage/v1/object/screenshots/${path}`, {
    method: 'POST',
    headers: {
      apikey: SUPABASE_SERVICE_KEY,
      Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
      'Content-Type': mimeType || 'application/octet-stream',
      'x-upsert': 'true',
    },
    body: buffer,
  });

  if (!res.ok) {
    const t = await res.text();
    return { ok: false, error: 'Upload failed: ' + t.slice(0, 120) };
  }
  return { ok: true, url: `${SUPABASE_URL}/storage/v1/object/public/screenshots/${path}` };
}

function randomSessionId() {
  return 'chat-' + crypto.randomBytes(12).toString('hex');
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
  getSetting, setSetting, getFee, getPublicSettings,
  getConfig, invalidateConfigCache,
  hashPassword, verifyPassword,
  signJWT, verifyJWT, requireAdmin, requireSuper,
  verifyPayment, createTelegramInvite, uploadScreenshotToStorage, uploadChatMedia, randomSessionId,
  checkRateLimit, validateRegistration, randomPublicId,
  getClientIp, json,
  ADMIN_PASSWORD,
};

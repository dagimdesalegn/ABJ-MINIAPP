const {
  requireAdmin, getPublicSettings, getSetting, setSetting,
  supabaseQuery, supabaseDelete, invalidateConfigCache, json,
} = require('./_lib');

const SYSTEM_KEYS = [
  'tg_api_id',
  'tg_api_hash',
  'tg_session',
  'tg_channel_id',
  'verify_api_url',
  'verify_api_key',
];

const TEMP_KEYS = [
  'tg_temp_session',
  'tg_temp_phone_hash',
  'tg_temp_phone',
  'tg_temp_api_id',
  'tg_temp_api_hash',
];

module.exports = async (req, res) => {
  try {
    return await handle(req, res);
  } catch (err) {
    console.error('[admin-settings] unhandled:', err);
    return json(res, 500, {
      error: 'Server error: ' + (err.message || String(err)),
      stack: String(err.stack || '').split('\n').slice(0, 3).join(' | '),
    });
  }
};

async function handle(req, res) {
  /* ============================================================
     PUBLIC GET (no auth) — used by home page
     ============================================================ */
  if (req.method === 'GET' && !req.headers.authorization) {
    try {
      const s = await getPublicSettings();
      return json(res, 200, s);
    } catch {
      return json(res, 200, {
        fee: 10000,
        accounts: { Telebirr: '', CBE: '', mPesa: '' },
        contact: { username: '', phone: '' },
      });
    }
  }

  /* ============================================================
     AUTHENTICATED ADMIN
     ============================================================ */
  const payload = requireAdmin(req);
  if (!payload) return json(res, 401, { error: 'Unauthorized' });

  const action = String(req.query.action || '');

  /* ---------- TELEGRAM WIZARD (super only) ---------- */
  if (req.method === 'POST' && action.startsWith('tg-')) {
    if (payload.role !== 'super') return json(res, 403, { error: 'Super admin only.' });

    const { TelegramClient, Api } = require('telegram');
    const { StringSession } = require('telegram/sessions');

    /* ---------- tg-start ---------- */
    if (action === 'tg-start') {
      const { api_id, api_hash, phone } = req.body || {};
      if (!api_id || !api_hash || !phone) {
        return json(res, 400, { error: 'API ID, API Hash and phone number are required.' });
      }

      let client;
      try {
        client = new TelegramClient(
          new StringSession(''),
          Number(api_id),
          String(api_hash),
          { connectionRetries: 3, useWSS: true, deviceModel: 'ABJ Tutorial', systemVersion: 'Vercel', appVersion: '1.0.0' }
        );
        await client.connect();

        const result = await client.invoke(new Api.auth.SendCode({
          phoneNumber: String(phone).trim(),
          apiId: Number(api_id),
          apiHash: String(api_hash),
          settings: new Api.CodeSettings({}),
        }));

        await setSetting('tg_temp_session',    client.session.save());
        await setSetting('tg_temp_phone_hash', result.phoneCodeHash);
        await setSetting('tg_temp_phone',      String(phone).trim());
        await setSetting('tg_temp_api_id',     String(api_id));
        await setSetting('tg_temp_api_hash',   String(api_hash));

        try { await client.disconnect(); } catch {}
        return json(res, 200, { ok: true });
      } catch (e) {
        try { if (client) await client.disconnect(); } catch {}
        return json(res, 500, { error: e.message || 'Could not send code. Check API ID, Hash and phone.' });
      }
    }

    /* ---------- tg-verify ---------- */
    if (action === 'tg-verify') {
      const { code } = req.body || {};
      if (!code) return json(res, 400, { error: 'Verification code is required.' });

      const tempSession = await getSetting('tg_temp_session', '');
      const phoneHash   = await getSetting('tg_temp_phone_hash', '');
      const phone       = await getSetting('tg_temp_phone', '');
      const apiIdStr    = await getSetting('tg_temp_api_id', '');
      const apiHashStr  = await getSetting('tg_temp_api_hash', '');

      if (!tempSession || !phoneHash || !apiIdStr || !apiHashStr) {
        return json(res, 400, { error: 'Session expired. Please start again.' });
      }

      let client;
      try {
        client = new TelegramClient(
          new StringSession(tempSession),
          Number(apiIdStr),
          String(apiHashStr),
          { connectionRetries: 3, useWSS: true, deviceModel: 'ABJ Tutorial', systemVersion: 'Vercel', appVersion: '1.0.0' }
        );
        await client.connect();

        const result = await client.invoke(new Api.auth.SignIn({
          phoneNumber: phone,
          phoneCodeHash: phoneHash,
          phoneCode: String(code).trim(),
        }));

        if (result instanceof Api.auth.AuthorizationSignUpRequired) {
          try { await client.disconnect(); } catch {}
          return json(res, 400, { error: 'This phone number is not registered on Telegram.' });
        }

        await setSetting('tg_session',  client.session.save());
        await setSetting('tg_api_id',   apiIdStr);
        await setSetting('tg_api_hash', apiHashStr);
        for (const k of TEMP_KEYS) await setSetting(k, '');

        try { await client.disconnect(); } catch {}
        invalidateConfigCache();
        return json(res, 200, { ok: true, needs_2fa: false });

      } catch (e) {
        const msg = String(e.message || e);
        if (msg.includes('SESSION_PASSWORD_NEEDED') || msg.includes('SESSION_PASSWORD')) {
          try { await client.disconnect(); } catch {}
          return json(res, 200, { ok: true, needs_2fa: true });
        }
        try { if (client) await client.disconnect(); } catch {}
        return json(res, 500, { error: msg || 'Verification failed.' });
      }
    }

    /* ---------- tg-password ---------- */
    if (action === 'tg-password') {
      const { password } = req.body || {};
      if (!password) return json(res, 400, { error: '2FA password is required.' });

      const tempSession = await getSetting('tg_temp_session', '');
      const apiIdStr    = await getSetting('tg_temp_api_id', '');
      const apiHashStr  = await getSetting('tg_temp_api_hash', '');

      if (!tempSession || !apiIdStr || !apiHashStr) {
        return json(res, 400, { error: 'Session expired. Please start again.' });
      }

      let client;
      try {
        client = new TelegramClient(
          new StringSession(tempSession),
          Number(apiIdStr),
          String(apiHashStr),
          { connectionRetries: 3, useWSS: true, deviceModel: 'ABJ Tutorial', systemVersion: 'Vercel', appVersion: '1.0.0' }
        );
        await client.connect();

        await client.signInWithPassword({
          password: async () => String(password),
          onError: (err) => { throw err; },
        });

        await setSetting('tg_session',  client.session.save());
        await setSetting('tg_api_id',   apiIdStr);
        await setSetting('tg_api_hash', apiHashStr);
        for (const k of TEMP_KEYS) await setSetting(k, '');

        try { await client.disconnect(); } catch {}
        invalidateConfigCache();
        return json(res, 200, { ok: true });

      } catch (e) {
        try { if (client) await client.disconnect(); } catch {}
        return json(res, 500, { error: e.message || 'Password verification failed.' });
      }
    }

    /* ---------- tg-cancel ---------- */
    if (action === 'tg-cancel') {
      for (const k of TEMP_KEYS) await setSetting(k, '');
      return json(res, 200, { ok: true });
    }

    /* ---------- tg-clear ---------- */
    if (action === 'tg-clear') {
      await setSetting('tg_session', '');
      await setSetting('tg_api_id', '');
      await setSetting('tg_api_hash', '');
      for (const k of TEMP_KEYS) await setSetting(k, '');
      invalidateConfigCache();
      return json(res, 200, { ok: true });
    }
  }

  /* ---------- GET: system settings ---------- */
  if (req.method === 'GET') {
    const q = await supabaseQuery('app_settings?select=key,value');
    const raw = {};
    (q.data || []).forEach(r => {
      if (TEMP_KEYS.includes(r.key)) return;
      raw[r.key] = r.value;
    });
    return json(res, 200, { settings: raw, role: payload.role });
  }

  /* ---------- POST: save settings ---------- */
  if (req.method === 'POST') {
    if (payload.role !== 'super') return json(res, 403, { error: 'Super admin only.' });

    const body = req.body || {};

    if (body.fee != null) {
      const n = parseFloat(body.fee);
      if (isNaN(n) || n <= 0) return json(res, 400, { error: 'Invalid fee amount.' });
      await setSetting('fee', String(Math.round(n)));
    }
    if (body.account_telebirr != null) await setSetting('account_telebirr', String(body.account_telebirr).slice(0, 32));
    if (body.account_cbe      != null) await setSetting('account_cbe',      String(body.account_cbe).slice(0, 32));
    if (body.account_mpesa    != null) await setSetting('account_mpesa',    String(body.account_mpesa).slice(0, 32));
    if (body.contact_username != null) await setSetting('contact_username', String(body.contact_username).slice(0, 64));
    if (body.contact_phone    != null) await setSetting('contact_phone',    String(body.contact_phone).slice(0, 32));

    let systemTouched = false;
    for (const key of SYSTEM_KEYS) {
      if (key in body) {
        const val = body[key];
        if (val === undefined || val === null) continue;
        const clean = String(val).trim().slice(0, 4096);
        await setSetting(key, clean);
        systemTouched = true;
      }
    }

    if (systemTouched) invalidateConfigCache();

    if (body.reset_rate_limits === true) {
      await supabaseDelete('rate_limits?id=neq.00000000-0000-0000-0000-000000000000');
    }

    return json(res, 200, { success: true, system_updated: systemTouched });
  }

  return json(res, 405, { error: 'Method not allowed' });
}
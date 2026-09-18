const {
  requireAdmin, getPublicSettings, setSetting,
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

module.exports = async (req, res) => {
  /* ---------- PUBLIC GET (no auth) ---------- */
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

  /* ---------- AUTHENTICATED ADMIN ---------- */
  const payload = requireAdmin(req);
  if (!payload) return json(res, 401, { error: 'Unauthorized' });

  if (req.method === 'GET') {
    const q = await supabaseQuery('app_settings?select=key,value');
    const raw = {};
    (q.data || []).forEach(r => { raw[r.key] = r.value; });

    /* Super admin sees everything unmasked */
    return json(res, 200, { settings: raw, role: payload.role });
  }

  if (req.method === 'POST') {
    if (payload.role !== 'super') return json(res, 403, { error: 'Super admin only.' });

    const body = req.body || {};

    /* Public-facing settings */
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

    /* System settings */
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
};
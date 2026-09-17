const {
  requireAdmin, getSetting, setSetting, getPublicSettings,
  supabaseQuery, json,
} = require('./_lib');

module.exports = async (req, res) => {
  /* ---------- PUBLIC GET (no auth) — used by home page ---------- */
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
    const out = {};
    (q.data || []).forEach(r => { out[r.key] = r.value; });
    return json(res, 200, { settings: out, role: payload.role });
  }

  if (req.method === 'POST') {
    if (payload.role !== 'super') return json(res, 403, { error: 'Super admin only.' });
    const { fee, account_telebirr, account_cbe, account_mpesa, contact_username, contact_phone } = req.body || {};

    if (fee != null) {
      const n = parseFloat(fee);
      if (isNaN(n) || n <= 0) return json(res, 400, { error: 'Invalid fee amount.' });
      await setSetting('fee', String(Math.round(n)));
    }
    if (account_telebirr != null) await setSetting('account_telebirr', String(account_telebirr).slice(0, 32));
    if (account_cbe      != null) await setSetting('account_cbe',      String(account_cbe).slice(0, 32));
    if (account_mpesa    != null) await setSetting('account_mpesa',    String(account_mpesa).slice(0, 32));
    if (contact_username != null) await setSetting('contact_username', String(contact_username).slice(0, 64));
    if (contact_phone    != null) await setSetting('contact_phone',    String(contact_phone).slice(0, 32));

    return json(res, 200, { success: true });
  }

  return json(res, 405, { error: 'Method not allowed' });
};
const crypto = require('crypto');
const { signJWT, getClientIp, checkRateLimit, supabaseQuery, verifyPassword, json, ADMIN_PASSWORD } = require('./_lib');

module.exports = async (req, res) => {
  if (req.method !== 'POST') return json(res, 405, { error: 'Method not allowed' });

  const ip = getClientIp(req);
  const allowed = await checkRateLimit(ip, 20);
  if (!allowed) return json(res, 429, { error: 'Too many attempts.' });

  const { username, password } = req.body || {};
  const user = String(username || 'super').trim().toLowerCase();
  const pass = String(password || '');

  // Super admin — env password, username "super"
  if (user === 'super' && ADMIN_PASSWORD) {
    const a = Buffer.from(pass);
    const b = Buffer.from(ADMIN_PASSWORD);
    const ok = a.length === b.length && crypto.timingSafeEqual(a, b);
    if (ok) {
      const token = signJWT({ role: 'super', username: 'super' }, 3600 * 4);
      return json(res, 200, { token, role: 'super', username: 'super' });
    }
    await new Promise(r => setTimeout(r, 700));
    return json(res, 401, { error: 'Invalid credentials.' });
  }

  // Additional admin — check DB
  const q = await supabaseQuery(`admins?username=eq.${encodeURIComponent(user)}&select=id,username,password_hash,full_name`);
  const row = q.data?.[0];
  if (!row) {
    await new Promise(r => setTimeout(r, 700));
    return json(res, 401, { error: 'Invalid credentials.' });
  }
  const ok = verifyPassword(pass, row.password_hash);
  if (!ok) {
    await new Promise(r => setTimeout(r, 700));
    return json(res, 401, { error: 'Invalid credentials.' });
  }
  const token = signJWT({ role: 'admin', username: row.username, admin_id: row.id }, 3600 * 4);
  return json(res, 200, { token, role: 'admin', username: row.username });
};
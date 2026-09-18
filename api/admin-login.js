const {
  signJWT, getClientIp, checkRateLimit,
  supabaseQuery, supabaseInsert, hashPassword, verifyPassword,
  json, ADMIN_PASSWORD,
} = require('./_lib');

/* Bootstrap the super admin in DB from env on first login (idempotent) */
async function bootstrapSuperAdmin() {
  const q = await supabaseQuery('admins?role=eq.super&select=id&limit=1');
  if (q.data && q.data.length) return;       // already bootstrapped
  if (!ADMIN_PASSWORD) return;                // no env password, skip

  await supabaseInsert('admins', {
    username: 'super',
    password_hash: hashPassword(ADMIN_PASSWORD),
    full_name: 'Super Admin',
    role: 'super',
    created_by: 'bootstrap',
  });
}

module.exports = async (req, res) => {
  if (req.method !== 'POST') return json(res, 405, { error: 'Method not allowed' });

  const ip = getClientIp(req);
  const allowed = await checkRateLimit(ip, 60);
  if (!allowed) return json(res, 429, { error: 'Too many attempts.' });

  const { username, password } = req.body || {};
  const user = String(username || 'super').trim().toLowerCase();
  const pass = String(password || '');

  /* Ensure super admin exists (first-time setup) */
  await bootstrapSuperAdmin();

  /* Look up in admins table (both super + admin) */
  const q = await supabaseQuery(
    `admins?username=eq.${encodeURIComponent(user)}&select=id,username,password_hash,full_name,role`
  );
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

  const role = row.role === 'super' ? 'super' : 'admin';
  const token = signJWT({ role, username: row.username, admin_id: row.id }, 3600 * 4);

  return json(res, 200, {
    token,
    role,
    username: row.username,
    full_name: row.full_name || '',
  });
};
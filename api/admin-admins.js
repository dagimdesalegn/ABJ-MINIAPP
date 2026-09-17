const { requireSuper, supabaseQuery, supabaseInsert, supabaseDelete, hashPassword, json } = require('./_lib');

module.exports = async (req, res) => {
  const superAdmin = requireSuper(req);
  if (!superAdmin) return json(res, 403, { error: 'Super admin only.' });

  if (req.method === 'GET') {
    const q = await supabaseQuery('admins?order=created_at.desc&select=id,username,full_name,created_at');
    return json(res, 200, { admins: q.data || [] });
  }

  if (req.method === 'POST') {
    const { username, password, full_name } = req.body || {};
    const u = String(username || '').trim().toLowerCase();
    const p = String(password || '');
    const n = String(full_name || '').trim().slice(0, 64);

    if (!/^[a-z0-9_]{3,24}$/.test(u)) return json(res, 400, { error: 'Username must be 3–24 chars, lowercase letters, digits, underscore.' });
    if (p.length < 6) return json(res, 400, { error: 'Password must be at least 6 characters.' });
    if (u === 'super') return json(res, 400, { error: 'Reserved username.' });

    const exists = await supabaseQuery(`admins?username=eq.${encodeURIComponent(u)}&select=id`);
    if (exists.data && exists.data.length) return json(res, 409, { error: 'Username already exists.' });

    const hash = hashPassword(p);
    const ins = await supabaseInsert('admins', {
      username: u,
      password_hash: hash,
      full_name: n || null,
      created_by: superAdmin.username,
    });
    if (!ins.ok) return json(res, 500, { error: 'Could not create admin.' });
    return json(res, 200, { success: true, admin: ins.data?.[0] });
  }

  if (req.method === 'DELETE') {
    const id = String(req.query.id || '');
    if (!/^[0-9a-f-]{36}$/.test(id)) return json(res, 400, { error: 'Invalid id.' });
    const del = await supabaseDelete(`admins?id=eq.${encodeURIComponent(id)}`);
    if (!del.ok) return json(res, 500, { error: 'Could not delete.' });
    return json(res, 200, { success: true });
  }

  return json(res, 405, { error: 'Method not allowed' });
};
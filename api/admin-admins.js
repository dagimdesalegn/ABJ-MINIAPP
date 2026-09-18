const {
  requireAdmin, requireSuper,
  supabaseQuery, supabaseInsert, supabaseUpdate, supabaseDelete,
  hashPassword, verifyPassword, json,
} = require('./_lib');

module.exports = async (req, res) => {

  /* ============================================================
     PROFILE — self-service (any admin)
     GET  /api/admin-admins?action=profile   → view own profile
     POST /api/admin-admins?action=profile   → update own profile
     ============================================================ */
  const action = String(req.query.action || '');
  if (action === 'profile') {
    const me = requireAdmin(req);
    if (!me) return json(res, 401, { error: 'Unauthorized' });

    if (req.method === 'GET') {
      const q = await supabaseQuery(
        `admins?id=eq.${encodeURIComponent(me.admin_id)}&select=id,username,full_name,role,created_at`
      );
      const row = q.data?.[0];
      if (!row) return json(res, 404, { error: 'Profile not found.' });
      return json(res, 200, { profile: row });
    }

    if (req.method === 'POST') {
      const { username, full_name, current_password, new_password } = req.body || {};

      const q = await supabaseQuery(`admins?id=eq.${encodeURIComponent(me.admin_id)}&select=*`);
      const row = q.data?.[0];
      if (!row) return json(res, 404, { error: 'Profile not found.' });

      const patch = {};

      /* Username change */
      if (username && String(username).trim().toLowerCase() !== row.username) {
        const u = String(username).trim().toLowerCase();
        if (!/^[a-z0-9_]{3,24}$/.test(u)) {
          return json(res, 400, { error: 'Username must be 3–24 chars (lowercase a-z, 0-9, _).' });
        }
        const exists = await supabaseQuery(`admins?username=eq.${encodeURIComponent(u)}&select=id`);
        if (exists.data && exists.data.length) {
          return json(res, 409, { error: 'Username already taken.' });
        }
        patch.username = u;
      }

      /* Full name change */
      if (full_name != null) {
        patch.full_name = String(full_name).trim().slice(0, 64);
      }

      /* Password change */
      if (new_password) {
        if (!current_password) {
          return json(res, 400, { error: 'Enter your current password to change it.' });
        }
        if (!verifyPassword(String(current_password), row.password_hash)) {
          return json(res, 401, { error: 'Current password is incorrect.' });
        }
        if (String(new_password).length < 6) {
          return json(res, 400, { error: 'New password must be at least 6 characters.' });
        }
        patch.password_hash = hashPassword(String(new_password));
      }

      if (!Object.keys(patch).length) {
        return json(res, 400, { error: 'Nothing to update.' });
      }

      const upd = await supabaseUpdate(`admins?id=eq.${encodeURIComponent(me.admin_id)}`, patch);
      if (!upd.ok) return json(res, 500, { error: 'Update failed.' });

      const updated = upd.data?.[0] || {};
      const reauth = !!patch.username || !!patch.password_hash;

      return json(res, 200, {
        success: true,
        profile: {
          id: updated.id,
          username: updated.username,
          full_name: updated.full_name,
          role: updated.role,
        },
        reauth_required: reauth,
      });
    }

    return json(res, 405, { error: 'Method not allowed' });
  }

  /* ============================================================
     ADMIN MANAGEMENT — super only
     ============================================================ */
  const superAdmin = requireSuper(req);
  if (!superAdmin) return json(res, 403, { error: 'Super admin only.' });

  if (req.method === 'GET') {
    const q = await supabaseQuery(
      'admins?order=role.desc,created_at.desc&select=id,username,full_name,role,created_at'
    );
    return json(res, 200, { admins: q.data || [] });
  }

  if (req.method === 'POST') {
    const { username, password, full_name, role } = req.body || {};
    const u = String(username || '').trim().toLowerCase();
    const p = String(password || '');
    const n = String(full_name || '').trim().slice(0, 64);
    const r = role === 'super' ? 'super' : 'admin';

    if (!/^[a-z0-9_]{3,24}$/.test(u)) {
      return json(res, 400, { error: 'Username must be 3–24 chars (lowercase a-z, 0-9, _).' });
    }
    if (p.length < 6) return json(res, 400, { error: 'Password must be at least 6 characters.' });

    const exists = await supabaseQuery(`admins?username=eq.${encodeURIComponent(u)}&select=id`);
    if (exists.data && exists.data.length) return json(res, 409, { error: 'Username already exists.' });

    const ins = await supabaseInsert('admins', {
      username: u,
      password_hash: hashPassword(p),
      full_name: n || null,
      role: r,
      created_by: superAdmin.username,
    });
    if (!ins.ok) return json(res, 500, { error: 'Could not create admin.' });
    return json(res, 200, { success: true, admin: ins.data?.[0] });
  }

  if (req.method === 'DELETE') {
    const id = String(req.query.id || '');
    if (!/^[0-9a-f-]{36}$/.test(id)) return json(res, 400, { error: 'Invalid id.' });

    /* Prevent deleting super admins */
    const q = await supabaseQuery(`admins?id=eq.${encodeURIComponent(id)}&select=role,username`);
    const row = q.data?.[0];
    if (!row) return json(res, 404, { error: 'Not found.' });
    if (row.role === 'super') return json(res, 400, { error: 'Cannot delete a super admin.' });

    const del = await supabaseDelete(`admins?id=eq.${encodeURIComponent(id)}`);
    if (!del.ok) return json(res, 500, { error: 'Could not delete.' });
    return json(res, 200, { success: true });
  }

  return json(res, 405, { error: 'Method not allowed' });
};
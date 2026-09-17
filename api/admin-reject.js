const { requireAdmin, supabaseQuery, supabaseUpdate, getClientIp, json } = require('./_lib');

module.exports = async (req, res) => {
  if (req.method !== 'POST') return json(res, 405, { error: 'Method not allowed' });
  const admin = requireAdmin(req);
  if (!admin) return json(res, 401, { error: 'Unauthorized' });

  const { id, reason } = req.body || {};
  if (!id) return json(res, 400, { error: 'Missing registration id.' });

  const q = await supabaseQuery(`registrations?id=eq.${encodeURIComponent(id)}&select=id,status`);
  const row = q.data?.[0];
  if (!row) return json(res, 404, { error: 'Not found.' });
  if (row.status !== 'pending') return json(res, 400, { error: `Already ${row.status}.` });

  const now = new Date().toISOString();
  const upd = await supabaseUpdate(
    `registrations?id=eq.${encodeURIComponent(id)}`,
    {
      status: 'rejected',
      rejection_reason: reason ? String(reason).slice(0, 500) : null,
      approved_by: 'admin:' + getClientIp(req),
      updated_at: now,
    }
  );

  if (!upd.ok) return json(res, 500, { error: 'Failed to update.' });
  return json(res, 200, { success: true });
};
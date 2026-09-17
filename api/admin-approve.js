const {
  requireAdmin, supabaseQuery, supabaseUpdate,
  createTelegramInvite, getClientIp, json,
} = require('./_lib');

module.exports = async (req, res) => {
  if (req.method !== 'POST') return json(res, 405, { error: 'Method not allowed' });
  const admin = requireAdmin(req);
  if (!admin) return json(res, 401, { error: 'Unauthorized' });

  const { id } = req.body || {};
  if (!id) return json(res, 400, { error: 'Missing registration id.' });

  const q = await supabaseQuery(`registrations?id=eq.${encodeURIComponent(id)}&select=*`);
  const row = q.data?.[0];
  if (!row) return json(res, 404, { error: 'Registration not found.' });
  if (row.status !== 'pending') {
    return json(res, 400, { error: `Already ${row.status}.` });
  }

  let invite;
  try {
    invite = await createTelegramInvite(`ABJ-${row.public_id}`);
  } catch (err) {
    return json(res, 500, { error: 'Failed to create invite link: ' + err.message });
  }

  const now = new Date().toISOString();
  const upd = await supabaseUpdate(
    `registrations?id=eq.${encodeURIComponent(id)}`,
    {
      status: 'approved',
      invite_link: invite.invite_link,
      invite_link_created_at: now,
      approved_at: now,
      approved_by: 'admin:' + getClientIp(req),
      updated_at: now,
    }
  );

  if (!upd.ok) return json(res, 500, { error: 'Failed to update registration.' });

  return json(res, 200, {
    success: true,
    invite_link: invite.invite_link,
    public_id: row.public_id,
  });
};
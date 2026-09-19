const { supabaseQuery, getClientIp, checkRateLimit, json } = require('./_lib');

module.exports = async (req, res) => {
  if (req.method !== 'GET') return json(res, 405, { error: 'Method not allowed' });

  const ip = getClientIp(req);
  const allowed = await checkRateLimit(ip, 60);
  if (!allowed) return json(res, 429, { error: 'Too many requests.' });

  const raw = String(req.query.id || '').trim().toUpperCase();
  if (!raw) return json(res, 400, { error: 'Registration ID required.' });

  const public_id = raw.replace(/\s+/g, '').replace(/\//g, '-');
  if (public_id.length < 3 || public_id.length > 32) {
    return json(res, 400, { error: 'Invalid registration ID format.' });
  }

  const q = await supabaseQuery(
    `registrations?public_id=eq.${encodeURIComponent(public_id)}` +
    `&select=public_id,id_number,status,full_name,semester,stream,created_at,approved_at,` +
    `invite_link,invite_link_created_at,rejection_reason,auto_approved,` +
    `verification_status,screenshot_url`
  );
  const row = q.data?.[0];
  if (!row) return json(res, 404, { error: 'No registration found for this Student ID.' });

  const out = {
    public_id: row.public_id,
    id_number: row.id_number || row.public_id,
    status: row.status,
    full_name: row.full_name,
    semester: row.semester,
    stream: row.stream,
    created_at: row.created_at,
    approved_at: row.approved_at,
    auto_approved: row.auto_approved || false,
    verification_status: row.verification_status || 'auto_verified',
    screenshot_uploaded: !!row.screenshot_url,
  };
  if (row.status === 'approved' && row.invite_link) {
    out.invite_link = row.invite_link;
    out.invite_link_created_at = row.invite_link_created_at;
  }
  if (row.status === 'rejected' && row.rejection_reason) {
    out.rejection_reason = row.rejection_reason;
  }

  return json(res, 200, out);
};
const { requireAdmin, supabaseQuery, json } = require('./_lib');

module.exports = async (req, res) => {
  if (req.method !== 'GET') return json(res, 405, { error: 'Method not allowed' });
  const payload = requireAdmin(req);
  if (!payload) return json(res, 401, { error: 'Unauthorized' });

  const status = String(req.query.status || 'pending');
  if (!['pending', 'approved', 'rejected'].includes(status)) {
    return json(res, 400, { error: 'Invalid status.' });
  }

  const q = await supabaseQuery(
    `registrations?status=eq.${status}&order=created_at.desc&limit=200` +
    `&select=id,public_id,full_name,id_number,semester,stream,gender,payment_method,` +
    `transaction_ref,amount,status,invite_link,approved_at,rejection_reason,created_at,` +
    `auto_approved,verification_status,screenshot_url,verify_error`
  );

  return json(res, 200, { items: q.data || [] });
};
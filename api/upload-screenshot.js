const {
  supabaseQuery, supabaseUpdate, uploadScreenshotToStorage,
  checkRateLimit, getClientIp, json,
} = require('./_lib');

module.exports = async (req, res) => {
  if (req.method !== 'POST') return json(res, 405, { error: 'Method not allowed' });

  const ip = getClientIp(req);
  const allowed = await checkRateLimit(ip, 10);
  if (!allowed) return json(res, 429, { error: 'Too many attempts. Please try again later.' });

  const { public_id, screenshot_base64, mime_type } = req.body || {};
  if (!public_id || !screenshot_base64) {
    return json(res, 400, { error: 'Missing public_id or screenshot.' });
  }

  const id = String(public_id).trim().toUpperCase();
  if (id.length < 3 || id.length > 32 || !/^[A-Z0-9\-\/]+$/.test(id)) {
    return json(res, 400, { error: 'Invalid registration ID.' });
  }
  const publicIdNorm = id.replace(/\s+/g, '').replace(/\//g, '-');

  const q = await supabaseQuery(
    `registrations?public_id=eq.${encodeURIComponent(publicIdNorm)}&select=id,status,screenshot_url`
  );
  const row = q.data?.[0];
  if (!row) return json(res, 404, { error: 'Registration not found.' });
  if (row.status !== 'pending') {
    return json(res, 400, { error: `Registration already ${row.status}.` });
  }

  const up = await uploadScreenshotToStorage(publicIdNorm, screenshot_base64, mime_type);
  if (!up.ok) return json(res, 500, { error: up.error || 'Upload failed.' });

  const upd = await supabaseUpdate(
    `registrations?id=eq.${encodeURIComponent(row.id)}`,
    {
      screenshot_url: up.url,
      verification_status: 'screenshot_uploaded',
      updated_at: new Date().toISOString(),
    }
  );
  if (!upd.ok) return json(res, 500, { error: 'Could not save screenshot.' });

  return json(res, 200, { success: true, screenshot_url: up.url });
};
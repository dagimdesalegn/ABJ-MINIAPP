const {
  requireSuper, supabaseQuery, supabaseInsert, supabaseDelete, json,
} = require('./_lib');

module.exports = async (req, res) => {
  /* ---------- PUBLIC GET (no auth) — home page slider ---------- */
  if (req.method === 'GET' && !req.headers.authorization) {
    const q = await supabaseQuery('testimonials?order=display_order.asc,created_at.asc&select=id,student_name,subject,text,stars');
    return json(res, 200, { items: q.data || [] });
  }

  /* ---------- SUPER ADMIN ---------- */
  const admin = requireSuper(req);
  if (!admin) return json(res, 403, { error: 'Super admin only.' });

  if (req.method === 'GET') {
    const q = await supabaseQuery('testimonials?order=display_order.asc,created_at.asc&select=id,student_name,subject,text,stars,created_at');
    return json(res, 200, { items: q.data || [] });
  }

  if (req.method === 'POST') {
    const { student_name, subject, text, stars } = req.body || {};
    if (!student_name || !subject || !text) return json(res, 400, { error: 'Name, subject, and text are required.' });
    if (String(text).length > 1000) return json(res, 400, { error: 'Text too long (max 1000 chars).' });
    const starVal = Math.min(5, Math.max(1, parseInt(stars, 10) || 5));
    const ins = await supabaseInsert('testimonials', {
      student_name: String(student_name).trim().slice(0, 64),
      subject: String(subject).trim().slice(0, 64),
      text: String(text).trim(),
      stars: starVal,
      created_by: admin.username,
    });
    if (!ins.ok) return json(res, 500, { error: 'Could not save testimonial.' });
    return json(res, 200, { success: true, item: ins.data?.[0] });
  }

  if (req.method === 'DELETE') {
    const id = String(req.query.id || '');
    if (!/^[0-9a-f-]{36}$/.test(id)) return json(res, 400, { error: 'Invalid id.' });
    const del = await supabaseDelete(`testimonials?id=eq.${encodeURIComponent(id)}`);
    return json(res, del.ok ? 200 : 500, { success: del.ok });
  }

  return json(res, 405, { error: 'Method not allowed' });
};
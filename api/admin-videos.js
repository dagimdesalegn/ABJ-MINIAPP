const { requireSuper, supabaseQuery, supabaseInsert, supabaseDelete, json } = require('./_lib');

module.exports = async (req, res) => {
  const admin = requireSuper(req);
  if (!admin) return json(res, 403, { error: 'Super admin only.' });

  if (req.method === 'GET') {
    const q = await supabaseQuery('videos?order=display_order.asc,created_at.asc&select=id,title,url,tag,display_order,created_at');
    return json(res, 200, { items: q.data || [] });
  }

  if (req.method === 'POST') {
    const { title, url, tag } = req.body || {};
    if (!title || !url) return json(res, 400, { error: 'Title and YouTube URL are required.' });
    if (String(title).length > 200) return json(res, 400, { error: 'Title too long.' });
    if (String(url).length > 500) return json(res, 400, { error: 'URL too long.' });
    const ins = await supabaseInsert('videos', {
      title: String(title).trim(),
      url: String(url).trim(),
      tag: String(tag || 'Lesson').trim().slice(0, 40),
      created_by: admin.username,
    });
    if (!ins.ok) return json(res, 500, { error: 'Could not save video.' });
    return json(res, 200, { success: true, item: ins.data?.[0] });
  }

  if (req.method === 'DELETE') {
    const id = String(req.query.id || '');
    if (!/^[0-9a-f-]{36}$/.test(id)) return json(res, 400, { error: 'Invalid id.' });
    const del = await supabaseDelete(`videos?id=eq.${encodeURIComponent(id)}`);
    return json(res, del.ok ? 200 : 500, { success: del.ok });
  }

  return json(res, 405, { error: 'Method not allowed' });
};
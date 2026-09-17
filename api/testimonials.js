const { supabaseQuery, json } = require('./_lib');

module.exports = async (req, res) => {
  if (req.method !== 'GET') return json(res, 405, { error: 'Method not allowed' });
  const q = await supabaseQuery('testimonials?order=display_order.asc,created_at.asc&select=id,student_name,subject,text,stars');
  return json(res, 200, { items: q.data || [] });
};
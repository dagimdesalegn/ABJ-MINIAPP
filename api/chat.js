const {
  supabaseQuery, supabaseInsert,
  uploadChatMedia, json,
} = require('./_lib');

module.exports = async (req, res) => {
  /* ---------- GET: fetch messages for a session ---------- */
  if (req.method === 'GET') {
    const sessionId = String(req.query.session_id || '').trim();
    if (!sessionId || sessionId.length > 64) return json(res, 400, { error: 'Invalid session.' });

    const q = await supabaseQuery(
      `chat_messages?session_id=eq.${encodeURIComponent(sessionId)}` +
      `&order=created_at.asc&limit=500` +
      `&select=id,sender,sender_name,message_type,content,file_url,file_name,created_at`
    );
    return json(res, 200, { items: q.data || [] });
  }

  /* ---------- POST: send a message (no rate limit) ---------- */
  if (req.method === 'POST') {
    const body = req.body || {};
    const sessionId = String(body.session_id || '').trim();
    if (!sessionId || sessionId.length > 64) return json(res, 400, { error: 'Invalid session.' });

    const type = ['text','image','pdf','voice'].includes(body.message_type) ? body.message_type : 'text';
    const content = body.content ? String(body.content).slice(0, 8000) : null;
    const registrationId = body.registration_id ? String(body.registration_id).slice(0, 32) : null;

    let fileUrl = null, fileName = null, fileSize = null;

    if (type !== 'text') {
      if (!body.file_base64) return json(res, 400, { error: 'Missing file data.' });
      fileName = body.file_name ? String(body.file_name).slice(0, 100) : (type + '.bin');
      const up = await uploadChatMedia(sessionId, body.file_base64, body.mime_type || 'application/octet-stream', fileName);
      if (!up.ok) return json(res, 500, { error: up.error || 'Upload failed.' });
      fileUrl = up.url;
      try { fileSize = Buffer.from(String(body.file_base64).replace(/^data:[^,]+,/, ''), 'base64').length; } catch {}
    } else if (!content) {
      return json(res, 400, { error: 'Empty message.' });
    }

    const ins = await supabaseInsert('chat_messages', {
      session_id: sessionId,
      registration_id: registrationId,
      sender: 'user',
      sender_name: registrationId || 'Guest',
      message_type: type,
      content,
      file_url: fileUrl,
      file_name: fileName,
      file_size: fileSize,
      is_read: false,
    });
    if (!ins.ok) return json(res, 500, { error: 'Could not save message.' });
    return json(res, 200, { success: true, item: ins.data?.[0] });
  }

  return json(res, 405, { error: 'Method not allowed' });
};
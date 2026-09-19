const {
  signJWT, getClientIp, checkRateLimit,
  supabaseQuery, supabaseInsert, supabaseUpdate, supabaseDelete,
  hashPassword, verifyPassword,
  requireAdmin, requireSuper,
  getPublicSettings, getSetting, setSetting,
  invalidateConfigCache,
  createTelegramInvite,
  uploadChatMedia,
  json, ADMIN_PASSWORD,
} = require('./_lib');

/* ============================================================
   ROUTER
   ============================================================ */
const ROUTES = {
  login:        handleLogin,
  list:         handleList,
  approve:      handleApprove,
  reject:       handleReject,
  settings:     handleSettings,
  admins:       handleAdmins,
  videos:       handleVideos,
  testimonials: handleTestimonials,
  chats:        handleChats,
  stats:        handleStats,
};

module.exports = async (req, res) => {
  try {
    const route = String(req.query.route || '').toLowerCase();
    const fn = ROUTES[route];
    if (!fn) return json(res, 404, { error: 'Unknown admin route: ' + route });
    return await fn(req, res);
  } catch (err) {
    console.error('[admin] unhandled:', err);
    return json(res, 500, { error: 'Server error: ' + (err.message || String(err)) });
  }
};

/* ============================================================
   1. LOGIN
   ============================================================ */
async function bootstrapSuperAdmin() {
  const q = await supabaseQuery('admins?role=eq.super&select=id&limit=1');
  if (q.data && q.data.length) return;
  if (!ADMIN_PASSWORD) return;

  await supabaseInsert('admins', {
    username: 'super',
    password_hash: hashPassword(ADMIN_PASSWORD),
    full_name: 'Super Admin',
    role: 'super',
    created_by: 'bootstrap',
  });
}

async function handleLogin(req, res) {
  if (req.method !== 'POST') return json(res, 405, { error: 'Method not allowed' });

  const ip = getClientIp(req);
  const allowed = await checkRateLimit(ip, 60);
  if (!allowed) return json(res, 429, { error: 'Too many attempts.' });

  const { username, password } = req.body || {};
  const user = String(username || 'super').trim().toLowerCase();
  const pass = String(password || '');

  await bootstrapSuperAdmin();

  const q = await supabaseQuery(
    `admins?username=eq.${encodeURIComponent(user)}&select=id,username,password_hash,full_name,role`
  );
  const row = q.data?.[0];
  if (!row) {
    await new Promise(r => setTimeout(r, 700));
    return json(res, 401, { error: 'Invalid credentials.' });
  }

  const ok = verifyPassword(pass, row.password_hash);
  if (!ok) {
    await new Promise(r => setTimeout(r, 700));
    return json(res, 401, { error: 'Invalid credentials.' });
  }

  const role = row.role === 'super' ? 'super' : 'admin';
  const token = signJWT({ role, username: row.username, admin_id: row.id }, 3600 * 4);

  return json(res, 200, {
    token,
    role,
    username: row.username,
    full_name: row.full_name || '',
  });
}

/* ============================================================
   2. LIST
   ============================================================ */
async function handleList(req, res) {
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
}

/* ============================================================
   3. APPROVE
   ============================================================ */
async function handleApprove(req, res) {
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
}

/* ============================================================
   4. REJECT
   ============================================================ */
async function handleReject(req, res) {
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
}

/* ============================================================
   5. SETTINGS
   ============================================================ */
const SYSTEM_KEYS = [
  'tg_api_id',
  'tg_api_hash',
  'tg_session',
  'tg_channel_id',
  'verify_api_url',
  'verify_api_key',
];

const TEMP_KEYS = [
  'tg_temp_session',
  'tg_temp_phone_hash',
  'tg_temp_phone',
  'tg_temp_api_id',
  'tg_temp_api_hash',
];

async function handleSettings(req, res) {
  if (req.method === 'GET' && !req.headers.authorization) {
    try {
      const s = await getPublicSettings();
      return json(res, 200, s);
    } catch {
      return json(res, 200, {
        fee: 10000,
        accounts: { Telebirr: '', CBE: '', mPesa: '' },
        contact: { username: '', phone: '' },
      });
    }
  }

  const payload = requireAdmin(req);
  if (!payload) return json(res, 401, { error: 'Unauthorized' });

  const action = String(req.query.action || '');

  if (req.method === 'POST' && action.startsWith('tg-')) {
    if (payload.role !== 'super') return json(res, 403, { error: 'Super admin only.' });

    const { TelegramClient, Api } = require('telegram');
    const { StringSession } = require('telegram/sessions');
    const { computeCheck } = require('telegram/Password');

    const CLIENT_OPTS = {
      connectionRetries: 3,
      useWSS: true,
      deviceModel: 'ABJ Tutorial',
      systemVersion: 'Vercel',
      appVersion: '1.0.0',
    };

    if (action === 'tg-start') {
      const { api_id, api_hash, phone, channel_id } = req.body || {};
      if (!api_id || !api_hash || !phone) {
        return json(res, 400, { error: 'API ID, API Hash and phone number are required.' });
      }
      if (channel_id && String(channel_id).trim()) {
        await setSetting('tg_channel_id', String(channel_id).trim().slice(0, 64));
      }
      let client;
      try {
        client = new TelegramClient(
          new StringSession(''),
          Number(api_id),
          String(api_hash),
          CLIENT_OPTS
        );
        await client.connect();
        const result = await client.invoke(new Api.auth.SendCode({
          phoneNumber: String(phone).trim(),
          apiId: Number(api_id),
          apiHash: String(api_hash),
          settings: new Api.CodeSettings({}),
        }));
        await setSetting('tg_temp_session',    client.session.save());
        await setSetting('tg_temp_phone_hash', result.phoneCodeHash);
        await setSetting('tg_temp_phone',      String(phone).trim());
        await setSetting('tg_temp_api_id',     String(api_id));
        await setSetting('tg_temp_api_hash',   String(api_hash));
        try { await client.disconnect(); } catch {}
        return json(res, 200, { ok: true });
      } catch (e) {
        try { if (client) await client.disconnect(); } catch {}
        return json(res, 500, { error: e.message || 'Could not send code.' });
      }
    }

    if (action === 'tg-verify') {
      const { code } = req.body || {};
      if (!code) return json(res, 400, { error: 'Verification code is required.' });

      const tempSession = await getSetting('tg_temp_session', '');
      const phoneHash   = await getSetting('tg_temp_phone_hash', '');
      const phone       = await getSetting('tg_temp_phone', '');
      const apiIdStr    = await getSetting('tg_temp_api_id', '');
      const apiHashStr  = await getSetting('tg_temp_api_hash', '');

      if (!tempSession || !phoneHash || !apiIdStr || !apiHashStr) {
        return json(res, 400, { error: 'Session expired. Please start again.' });
      }

      let client;
      try {
        client = new TelegramClient(
          new StringSession(tempSession),
          Number(apiIdStr),
          String(apiHashStr),
          CLIENT_OPTS
        );
        await client.connect();

        const result = await client.invoke(new Api.auth.SignIn({
          phoneNumber: phone,
          phoneCodeHash: phoneHash,
          phoneCode: String(code).trim(),
        }));

        if (result instanceof Api.auth.AuthorizationSignUpRequired) {
          try { await client.disconnect(); } catch {}
          return json(res, 400, { error: 'This phone number is not registered on Telegram.' });
        }

        await setSetting('tg_session',  client.session.save());
        await setSetting('tg_api_id',   apiIdStr);
        await setSetting('tg_api_hash', apiHashStr);
        for (const k of TEMP_KEYS) await setSetting(k, '');

        try { await client.disconnect(); } catch {}
        invalidateConfigCache();
        return json(res, 200, { ok: true, needs_2fa: false });
      } catch (e) {
        const msg = String(e.message || e);
        if (msg.includes('SESSION_PASSWORD_NEEDED') || msg.includes('SESSION_PASSWORD')) {
          try { await setSetting('tg_temp_session', client.session.save()); } catch {}
          try { await client.disconnect(); } catch {}
          return json(res, 200, { ok: true, needs_2fa: true });
        }
        try { if (client) await client.disconnect(); } catch {}
        return json(res, 500, { error: msg || 'Verification failed.' });
      }
    }

    if (action === 'tg-password') {
      const { password } = req.body || {};
      if (!password) return json(res, 400, { error: '2FA password is required.' });

      const tempSession = await getSetting('tg_temp_session', '');
      const apiIdStr    = await getSetting('tg_temp_api_id', '');
      const apiHashStr  = await getSetting('tg_temp_api_hash', '');

      if (!tempSession || !apiIdStr || !apiHashStr) {
        return json(res, 400, { error: 'Session expired. Please start again.' });
      }

      let client;
      try {
        client = new TelegramClient(
          new StringSession(tempSession),
          Number(apiIdStr),
          String(apiHashStr),
          CLIENT_OPTS
        );
        await client.connect();

        const passwordSrpResult = await client.invoke(new Api.account.GetPassword());
        const passwordSrpCheck = await computeCheck(passwordSrpResult, String(password));
        await client.invoke(new Api.auth.CheckPassword({ password: passwordSrpCheck }));

        await setSetting('tg_session',  client.session.save());
        await setSetting('tg_api_id',   apiIdStr);
        await setSetting('tg_api_hash', apiHashStr);
        for (const k of TEMP_KEYS) await setSetting(k, '');

        try { await client.disconnect(); } catch {}
        invalidateConfigCache();
        return json(res, 200, { ok: true });
      } catch (e) {
        const msg = String(e.message || e);
        try { if (client) await client.disconnect(); } catch {}
        return json(res, 500, { error: msg || 'Password verification failed.' });
      }
    }

    if (action === 'tg-cancel') {
      for (const k of TEMP_KEYS) await setSetting(k, '');
      return json(res, 200, { ok: true });
    }

    if (action === 'tg-clear') {
      await setSetting('tg_session', '');
      await setSetting('tg_api_id', '');
      await setSetting('tg_api_hash', '');
      for (const k of TEMP_KEYS) await setSetting(k, '');
      invalidateConfigCache();
      return json(res, 200, { ok: true });
    }
  }

  if (req.method === 'GET') {
    const q = await supabaseQuery('app_settings?select=key,value');
    const raw = {};
    (q.data || []).forEach(r => {
      if (TEMP_KEYS.includes(r.key)) return;
      raw[r.key] = r.value;
    });
    return json(res, 200, { settings: raw, role: payload.role });
  }

  if (req.method === 'POST') {
    if (payload.role !== 'super') return json(res, 403, { error: 'Super admin only.' });

    const body = req.body || {};

    if (body.fee != null) {
      const n = parseFloat(body.fee);
      if (isNaN(n) || n <= 0) return json(res, 400, { error: 'Invalid fee amount.' });
      await setSetting('fee', String(Math.round(n)));
    }
    if (body.account_telebirr != null) await setSetting('account_telebirr', String(body.account_telebirr).slice(0, 32));
    if (body.account_cbe      != null) await setSetting('account_cbe',      String(body.account_cbe).slice(0, 32));
    if (body.account_mpesa    != null) await setSetting('account_mpesa',    String(body.account_mpesa).slice(0, 32));
    if (body.contact_username != null) await setSetting('contact_username', String(body.contact_username).slice(0, 64));
    if (body.contact_phone    != null) await setSetting('contact_phone',    String(body.contact_phone).slice(0, 32));

    let systemTouched = false;
    for (const key of SYSTEM_KEYS) {
      if (key in body) {
        const val = body[key];
        if (val === undefined || val === null) continue;
        const clean = String(val).trim().slice(0, 4096);
        await setSetting(key, clean);
        systemTouched = true;
      }
    }

    if (systemTouched) invalidateConfigCache();

    if (body.reset_rate_limits === true) {
      await supabaseDelete('rate_limits?id=neq.00000000-0000-0000-0000-000000000000');
    }

    return json(res, 200, { success: true, system_updated: systemTouched });
  }

  return json(res, 405, { error: 'Method not allowed' });
}

/* ============================================================
   6. ADMINS
   ============================================================ */
async function handleAdmins(req, res) {
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

      if (full_name != null) {
        patch.full_name = String(full_name).trim().slice(0, 64);
      }

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

    const q = await supabaseQuery(`admins?id=eq.${encodeURIComponent(id)}&select=role,username`);
    const row = q.data?.[0];
    if (!row) return json(res, 404, { error: 'Not found.' });
    if (row.role === 'super') return json(res, 400, { error: 'Cannot delete a super admin.' });

    const del = await supabaseDelete(`admins?id=eq.${encodeURIComponent(id)}`);
    if (!del.ok) return json(res, 500, { error: 'Could not delete.' });
    return json(res, 200, { success: true });
  }

  return json(res, 405, { error: 'Method not allowed' });
}

/* ============================================================
   7. VIDEOS
   ============================================================ */
async function handleVideos(req, res) {
  if (req.method === 'GET' && !req.headers.authorization) {
    const q = await supabaseQuery('videos?order=display_order.asc,created_at.asc&select=id,title,url,tag');
    return json(res, 200, { items: q.data || [] });
  }

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
}

/* ============================================================
   8. TESTIMONIALS
   ============================================================ */
async function handleTestimonials(req, res) {
  if (req.method === 'GET' && !req.headers.authorization) {
    const q = await supabaseQuery('testimonials?order=display_order.asc,created_at.asc&select=id,student_name,subject,text,stars');
    return json(res, 200, { items: q.data || [] });
  }

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
}

/* ============================================================
   9. CHATS
   ============================================================ */
async function handleChats(req, res) {
  const admin = requireAdmin(req);
  if (!admin) return json(res, 401, { error: 'Unauthorized' });

  const action = String(req.query.action || '');

  if (req.method === 'GET' && !action) {
    const sessionId = String(req.query.session_id || '').trim();

    if (sessionId) {
      const q = await supabaseQuery(
        `chat_messages?session_id=eq.${encodeURIComponent(sessionId)}` +
        `&order=created_at.asc&limit=500` +
        `&select=id,sender,sender_name,message_type,content,file_url,file_name,is_read,created_at`
      );
      await supabaseUpdate(
        `chat_messages?session_id=eq.${encodeURIComponent(sessionId)}&sender=eq.user&is_read=eq.false`,
        { is_read: true }
      );
      return json(res, 200, { items: q.data || [] });
    }

    const q = await supabaseQuery(
      `chat_messages?order=created_at.desc&limit=500` +
      `&select=session_id,registration_id,sender,content,message_type,is_read,created_at,file_name`
    );
    const rows = q.data || [];
    const seen = new Map();
    for (const r of rows) {
      if (!seen.has(r.session_id)) {
        seen.set(r.session_id, {
          session_id: r.session_id,
          registration_id: r.registration_id,
          last_message: r.message_type === 'text' ? (r.content || '') : `[${r.message_type}]`,
          last_sender: r.sender,
          last_at: r.created_at,
          unread: 0,
        });
      }
      if (r.sender === 'user' && !r.is_read) seen.get(r.session_id).unread++;
    }
    const sessions = [...seen.values()].sort((a,b) => (b.last_at||'').localeCompare(a.last_at||''));
    return json(res, 200, { sessions });
  }

  if (req.method === 'GET' && action === 'unread-count') {
    const q = await supabaseQuery(
      `chat_messages?sender=eq.user&is_read=eq.false&select=session_id`
    );
    const rows = q.data || [];
    const sessions = new Set(rows.map(r => r.session_id));
    return json(res, 200, { count: rows.length, sessions: sessions.size });
  }

  if (req.method === 'POST') {
    const body = req.body || {};
    const sessionId = String(body.session_id || '').trim();
    if (!sessionId) return json(res, 400, { error: 'session_id required.' });

    const type = ['text','image','pdf','voice'].includes(body.message_type) ? body.message_type : 'text';
    const content = body.content ? String(body.content).slice(0, 4000) : null;

    let fileUrl = null, fileName = null, fileSize = null;

    if (type !== 'text') {
      if (!body.file_base64) return json(res, 400, { error: 'Missing file data.' });
      fileName = body.file_name ? String(body.file_name).slice(0, 100) : (type + '.bin');
      const up = await uploadChatMedia('admin-' + sessionId, body.file_base64, body.mime_type || 'application/octet-stream', fileName);
      if (!up.ok) return json(res, 500, { error: up.error || 'Upload failed.' });
      fileUrl = up.url;
      try { fileSize = Buffer.from(String(body.file_base64).replace(/^data:[^,]+,/, ''), 'base64').length; } catch {}
    } else if (!content) {
      return json(res, 400, { error: 'Empty message.' });
    }

    const ins = await supabaseInsert('chat_messages', {
      session_id: sessionId,
      sender: 'admin',
      sender_name: admin.full_name || admin.username,
      message_type: type,
      content,
      file_url: fileUrl,
      file_name: fileName,
      file_size: fileSize,
      is_read: true,
    });
    if (!ins.ok) return json(res, 500, { error: 'Could not save reply.' });
    return json(res, 200, { success: true, item: ins.data?.[0] });
  }

  return json(res, 405, { error: 'Method not allowed' });
}

/* ============================================================
   10. STATS / FINANCE
   ============================================================ */
async function handleStats(req, res) {
  if (req.method !== 'GET') return json(res, 405, { error: 'Method not allowed' });
  const payload = requireAdmin(req);
  if (!payload) return json(res, 401, { error: 'Unauthorized' });

  const q = await supabaseQuery(
    'registrations?select=id,status,amount,created_at,approved_at,payment_method,semester,stream'
  );
  const rows = q.data || [];

  const now = new Date();
  const startOfDay   = new Date(now.getFullYear(), now.getMonth(), now.getDate()).getTime();
  const startOfWeek  = now.getTime() - 7 * 86400000;
  const startOfMonth = new Date(now.getFullYear(), now.getMonth(), 1).getTime();

  let totalUsers = 0, totalRevenue = 0;
  let todayUsers = 0, todayRevenue = 0;
  let weekUsers = 0, weekRevenue = 0;
  let monthUsers = 0, monthRevenue = 0;
  let pending = 0, approved = 0, rejected = 0, autoApproved = 0;
  const byMethod = {};
  const bySemester = {};

  for (const r of rows) {
    const amt = parseFloat(r.amount) || 0;
    const createdMs = r.created_at ? new Date(r.created_at).getTime() : 0;

    if (r.status === 'approved') {
      approved++;
      totalUsers++;
      totalRevenue += amt;

      if (createdMs >= startOfDay)   { todayUsers++; todayRevenue += amt; }
      if (createdMs >= startOfWeek)  { weekUsers++;  weekRevenue  += amt; }
      if (createdMs >= startOfMonth) { monthUsers++; monthRevenue += amt; }

      const m = r.payment_method || 'Unknown';
      byMethod[m] = byMethod[m] || { count: 0, revenue: 0 };
      byMethod[m].count++;
      byMethod[m].revenue += amt;

      const s = r.semester || 'Unknown';
      bySemester[s] = (bySemester[s] || 0) + 1;
    } else if (r.status === 'pending') {
      pending++;
    } else if (r.status === 'rejected') {
      rejected++;
    }
  }

  return json(res, 200, {
    totalRecords: rows.length,
    totalUsers, totalRevenue,
    todayUsers, todayRevenue,
    weekUsers, weekRevenue,
    monthUsers, monthRevenue,
    pending, approved, rejected,
    byMethod,
    bySemester,
    generated_at: new Date().toISOString(),
  });
}
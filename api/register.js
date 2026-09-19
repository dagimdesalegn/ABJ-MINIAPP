const {
  supabaseQuery, supabaseInsert, supabaseDelete, verifyPayment, createTelegramInvite,
  checkRateLimit, validateRegistration,
  getClientIp, getFee, json,
} = require('./_lib');

module.exports = async (req, res) => {
  if (req.method !== 'POST') return json(res, 405, { error: 'Method not allowed' });

  const ip = getClientIp(req);
  // Raised from 5 → 20/hr to accommodate dorm NAT
  const allowed = await checkRateLimit(ip, 20);
  if (!allowed) return json(res, 429, { error: 'Too many attempts from this network. Please try again in an hour.' });

  const body = req.body || {};
  const validationError = validateRegistration(body);
  if (validationError) return json(res, 400, { error: validationError });

  const {
    full_name, id_number, semester, stream, gender,
    payment_method, transaction_ref, transaction_suffix,
  } = body;

  const ref = String(transaction_ref).trim();
  const suffix = transaction_suffix ? String(transaction_suffix).trim() : null;
  const rawId = id_number.trim().toUpperCase().replace(/\s+/g, '');
  const public_id = rawId.replace(/\//g, '-');

  /* 1. Check if this UNIVERSITY ID already registered */
  const existingUni = await supabaseQuery(
    `registrations?public_id=eq.${encodeURIComponent(public_id)}&select=public_id,status`
  );
  if (existingUni.ok && existingUni.data && existingUni.data.length > 0) {
    const prev = existingUni.data[0];
    if (prev.status === 'pending' || prev.status === 'approved') {
      return json(res, 409, {
        error: 'This Student ID is already registered. Use "Check My Status" to see your registration.',
        code: 'already_registered',
        public_id: prev.public_id,
      });
    }
    // rejected → allow re-registration: remove old record first
    if (prev.status === 'rejected') {
      await supabaseDelete(`registrations?public_id=eq.${encodeURIComponent(prev.public_id)}`);
    }
  }

  /* 2. Reference uniqueness */
  const existingRef = await supabaseQuery(
    `registrations?transaction_ref=eq.${encodeURIComponent(ref)}&select=public_id`
  );
  if (existingRef.ok && existingRef.data && existingRef.data.length > 0) {
    return json(res, 409, { error: 'This transaction reference has already been used.' });
  }

  /* 3. Verify with Verify.ET */
  const verify = await verifyPayment(ref, suffix);
  const result = verify.result;

  const baseRecord = {
    public_id,
    full_name: full_name.trim().split(/\s+/)
      .map(w => w.charAt(0).toUpperCase() + w.slice(1).toLowerCase()).join(' '),
    id_number: rawId,
    semester, stream, gender,
    payment_method,
    transaction_ref: ref,
    transaction_suffix: suffix,
    receiver_account: verify.receiver || null,
    client_ip: ip,
    verify_error: verify.message || null,
    verify_response: verify,
  };

  /* ---------- CASE A — HARD FAILURES ---------- */
  if (result === 'failed' || result === 'mismatch' || result === 'duplicate' || result === 'invalid') {
    const ins = await supabaseInsert('registrations', {
      ...baseRecord,
      amount: 0,
      status: 'rejected',
      verification_status: 'auto_failed',
      auto_approved: false,
      rejection_reason: verify.message || 'Automated payment verification failed.',
    });
    // If insert failed due to duplicate ref (race condition), report cleanly
    if (!ins.ok && ins.status === 409) {
      return json(res, 409, { error: 'This transaction reference has already been used.' });
    }
    return json(res, 400, {
      error: verify.message || 'Payment could not be verified.',
      code: result,
    });
  }

  /* ---------- CASE B — SUCCESS: auto-approve ---------- */
  if (result === 'success') {
    const expected = await getFee();
    const received = parseFloat(verify.amount);

    if (Math.abs(received - expected) > 0.01) {
      const diff = Math.abs(received - expected);
      const ins = await supabaseInsert('registrations', {
        ...baseRecord,
        amount: received,
        status: 'rejected',
        verification_status: 'auto_failed',
        auto_approved: false,
        rejection_reason: `Payment amount does not match. Received ETB ${received.toLocaleString()}, required exactly ETB ${expected.toLocaleString()} (${received < expected ? 'short by' : 'over by'} ETB ${diff.toLocaleString()}).`,
      });
      if (!ins.ok && ins.status === 409) {
        return json(res, 409, { error: 'This transaction reference has already been used.' });
      }
      return json(res, 400, {
        error: `Payment amount does not match. Received ETB ${received.toLocaleString()}, required exactly ETB ${expected.toLocaleString()}.`,
        code: 'amount_mismatch',
      });
    }

    /* Try to auto-create invite. This is now mutex-protected, so concurrent registrations queue. */
    let invite = null, inviteErr = null;
    try {
      invite = await createTelegramInvite(`ABJ-${public_id}`);
    } catch (e) {
      inviteErr = e.message || 'Invite creation failed';
    }

    const now = new Date().toISOString();
    const record = {
      ...baseRecord,
      amount: received,
      status: invite ? 'approved' : 'pending',
      verification_status: invite ? 'auto_verified' : 'auto_verified_invite_pending',
      auto_approved: true,
      approved_at: invite ? now : null,
      invite_link: invite ? invite.invite_link : null,
      invite_link_created_at: invite ? now : null,
      approved_by: 'auto:verify.et',
      rejection_reason: inviteErr ? `Auto-approved but invite failed: ${inviteErr}` : null,
    };

    const insert = await supabaseInsert('registrations', record);
    if (!insert.ok) {
      if (insert.status === 409) {
        return json(res, 409, { error: 'This transaction reference has already been used.' });
      }
      return json(res, 500, { error: 'Could not save your registration. Please try again.' });
    }

    return json(res, 200, {
      success: true,
      public_id,
      id_number: rawId,
      status: record.status,
      auto_approved: true,
      invite_link: invite ? invite.invite_link : null,
      message: invite
        ? 'Verified automatically. Welcome to ABJ!'
        : 'Payment verified. Invite link will be ready shortly — check status in a moment.',
    });
  }

  /* ---------- CASE C — PENDING / SERVICE ERROR ---------- */
  const needsScreenshot = ['pending', 'service_error', 'not_found'].includes(result);

  const ins = await supabaseInsert('registrations', {
    ...baseRecord,
    amount: 0,
    status: 'pending',
    verification_status: needsScreenshot ? 'needs_manual' : 'auto_pending',
    auto_approved: false,
  });

  if (!ins.ok && ins.status === 409) {
    return json(res, 409, { error: 'This transaction reference has already been used.' });
  }

  return json(res, 200, {
    success: true,
    public_id,
    id_number: rawId,
    status: 'pending',
    needs_screenshot: needsScreenshot,
    verify_message: verify.message || null,
    message: needsScreenshot
      ? 'Automated verification could not confirm your payment. Please upload a screenshot.'
      : 'Registration received. Awaiting manual review.',
  });
};

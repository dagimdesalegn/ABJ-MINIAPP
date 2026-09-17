const {
  supabaseQuery, supabaseInsert, verifyPayment,
  checkRateLimit, validateRegistration, randomPublicId,
  getClientIp, getFee, json,
} = require('./_lib');

module.exports = async (req, res) => {
  if (req.method !== 'POST') return json(res, 405, { error: 'Method not allowed' });

  const ip = getClientIp(req);
  const allowed = await checkRateLimit(ip, 5);
  if (!allowed) return json(res, 429, { error: 'Too many attempts. Please try again later.' });

  const body = req.body || {};
  const validationError = validateRegistration(body);
  if (validationError) return json(res, 400, { error: validationError });

  const {
    full_name, id_number, semester, stream, gender,
    payment_method, transaction_ref, transaction_suffix,
  } = body;

  const ref = String(transaction_ref).trim();
  const suffix = transaction_suffix ? String(transaction_suffix).trim() : null;

  // 1. Reference uniqueness check
  const existing = await supabaseQuery(
    `registrations?transaction_ref=eq.${encodeURIComponent(ref)}&select=public_id`
  );
  if (existing.ok && existing.data && existing.data.length > 0) {
    return json(res, 409, { error: 'This transaction reference has already been used.' });
  }

  // 2. Server-side verification with Verify.ET
  const verify = await verifyPayment(ref, suffix);
  if (verify.result !== 'success') {
    return json(res, 400, {
      error: verify.message || 'Payment could not be verified.',
      code: verify.result,
    });
  }

  // 3. Amount must match the current DB-driven fee exactly
  const expected = await getFee();
  const received = parseFloat(verify.amount);
  if (Math.abs(received - expected) > 0.01) {
    const diff = Math.abs(received - expected);
    return json(res, 400, {
      error: `Payment amount does not match. Received ETB ${received.toLocaleString()}, required exactly ETB ${expected.toLocaleString()} (${received < expected ? 'short by' : 'over by'} ETB ${diff.toLocaleString()}).`,
    });
  }

  // 4. Insert
  const public_id = randomPublicId();
  const record = {
    public_id,
    full_name: full_name.trim().split(/\s+/)
      .map(w => w.charAt(0).toUpperCase() + w.slice(1).toLowerCase()).join(' '),
    id_number: id_number.trim().toUpperCase().replace(/\s+/g, ''),
    semester,
    stream,
    gender,
    payment_method,
    transaction_ref: ref,
    transaction_suffix: suffix,
    amount: received,
    receiver_account: verify.receiver || null,
    status: 'pending',
    client_ip: ip,
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
    status: 'pending',
    message: 'Registration received. Save your ID to check status.',
  });
};
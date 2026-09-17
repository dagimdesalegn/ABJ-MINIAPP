const { getPublicSettings, json } = require('./_lib');

module.exports = async (req, res) => {
  if (req.method !== 'GET') return json(res, 405, { error: 'Method not allowed' });
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
};
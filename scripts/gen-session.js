/*  Generate a Telegram user-account session string (no bot needed).
 *
 *  1.  set TELEGRAM_API_ID and TELEGRAM_API_HASH in your shell
 *  2.  node scripts/gen-session.js
 *  3.  Enter phone, the code Telegram sends, and 2FA password
 *  4.  Copy the printed string into Vercel as TELEGRAM_SESSION
 */
const readline = require('readline');
const { TelegramClient } = require('telegram');
const { StringSession } = require('telegram/sessions');

const apiId = Number(process.env.TELEGRAM_API_ID || 0);
const apiHash = process.env.TELEGRAM_API_HASH || '';

if (!apiId || !apiHash) {
  console.error('\n✖  Set TELEGRAM_API_ID and TELEGRAM_API_HASH first.\n');
  process.exit(1);
}

const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
const ask = (q) => new Promise(r => rl.question(q, r));

(async () => {
  const client = new TelegramClient(new StringSession(''), apiId, apiHash, { connectionRetries: 5 });

  await client.start({
    phoneNumber: async () => await ask('Phone number (e.g. +2519xxxxxxxx): '),
    password:    async () => await ask('2FA password (leave blank if none): '),
    phoneCode:   async () => await ask('Login code from Telegram: '),
    onError:     (err) => console.error('!', err.message),
  });

  console.log('\n========================================');
  console.log('  YOUR TELEGRAM_SESSION  (copy below)');
  console.log('========================================\n');
  console.log(client.session.save());
  console.log('\n========================================\n');
  console.log('Paste it into Vercel → Settings → Environment Variables → TELEGRAM_SESSION\n');

  rl.close();
  process.exit(0);
})();
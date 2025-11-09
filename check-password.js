// netlify/functions/check-password.js
const crypto = require('crypto');
const zxcvbn = require('zxcvbn');

function generateFromSeed(seed, length = 16, useSymbols = true) {
  const normalized = (seed || '').replace(/[^A-Za-z0-9]/g, '');
  const base = normalized.length ? normalized : '';
  const upper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  const lower = 'abcdefghijklmnopqrstuvwxyz';
  const digits = '0123456789';
  const symbols = '!@#$%^&*()-_=+[]{}<>?';
  const all = upper + lower + digits + (useSymbols ? symbols : '');

  const seedHash = crypto.createHash('sha256').update(seed || Math.random().toString()).digest('hex');
  let pw = '';
  for (let i = 0; i < Math.min(4, base.length); i++) {
    const c = base.charAt(i);
    const nib = parseInt(seedHash.charAt(i) || '0', 16);
    pw += (nib % 2 === 0) ? c.toLowerCase() : c.toUpperCase();
  }
  const needed = Math.max(length - pw.length, 0);
  const rnd = crypto.randomBytes(needed || 4);
  for (let i = 0; i < needed; i++) {
    const idx = rnd[i] % all.length;
    pw += all.charAt(idx);
  }
  if (!/[A-Z]/.test(pw)) pw = upper.charAt(rnd[0] % upper.length) + pw.slice(1);
  if (!/[a-z]/.test(pw)) pw = pw.slice(0,1) + lower.charAt(rnd[1 % rnd.length] % lower.length) + pw.slice(2);
  if (!/[0-9]/.test(pw)) pw = pw.slice(0,2) + digits.charAt(rnd[2 % rnd.length] % digits.length) + pw.slice(3);
  if (useSymbols && !/[!@#\$%\^&\*\(\)\-_=+\[\]\{\}<>\?]/.test(pw)) {
    pw = pw.slice(0,3) + symbols.charAt(rnd[3 % rnd.length] % symbols.length) + pw.slice(4);
  }
  let arr = pw.split('');
  for (let i = arr.length - 1; i > 0; i--) {
    const j = parseInt(seedHash.charAt(i % seedHash.length), 16) % (i + 1);
    [arr[i], arr[j]] = [arr[j], arr[i]];
  }
  return arr.join('').slice(0, length);
}

function sha1Hex(input) {
  return crypto.createHash('sha1').update(input, 'utf8').digest('hex').toUpperCase();
}

async function checkHIBPBySha1(sha1) {
  const prefix = sha1.slice(0,5);
  const suffix = sha1.slice(5);
  const resp = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
    headers: { 'User-Agent': 'Sweenah-Password-Checker' }
  });
  if (!resp || !resp.ok) throw new Error('HIBP error');
  const text = await resp.text();
  const hit = text.split('\n').find(line => line.split(':')[0].toUpperCase() === suffix);
  if (!hit) return { pwned:false, count:0, sha1_prefix: prefix };
  const count = parseInt(hit.split(':')[1], 10) || 0;
  return { pwned:true, count, sha1_prefix: prefix };
}

async function checkPwned(password) {
  const sha1 = sha1Hex(password);
  return await checkHIBPBySha1(sha1);
}

exports.handler = async (event) => {
  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, body: JSON.stringify({ error: 'method_not_allowed' }) };
  }
  try {
    const body = JSON.parse(event.body || '{}');
    const action = body.action || 'test';

    if (action === 'test') {
      const password = body.password || '';
      if (!password) return { statusCode: 400, body: JSON.stringify({ error: 'password_required' }) };
      const z = zxcvbn(password);
      const strength_score = z.score;
      const hibp = await checkPwned(password);
      return {
        statusCode: 200,
        headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
        body: JSON.stringify({
          pwned: hibp.pwned,
          pwned_count: hibp.count,
          strength_score,
          strength_feedback: z.feedback
        })
      };
    } else if (action === 'suggest') {
      const seed = (body.seed || '').toString();
      const length = parseInt(body.length, 10) || 16;
      const symbols = !!body.symbols;
      if (!seed || seed.trim().length === 0) {
        return { statusCode: 400, body: JSON.stringify({ error: 'seed_required' }) };
      }
      let attempts = 0;
      let suggestion = null;
      while (attempts < 8) {
        const cand = generateFromSeed(seed + Math.random().toString(), length, symbols);
        const hibp = await checkPwned(cand).catch(()=>({pwned:false}));
        if (!hibp.pwned) {
          suggestion = cand;
          break;
        }
        attempts++;
      }
      if (!suggestion) suggestion = generateFromSeed(Math.random().toString(), length, symbols);
      const z2 = zxcvbn(suggestion);
      return {
        statusCode: 200,
        headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
        body: JSON.stringify({
          suggested_password: suggestion,
          suggested_password_score: z2.score,
          strength_feedback: z2.feedback
        })
      };
    } else {
      return { statusCode: 400, body: JSON.stringify({ error: 'unknown_action' }) };
    }
  } catch (e) {
    return { statusCode: 500, body: JSON.stringify({ error: 'internal_error', details: e.message }) };
  }
};
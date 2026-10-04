// POST /api/login  {user, pass} → ログイン用クッキーを発行
// 5回続けて間違えると15分ログインできなくなります（記録は非公開のBlobに保存）
import { get, put, del } from '@vercel/blob';
import { verifyPassword, sessionCookie, sameOrigin, json } from '../lib/auth.js';

const MAX = 5, LOCK_MIN = 15;
const failPath = u => 'auth/fail-' + Buffer.from(u).toString('hex').slice(0, 64) + '.json';

async function readFail(u) {
  try {
    const r = await get(failPath(u), { access: 'private', useCache: false });
    if (!r || r.statusCode !== 200) return { n: 0, until: 0 };
    return JSON.parse(await new Response(r.stream).text());
  } catch (e) { return { n: 0, until: 0 }; }
}

export async function POST(req) {
  if (!sameOrigin(req)) return json({ error: '不正な送信元です' }, 403);
  let body;
  try { body = await req.json(); } catch (e) { return json({ error: '送信内容が読めません' }, 400); }
  const user = String(body.user || '').trim().toLowerCase().slice(0, 40);
  const pass = String(body.pass || '');
  if (!user || !pass) return json({ error: 'IDとパスワードを入れてください' }, 400);

  const f = await readFail(user);
  if (f.until > Date.now()) {
    const min = Math.ceil((f.until - Date.now()) / 60000);
    return json({ error: `パスワードを続けて間違えたため、あと${min}分ほどログインできません` }, 429);
  }
  if (!verifyPassword(user, pass)) {
    const n = (f.until && f.until <= Date.now() ? 0 : f.n) + 1;
    const rec = { n, until: n >= MAX ? Date.now() + LOCK_MIN * 60000 : 0 };
    try { await put(failPath(user), JSON.stringify(rec), { access: 'private', allowOverwrite: true, contentType: 'application/json', cacheControlMaxAge: 60 }); } catch (e) { }
    await new Promise(r => setTimeout(r, 400));
    return json({ error: n >= MAX ? `パスワードを${MAX}回間違えたため、${LOCK_MIN}分ほどログインできません` : 'IDかパスワードが違います' }, 401);
  }
  if (f.n) { try { await del(failPath(user)); } catch (e) { } }
  return json({ user }, 200, { 'Set-Cookie': sessionCookie(user) });
}

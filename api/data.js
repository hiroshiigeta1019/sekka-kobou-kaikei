// /api/data — 帳簿データの読み書き（ログイン必須・非公開のBlobに保存）
//   GET  ?etag=…            → {exists, etag, data} / 変更なしなら {unchanged:true}
//   PUT  {etag, data}       → {etag}。ほかの人が先に保存していたら 409（上書きしない）
// 1日1回、上書きする前のデータを backup/YYYY-MM-DD.json に控え、30日分残します。
import { get, put, head, copy, list, del, BlobPreconditionFailedError, BlobNotFoundError } from '@vercel/blob';
import { sessionUser, sameOrigin, json } from '../lib/auth.js';

const PATH = 'ledger/current.json';
const KEEP = 30;
const jstDay = d => new Date(new Date(d).getTime() + 9 * 3600e3).toISOString().slice(0, 10);

export async function GET(req) {
  const user = sessionUser(req);
  if (!user) return json({ error: 'ログインしてください' }, 401);
  const etag = new URL(req.url).searchParams.get('etag') || undefined;
  const r = await get(PATH, { access: 'private', useCache: false, ifNoneMatch: etag });
  if (!r) return json({ exists: false });
  if (r.statusCode === 304) return json({ unchanged: true, etag: r.blob.etag });
  const text = await new Response(r.stream).text();
  return new Response(`{"exists":true,"etag":${JSON.stringify(r.blob.etag)},"data":${text}}`, {
    headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'private, no-store' }
  });
}

async function dailyBackup() {
  let h;
  try { h = await head(PATH); } catch (e) { return; }          // まだデータがない／一時的に読めないときは控えを作らない
  const day = jstDay(h.uploadedAt);
  if (day === jstDay(Date.now())) return;                       // 今日はもう控えてある（今日の保存が上書きされるだけ）
  await copy(PATH, `backup/${day}.json`, { access: 'private', allowOverwrite: true, contentType: 'application/json' });
  const { blobs } = await list({ prefix: 'backup/' });
  const old = blobs.map(b => b.pathname).sort().slice(0, -KEEP);
  if (old.length) await del(old);
}

export async function PUT(req) {
  const user = sessionUser(req);
  if (!user) return json({ error: 'ログインしてください' }, 401);
  if (!sameOrigin(req)) return json({ error: '不正な送信元です' }, 403);
  let body;
  try { body = await req.json(); } catch (e) { return json({ error: 'データが読めません（大きすぎる可能性があります）' }, 400); }
  const d = body && body.data;
  if (!d || d.app !== 'aoiro-ledger' || typeof d.sheets !== 'object') return json({ error: '青色帳簿のデータではありません' }, 400);
  d.savedBy = user;
  d.savedAt = new Date().toISOString();
  if (body.etag) { try { await dailyBackup(); } catch (e) { console.error('backup failed', e); } }
  const opts = { access: 'private', contentType: 'application/json', addRandomSuffix: false, cacheControlMaxAge: 60 };
  if (body.etag) { opts.allowOverwrite = true; opts.ifMatch = body.etag; }
  try {
    const r = await put(PATH, JSON.stringify(d), opts);
    return json({ etag: r.etag, savedAt: d.savedAt, savedBy: user });
  } catch (e) {
    if (e instanceof BlobPreconditionFailedError || /already exists|precondition/i.test(String(e.message))) {
      return json({ conflict: true, error: 'ほかの人が先に保存しています' }, 409);
    }
    console.error(e);
    return json({ error: '保存できませんでした：' + (e.message || e) }, 500);
  }
}

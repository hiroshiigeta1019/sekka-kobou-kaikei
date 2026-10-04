// lib/auth.js — ログインまわり（パスワード照合・ログイン状態のクッキー）
// 環境変数:
//   APP_USERS       … "hiroshi:塩:ハッシュ,father:塩:ハッシュ"（setup.html で作る。パスワードそのものは置かない）
//   SESSION_SECRET  … ログイン状態に署名するための長い乱数（32文字以上）
import { pbkdf2Sync, timingSafeEqual, createHmac, randomBytes } from 'node:crypto';

const COOKIE = 'aoiro_s';
const DAYS = 30;
export const ITER = 210000;

export function users() {
  const m = {};
  String(process.env.APP_USERS || '').split(/[,;\s]+/).filter(Boolean).forEach(x => {
    const [u, s, h] = x.split(':');
    if (u && /^[0-9a-f]{32}$/i.test(s || '') && /^[0-9a-f]{64}$/i.test(h || '')) m[u] = { s, h };
  });
  return m;
}

export function verifyPassword(user, pass) {
  const u = users()[user];
  // ユーザーがいなくても同じだけ計算して、存在の有無を時間で悟られないようにする
  const salt = u ? u.s : randomBytes(16).toString('hex');
  const got = pbkdf2Sync(String(pass || ''), Buffer.from(salt, 'hex'), ITER, 32, 'sha256');
  if (!u) return false;
  return timingSafeEqual(got, Buffer.from(u.h, 'hex'));
}

function secret() {
  const s = process.env.SESSION_SECRET || '';
  if (s.length < 32) throw new Error('SESSION_SECRET が設定されていません（32文字以上）');
  return s;
}
const mac = p => createHmac('sha256', secret()).update(p).digest('base64url');

export function sessionCookie(user) {
  const p = Buffer.from(JSON.stringify({ u: user, exp: Date.now() + DAYS * 864e5 })).toString('base64url');
  return `${COOKIE}=${p}.${mac(p)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${DAYS * 86400}`;
}
export const clearCookie = () => `${COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`;

/** ログイン中のユーザー名（未ログインなら null） */
export function sessionUser(req) {
  const m = (req.headers.get('cookie') || '').match(/(?:^|;\s*)aoiro_s=([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)/);
  if (!m) return null;
  const a = Buffer.from(mac(m[1])), b = Buffer.from(m[2]);
  if (a.length !== b.length || !timingSafeEqual(a, b)) return null;
  try {
    const o = JSON.parse(Buffer.from(m[1], 'base64url').toString());
    if (!o.u || !(o.exp > Date.now()) || !users()[o.u]) return null;   // 期限切れ・削除されたユーザーは無効
    return o.u;
  } catch (e) { return null; }
}

/** 書き込み系は同じサイトからの送信だけ受け付ける */
export function sameOrigin(req) {
  const o = req.headers.get('origin');
  if (!o) return true;
  try { return new URL(o).host === new URL(req.url).host; } catch (e) { return false; }
}

export const json = (o, status = 200, headers = {}) =>
  new Response(JSON.stringify(o), { status, headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...headers } });

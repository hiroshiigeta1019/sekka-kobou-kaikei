// POST /api/logout → ログイン用クッキーを消す
import { clearCookie, json } from '../lib/auth.js';
export async function POST() { return json({ ok: true }, 200, { 'Set-Cookie': clearCookie() }); }

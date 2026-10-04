// GET /api/me → ログイン中なら {user}、未ログインなら 401
import { sessionUser, json } from '../lib/auth.js';
export async function GET(req) {
  const user = sessionUser(req);
  return user ? json({ user }) : json({ error: 'ログインしてください' }, 401);
}

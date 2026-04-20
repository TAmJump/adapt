/**
 * =========================================================
 *  Adapt API Worker v1.0
 *  Cloudflare Workers + D1 (adapt-db)
 *
 *  デプロイ手順:
 *    1. Cloudflare ダッシュボード → Workers & Pages → Create
 *    2. Worker 名: adapt-api
 *    3. D1 Binding: 変数名 DB, データベース adapt-db
 *    4. 環境変数 (Plaintext):
 *         ALLOWED_ORIGINS   = "https://tamjump.github.io,https://adapt.tamjump.com,http://localhost:5500"
 *         ONETOUCH_API_BASE = "https://onetouch-api.animalb001.workers.dev"
 *         MEDADAPT_API_BASE = "https://medadapt-api-v2.animalb001.workers.dev"
 *         ONETOUCH_APP_URL  = "https://tamjump.github.io/onetouch_app"
 *         MEDADAPT_APP_URL  = "https://medadapt.scsgo.co.jp"
 *    5. このファイルを Edit code で全貼り付け → Deploy
 * =========================================================
 */

// ---------- ユーティリティ ----------
const CORS_HEADERS = (origin, allowed) => {
  const ok = allowed.includes(origin) ? origin : allowed[0] || '*';
  return {
    'Access-Control-Allow-Origin': ok,
    'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type,Authorization',
    'Access-Control-Max-Age': '86400',
    'Vary': 'Origin'
  };
};

const json = (data, status, cors) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', ...cors }
  });

const sha256 = async (text) => {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
};

const randomId = (len = 32) => {
  const bytes = crypto.getRandomValues(new Uint8Array(len));
  return [...bytes].map(b => b.toString(16).padStart(2, '0')).join('').slice(0, len);
};

const nowISO = () => new Date().toISOString();
const plusSec = (s) => new Date(Date.now() + s * 1000).toISOString();

// 新規会社ID採番: ADP-000001 形式
const nextCompanyId = async (db) => {
  const row = await db.prepare(
    "SELECT company_id FROM master_companies WHERE company_id LIKE 'ADP-%' ORDER BY company_id DESC LIMIT 1"
  ).first();
  const n = row ? parseInt(row.company_id.replace('ADP-', ''), 10) + 1 : 1;
  return 'ADP-' + String(n).padStart(6, '0');
};

// 新規スタッフID採番
const nextStaffId = async (db) => {
  const row = await db.prepare(
    "SELECT staff_id FROM master_staff WHERE staff_id LIKE 'ADP-STF-%' ORDER BY staff_id DESC LIMIT 1"
  ).first();
  const n = row ? parseInt(row.staff_id.replace('ADP-STF-', ''), 10) + 1 : 1;
  return 'ADP-STF-' + String(n).padStart(6, '0');
};

// ---------- 認証 ----------
async function requireAuth(request, db) {
  const auth = request.headers.get('Authorization') || '';
  if (!auth.startsWith('Bearer ')) return { error: 'unauthorized', status: 401 };
  const token = auth.slice(7);
  const sess = await db.prepare(
    "SELECT s.token, s.staff_id, s.expires_at, u.login_id, u.name, u.role, u.master_company_id, u.status " +
    "FROM sessions s JOIN master_staff u ON s.staff_id = u.staff_id WHERE s.token = ?"
  ).bind(token).first();
  if (!sess) return { error: 'invalid_token', status: 401 };
  if (new Date(sess.expires_at) < new Date()) {
    await db.prepare("DELETE FROM sessions WHERE token = ?").bind(token).run();
    return { error: 'expired', status: 401 };
  }
  if (sess.status !== 'active') return { error: 'account_suspended', status: 403 };
  return { user: sess };
}

async function audit(db, type, staffId, loginId, details, request) {
  try {
    await db.prepare(
      "INSERT INTO audit_logs (type, staff_id, login_id, details, ip, user_agent) VALUES (?,?,?,?,?,?)"
    ).bind(
      type, staffId || null, loginId || null,
      details ? JSON.stringify(details) : null,
      request.headers.get('CF-Connecting-IP') || null,
      (request.headers.get('User-Agent') || '').slice(0, 200)
    ).run();
  } catch (e) { /* best effort */ }
}

// =========================================================
//  メインハンドラ
// =========================================================
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const allowed = (env.ALLOWED_ORIGINS || '*').split(',').map(s => s.trim());
    const cors = CORS_HEADERS(request.headers.get('Origin') || '', allowed);

    if (request.method === 'OPTIONS') return new Response(null, { headers: cors });

    const db = env.DB;
    const path = url.pathname;
    const method = request.method;

    try {
      // ----- ヘルスチェック -----
      if (path === '/' || path === '/api/health') {
        return json({ ok: true, service: 'adapt-api', ts: nowISO() }, 200, cors);
      }

      // ========================================
      //  認証系
      // ========================================

      // 新規会社登録＋初期管理者作成
      if (path === '/api/auth/register' && method === 'POST') {
        const b = await request.json();
        const { company_name, login_id, name, email, password, phone } = b || {};
        if (!company_name || !login_id || !name || !password) {
          return json({ error: 'missing_fields' }, 400, cors);
        }
        if (password.length < 8) return json({ error: 'password_too_short' }, 400, cors);
        if (!/^[a-zA-Z0-9_-]{3,40}$/.test(login_id)) {
          return json({ error: 'invalid_login_id', hint: '3-40文字の半角英数字 _-' }, 400, cors);
        }

        const exists = await db.prepare("SELECT 1 FROM master_staff WHERE login_id = ?").bind(login_id).first();
        if (exists) return json({ error: 'login_id_taken' }, 409, cors);

        const companyId = await nextCompanyId(db);
        const staffId = await nextStaffId(db);
        const hash = await sha256(password);

        await db.batch([
          db.prepare("INSERT INTO master_companies (company_id, name, email, phone) VALUES (?,?,?,?)")
            .bind(companyId, company_name, email || null, phone || null),
          db.prepare(
            "INSERT INTO master_staff (staff_id, master_company_id, login_id, name, email, password_hash, role) " +
            "VALUES (?,?,?,?,?,?, 'master_admin')"
          ).bind(staffId, companyId, login_id, name, email || null, hash)
        ]);

        await audit(db, 'register', staffId, login_id, { company_id: companyId }, request);
        return json({ ok: true, company_id: companyId, staff_id: staffId, login_id }, 200, cors);
      }

      // ログイン
      if (path === '/api/auth/login' && method === 'POST') {
        const { login_id, password } = (await request.json()) || {};
        if (!login_id || !password) return json({ error: 'missing_fields' }, 400, cors);

        const hash = await sha256(password);
        const user = await db.prepare(
          "SELECT * FROM master_staff WHERE login_id = ? AND password_hash = ?"
        ).bind(login_id, hash).first();

        if (!user) {
          await audit(db, 'login_failed', null, login_id, null, request);
          return json({ error: 'invalid_credentials' }, 401, cors);
        }
        if (user.status !== 'active') return json({ error: 'account_suspended' }, 403, cors);

        const token = randomId(48);
        const expiresAt = plusSec(60 * 60 * 24 * 30); // 30日
        await db.batch([
          db.prepare("INSERT INTO sessions (token, staff_id, expires_at) VALUES (?,?,?)")
            .bind(token, user.staff_id, expiresAt),
          db.prepare("UPDATE master_staff SET last_login_at = datetime('now') WHERE staff_id = ?")
            .bind(user.staff_id)
        ]);

        await audit(db, 'login', user.staff_id, user.login_id, null, request);
        return json({
          ok: true,
          token,
          expires_at: expiresAt,
          user: {
            staff_id: user.staff_id,
            login_id: user.login_id,
            name: user.name,
            email: user.email,
            role: user.role,
            master_company_id: user.master_company_id
          }
        }, 200, cors);
      }

      // ログアウト
      if (path === '/api/auth/logout' && method === 'POST') {
        const auth = request.headers.get('Authorization') || '';
        if (auth.startsWith('Bearer ')) {
          const t = auth.slice(7);
          const s = await db.prepare("SELECT staff_id FROM sessions WHERE token = ?").bind(t).first();
          await db.prepare("DELETE FROM sessions WHERE token = ?").bind(t).run();
          if (s) await audit(db, 'logout', s.staff_id, null, null, request);
        }
        return json({ ok: true }, 200, cors);
      }

      // 自分
      if (path === '/api/auth/me' && method === 'GET') {
        const r = await requireAuth(request, db);
        if (r.error) return json({ error: r.error }, r.status, cors);
        const company = await db.prepare("SELECT * FROM master_companies WHERE company_id = ?")
          .bind(r.user.master_company_id).first();
        return json({ user: r.user, company }, 200, cors);
      }

      // パスワード変更
      if (path === '/api/auth/change-password' && method === 'POST') {
        const r = await requireAuth(request, db);
        if (r.error) return json({ error: r.error }, r.status, cors);
        const { old_password, new_password } = (await request.json()) || {};
        if (!old_password || !new_password) return json({ error: 'missing_fields' }, 400, cors);
        if (new_password.length < 8) return json({ error: 'password_too_short' }, 400, cors);
        const oldHash = await sha256(old_password);
        const check = await db.prepare(
          "SELECT 1 FROM master_staff WHERE staff_id = ? AND password_hash = ?"
        ).bind(r.user.staff_id, oldHash).first();
        if (!check) return json({ error: 'wrong_password' }, 401, cors);
        const newHash = await sha256(new_password);
        await db.prepare(
          "UPDATE master_staff SET password_hash = ?, updated_at = datetime('now') WHERE staff_id = ?"
        ).bind(newHash, r.user.staff_id).run();
        await audit(db, 'password_change', r.user.staff_id, r.user.login_id, null, request);
        return json({ ok: true }, 200, cors);
      }

      // ========================================
      //  子アプリ連携
      // ========================================

      // 紐付け一覧
      if (path === '/api/apps/links' && method === 'GET') {
        const r = await requireAuth(request, db);
        if (r.error) return json({ error: r.error }, r.status, cors);
        const rs = await db.prepare(
          "SELECT * FROM app_links WHERE staff_id = ? AND status != 'revoked' ORDER BY linked_at DESC"
        ).bind(r.user.staff_id).all();
        return json({ links: rs.results || [] }, 200, cors);
      }

      // 既存アカウント紐付け（子API で実際に認証確認）
      if (path === '/api/apps/links' && method === 'POST') {
        const r = await requireAuth(request, db);
        if (r.error) return json({ error: r.error }, r.status, cors);
        const { app_name, child_login_id, child_password } = (await request.json()) || {};
        if (!app_name || !child_login_id || !child_password) {
          return json({ error: 'missing_fields' }, 400, cors);
        }
        if (!['onetouch', 'medadapt'].includes(app_name)) {
          return json({ error: 'invalid_app' }, 400, cors);
        }

        // 子API でログインを試行
        const apiBase = app_name === 'onetouch' ? env.ONETOUCH_API_BASE : env.MEDADAPT_API_BASE;
        const loginPath = app_name === 'onetouch' ? '/api/auth/login' : '/auth/login';
        let verified = false;
        let childCompany = null;
        let childRole = null;
        try {
          const resp = await fetch(apiBase + loginPath, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ login_id: child_login_id, password: child_password })
          });
          if (resp.ok) {
            const data = await resp.json().catch(() => ({}));
            verified = !!(data.token || data.user || data.ok || data.success);
            // レスポンス形状は子アプリごとに異なるため柔軟に拾う
            childCompany = data.user?.company_code || data.company_code || data.user?.org_id || null;
            childRole    = data.user?.role || data.role || null;
          }
        } catch (e) { /* network / CORS 等 */ }

        if (!verified) return json({ error: 'child_auth_failed' }, 401, cors);

        try {
          await db.prepare(
            "INSERT INTO app_links (staff_id, app_name, child_login_id, child_company_code, child_role, status) " +
            "VALUES (?,?,?,?,?, 'linked')"
          ).bind(r.user.staff_id, app_name, child_login_id, childCompany, childRole).run();
        } catch (e) {
          if (String(e.message || '').includes('UNIQUE')) {
            return json({ error: 'already_linked' }, 409, cors);
          }
          throw e;
        }
        await audit(db, 'link', r.user.staff_id, r.user.login_id,
          { app_name, child_login_id }, request);
        return json({ ok: true }, 200, cors);
      }

      // 紐付け解除
      const unlinkMatch = path.match(/^\/api\/apps\/links\/(\d+)$/);
      if (unlinkMatch && method === 'DELETE') {
        const r = await requireAuth(request, db);
        if (r.error) return json({ error: r.error }, r.status, cors);
        const id = Number(unlinkMatch[1]);
        const row = await db.prepare(
          "SELECT * FROM app_links WHERE id = ? AND staff_id = ?"
        ).bind(id, r.user.staff_id).first();
        if (!row) return json({ error: 'not_found' }, 404, cors);
        await db.prepare("UPDATE app_links SET status = 'revoked' WHERE id = ?").bind(id).run();
        await audit(db, 'unlink', r.user.staff_id, r.user.login_id,
          { app_name: row.app_name, child_login_id: row.child_login_id }, request);
        return json({ ok: true }, 200, cors);
      }

      // ========================================
      //  SSO
      // ========================================

      // 短命チケット発行（親側）
      if (path === '/api/apps/sso-ticket' && method === 'POST') {
        const r = await requireAuth(request, db);
        if (r.error) return json({ error: r.error }, r.status, cors);
        const { app_name } = (await request.json()) || {};
        if (!['onetouch', 'medadapt'].includes(app_name)) {
          return json({ error: 'invalid_app' }, 400, cors);
        }

        const link = await db.prepare(
          "SELECT * FROM app_links WHERE staff_id = ? AND app_name = ? AND status = 'linked' " +
          "ORDER BY linked_at DESC LIMIT 1"
        ).bind(r.user.staff_id, app_name).first();
        if (!link) return json({ error: 'not_linked' }, 404, cors);

        const ticket = randomId(48);
        const exp = plusSec(60); // 60秒
        await db.prepare(
          "INSERT INTO sso_tickets (ticket, staff_id, app_name, child_login_id, expires_at) VALUES (?,?,?,?,?)"
        ).bind(ticket, r.user.staff_id, app_name, link.child_login_id, exp).run();
        await db.prepare(
          "UPDATE app_links SET last_sso_at = datetime('now') WHERE id = ?"
        ).bind(link.id).run();

        const redirectBase = app_name === 'onetouch' ? env.ONETOUCH_APP_URL : env.MEDADAPT_APP_URL;
        const landingPath = app_name === 'onetouch' ? '/login.html' : '/app.html';
        const redirect_url = `${redirectBase}${landingPath}?sso_ticket=${ticket}&from=adapt`;

        await audit(db, 'sso_issue', r.user.staff_id, r.user.login_id,
          { app_name, child_login_id: link.child_login_id }, request);
        return json({ ok: true, ticket, redirect_url, expires_at: exp }, 200, cors);
      }

      // チケット検証（子アプリの Worker から呼ぶ）
      if (path === '/api/apps/sso-verify' && method === 'GET') {
        const ticket = url.searchParams.get('ticket');
        if (!ticket) return json({ error: 'missing_ticket' }, 400, cors);
        const row = await db.prepare("SELECT * FROM sso_tickets WHERE ticket = ?").bind(ticket).first();
        if (!row) return json({ error: 'invalid_ticket' }, 404, cors);
        if (row.consumed_at) return json({ error: 'already_used' }, 410, cors);
        if (new Date(row.expires_at) < new Date()) return json({ error: 'expired' }, 410, cors);

        await db.prepare(
          "UPDATE sso_tickets SET consumed_at = datetime('now') WHERE ticket = ?"
        ).bind(ticket).run();

        // 親スタッフ情報も返す
        const staff = await db.prepare(
          "SELECT staff_id, login_id, name, email FROM master_staff WHERE staff_id = ?"
        ).bind(row.staff_id).first();

        await audit(db, 'sso_consumed', row.staff_id, null,
          { app_name: row.app_name, child_login_id: row.child_login_id }, request);
        return json({
          ok: true,
          app_name: row.app_name,
          child_login_id: row.child_login_id,
          master_staff: staff
        }, 200, cors);
      }

      // ========================================
      return json({ error: 'not_found', path, method }, 404, cors);
    } catch (e) {
      return json({ error: 'server_error', message: String(e.message || e) }, 500, cors);
    }
  }
};

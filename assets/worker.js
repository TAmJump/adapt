/**
 * =========================================================
 *  Adapt API Worker v2.0  (email-verified register + SES)
 *  Cloudflare Workers + D1 (adapt-db)
 *
 *  追加で必要な環境変数（Plaintext / Secret）:
 *    AWS_ACCESS_KEY_ID       = 既存MedAdapt/OneTouchAdaptと同じでOK (Plaintext)
 *    AWS_SECRET_ACCESS_KEY   = 同上 (Secret推奨)
 *    AWS_REGION              = ap-northeast-1
 *    FROM_EMAIL              = no-reply@tamjump.com
 *    BASE_URL                = https://tamjump.github.io/adapt
 *  ※ カスタムドメイン導入後は BASE_URL を差し替え
 * =========================================================
 */

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

// =========================================================
//  AWS SigV4 + SES SendEmail
// =========================================================
async function hexSha256(str) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
}
async function hmacBuf(key, msg) {
  const keyBuf = typeof key === 'string' ? new TextEncoder().encode(key) : key;
  const k = await crypto.subtle.importKey('raw', keyBuf, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', k, new TextEncoder().encode(msg));
  return new Uint8Array(sig);
}
async function hmacHex(key, msg) {
  const sig = await hmacBuf(key, msg);
  return [...sig].map(b => b.toString(16).padStart(2, '0')).join('');
}

async function sendEmail(env, { to, subject, html, text }) {
  const region = env.AWS_REGION || 'ap-northeast-1';
  const host = `email.${region}.amazonaws.com`;
  const url  = `https://${host}/`;

  const params = new URLSearchParams();
  params.set('Action', 'SendEmail');
  params.set('Source', env.FROM_EMAIL);
  params.set('Destination.ToAddresses.member.1', to);
  params.set('Message.Subject.Data', subject);
  params.set('Message.Subject.Charset', 'UTF-8');
  if (html) {
    params.set('Message.Body.Html.Data', html);
    params.set('Message.Body.Html.Charset', 'UTF-8');
  }
  if (text) {
    params.set('Message.Body.Text.Data', text);
    params.set('Message.Body.Text.Charset', 'UTF-8');
  }
  const body = params.toString();

  const d = new Date();
  const amzDate = d.toISOString().replace(/[:\-]/g, '').replace(/\.\d{3}/, '');
  const dateStamp = amzDate.slice(0, 8);

  const payloadHash = await hexSha256(body);
  const canonicalHeaders =
    `host:${host}\n` +
    `x-amz-date:${amzDate}\n`;
  const signedHeaders = 'host;x-amz-date';
  const canonicalRequest = [
    'POST', '/', '',
    canonicalHeaders,
    signedHeaders,
    payloadHash
  ].join('\n');

  const credentialScope = `${dateStamp}/${region}/ses/aws4_request`;
  const stringToSign = [
    'AWS4-HMAC-SHA256',
    amzDate,
    credentialScope,
    await hexSha256(canonicalRequest)
  ].join('\n');

  const kDate    = await hmacBuf('AWS4' + env.AWS_SECRET_ACCESS_KEY, dateStamp);
  const kRegion  = await hmacBuf(kDate, region);
  const kService = await hmacBuf(kRegion, 'ses');
  const kSigning = await hmacBuf(kService, 'aws4_request');
  const signature = await hmacHex(kSigning, stringToSign);

  const authHeader = `AWS4-HMAC-SHA256 Credential=${env.AWS_ACCESS_KEY_ID}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;

  const resp = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'X-Amz-Date': amzDate,
      'Authorization': authHeader
    },
    body
  });
  if (!resp.ok) {
    const t = await resp.text();
    throw new Error(`SES ${resp.status}: ${t.slice(0, 300)}`);
  }
  return await resp.text();
}

function verifyEmailHtml({ name, verifyUrl, companyName }) {
  const esc = (s) => String(s || '').replace(/[<>&"']/g, c => ({'<':'&lt;','>':'&gt;','&':'&amp;','"':'&quot;',"'":'&#39;'}[c]));
  return `<!DOCTYPE html>
<html lang="ja"><head><meta charset="UTF-8"></head>
<body style="font-family: 'Helvetica Neue', 'Hiragino Kaku Gothic ProN', 'Noto Sans JP', sans-serif; background:#ffffff; color:#0a0e1a; margin:0; padding:0;">
  <table width="100%" cellpadding="0" cellspacing="0" style="max-width:560px; margin:0 auto; padding:32px 20px;">
    <tr><td>
      <h1 style="font-size:22px; font-weight:900; margin:0 0 6px 0; letter-spacing:-0.01em;">Adapt</h1>
      <p style="font-family:monospace; font-size:11px; color:#5a6070; letter-spacing:0.12em; text-transform:uppercase; margin:0 0 28px 0;">Email Verification</p>
      <h2 style="font-size:18px; font-weight:700; margin:0 0 14px 0;">メールアドレスを確認してください</h2>
      <p style="font-size:14px; line-height:1.8; color:#2a2f3d; margin:0 0 20px 0;">
        ${esc(name)} 様<br><br>
        Adaptへのご登録ありがとうございます。<br>
        以下のボタンを押して、メールアドレスの確認と登録完了をお願いします。
      </p>
      <table cellpadding="0" cellspacing="0" style="margin:8px 0 28px 0;"><tr>
        <td style="background:#c4432b; border-radius:2px;">
          <a href="${verifyUrl}" style="display:inline-block; padding:13px 28px; color:#ffffff; font-weight:700; font-size:13px; letter-spacing:0.06em; text-decoration:none;">登録を完了する</a>
        </td>
      </tr></table>
      <p style="font-size:11px; color:#5a6070; line-height:1.8; margin:0 0 16px 0;">
        ボタンが押せない場合は以下のURLをブラウザに貼り付けてください：<br>
        <a href="${verifyUrl}" style="color:#c4432b; word-break:break-all;">${esc(verifyUrl)}</a>
      </p>
      <hr style="border:0; border-top:1px solid #e3e3e0; margin:24px 0;">
      <table style="font-size:11px; color:#5a6070; line-height:1.8;">
        <tr><td style="padding-right:16px;">登録会社</td><td style="color:#0a0e1a;">${esc(companyName)}</td></tr>
        <tr><td style="padding-right:16px;">有効期限</td><td>発行から24時間</td></tr>
      </table>
      <p style="font-size:11px; color:#9aa0ac; margin:18px 0 0 0;">
        心当たりがない場合、このメールは無視してください。<br>
        このアドレスには返信できません。
      </p>
    </td></tr>
  </table>
</body></html>`;
}

// =========================================================
//  認証系ヘルパー
// =========================================================
async function requireAuth(request, db) {
  const auth = request.headers.get('Authorization') || '';
  if (!auth.startsWith('Bearer ')) return { error: 'unauthorized', status: 401 };
  const token = auth.slice(7);
  const sess = await db.prepare(
    "SELECT s.token, s.staff_id, s.expires_at, u.login_id, u.name, u.email, u.role, u.master_company_id, u.status " +
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
  } catch (e) {}
}

const nextCompanyId = async (db) => {
  const row = await db.prepare(
    "SELECT company_id FROM master_companies WHERE company_id LIKE 'ADP-%' ORDER BY company_id DESC LIMIT 1"
  ).first();
  const n = row ? parseInt(row.company_id.replace('ADP-', ''), 10) + 1 : 1;
  return 'ADP-' + String(n).padStart(6, '0');
};
const nextStaffId = async (db) => {
  const row = await db.prepare(
    "SELECT staff_id FROM master_staff WHERE staff_id LIKE 'ADP-STF-%' ORDER BY staff_id DESC LIMIT 1"
  ).first();
  const n = row ? parseInt(row.staff_id.replace('ADP-STF-', ''), 10) + 1 : 1;
  return 'ADP-STF-' + String(n).padStart(6, '0');
};

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
      if (path === '/' || path === '/api/health') {
        return json({ ok: true, service: 'adapt-api', ts: nowISO() }, 200, cors);
      }

      // =============== Auth ===============

      // 新規登録（メール確認フロー）
      if (path === '/api/auth/register' && method === 'POST') {
        const b = await request.json();
        const { company_name, login_id, name, email, password, phone } = b || {};
        if (!company_name || !login_id || !name || !email || !password) {
          return json({ error: 'missing_fields', fields: ['company_name','login_id','name','email','password'].filter(k => !b?.[k]) }, 400, cors);
        }
        if (password.length < 8) return json({ error: 'password_too_short' }, 400, cors);
        if (!/^[a-zA-Z0-9_-]{3,40}$/.test(login_id)) {
          return json({ error: 'invalid_login_id' }, 400, cors);
        }
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
          return json({ error: 'invalid_email' }, 400, cors);
        }

        const exists = await db.prepare("SELECT 1 FROM master_staff WHERE login_id = ?").bind(login_id).first();
        if (exists) return json({ error: 'login_id_taken' }, 409, cors);

        // 同じメールで pending 中のやつがあれば置き換え
        await db.prepare("DELETE FROM email_verifications WHERE email = ? AND used_at IS NULL").bind(email).run();

        const token = randomId(48);
        const passwordHash = await sha256(password);
        const pending = {
          company_name, login_id, name, email,
          phone: phone || null, password_hash: passwordHash
        };
        const expiresAt = plusSec(60 * 60 * 24); // 24時間

        await db.prepare(
          "INSERT INTO email_verifications (token, email, pending_data, expires_at) VALUES (?,?,?,?)"
        ).bind(token, email, JSON.stringify(pending), expiresAt).run();

        const baseUrl = (env.BASE_URL || 'https://tamjump.github.io/adapt').replace(/\/+$/, '');
        const verifyUrl = `${baseUrl}/verify.html?token=${token}`;

        try {
          await sendEmail(env, {
            to: email,
            subject: '【Adapt】メールアドレス確認のお願い',
            html: verifyEmailHtml({ name, verifyUrl, companyName: company_name }),
            text:
`${name} 様

Adaptへのご登録ありがとうございます。
以下のURLを開いて、メールアドレスの確認と登録完了をお願いします。

${verifyUrl}

有効期限: 24時間
登録会社: ${company_name}

心当たりがない場合、このメールは無視してください。`
          });
        } catch (e) {
          // 送信失敗時は pending レコード削除
          await db.prepare("DELETE FROM email_verifications WHERE token = ?").bind(token).run();
          await audit(db, 'register_mail_fail', null, login_id, { email, error: String(e.message).slice(0,200) }, request);
          return json({ error: 'email_send_failed', detail: String(e.message).slice(0, 200) }, 502, cors);
        }

        await audit(db, 'register_pending', null, login_id, { email }, request);
        return json({ ok: true, pending_verification: true, email }, 200, cors);
      }

      // 確認トークン情報取得（verify.html 表示用）
      if (path === '/api/auth/verify-info' && method === 'GET') {
        const token = url.searchParams.get('token');
        if (!token) return json({ error: 'missing_token' }, 400, cors);
        const row = await db.prepare("SELECT * FROM email_verifications WHERE token = ?").bind(token).first();
        if (!row) return json({ error: 'invalid_token' }, 404, cors);
        if (row.used_at) return json({ error: 'already_used' }, 410, cors);
        if (new Date(row.expires_at) < new Date()) return json({ error: 'expired' }, 410, cors);
        const p = JSON.parse(row.pending_data);
        return json({
          ok: true,
          email: row.email,
          company_name: p.company_name,
          login_id: p.login_id,
          name: p.name,
          expires_at: row.expires_at
        }, 200, cors);
      }

      // 確認実行（アカウント作成）
      if (path === '/api/auth/verify' && method === 'POST') {
        const { token } = (await request.json()) || {};
        if (!token) return json({ error: 'missing_token' }, 400, cors);
        const row = await db.prepare("SELECT * FROM email_verifications WHERE token = ?").bind(token).first();
        if (!row) return json({ error: 'invalid_token' }, 404, cors);
        if (row.used_at) return json({ error: 'already_used' }, 410, cors);
        if (new Date(row.expires_at) < new Date()) return json({ error: 'expired' }, 410, cors);

        const p = JSON.parse(row.pending_data);
        // 二重チェック: login_id が空いているか
        const existsLI = await db.prepare("SELECT 1 FROM master_staff WHERE login_id = ?").bind(p.login_id).first();
        if (existsLI) return json({ error: 'login_id_taken' }, 409, cors);

        const companyId = await nextCompanyId(db);
        const staffId = await nextStaffId(db);
        const sessionToken = randomId(48);
        const expiresAt = plusSec(60 * 60 * 24 * 30);

        await db.batch([
          db.prepare("INSERT INTO master_companies (company_id, name, email, phone) VALUES (?,?,?,?)")
            .bind(companyId, p.company_name, p.email || null, p.phone || null),
          db.prepare(
            "INSERT INTO master_staff (staff_id, master_company_id, login_id, name, email, password_hash, role, last_login_at) " +
            "VALUES (?,?,?,?,?,?, 'master_admin', datetime('now'))"
          ).bind(staffId, companyId, p.login_id, p.name, p.email, p.password_hash),
          db.prepare("INSERT INTO sessions (token, staff_id, expires_at) VALUES (?,?,?)")
            .bind(sessionToken, staffId, expiresAt),
          db.prepare("UPDATE email_verifications SET used_at = datetime('now') WHERE token = ?")
            .bind(token)
        ]);

        await audit(db, 'register_verified', staffId, p.login_id, { company_id: companyId }, request);
        return json({
          ok: true,
          token: sessionToken,
          expires_at: expiresAt,
          user: {
            staff_id: staffId, login_id: p.login_id, name: p.name, email: p.email,
            role: 'master_admin', master_company_id: companyId
          }
        }, 200, cors);
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
          // 未承認の登録中アドレス/loginがあるかチェック
          const pending = await db.prepare(
            "SELECT * FROM email_verifications WHERE used_at IS NULL AND expires_at > datetime('now')"
          ).all();
          let isPending = false;
          for (const r of (pending.results || [])) {
            try { if (JSON.parse(r.pending_data).login_id === login_id) { isPending = true; break; } } catch {}
          }
          await audit(db, 'login_failed', null, login_id, { pending: isPending }, request);
          return json({ error: isPending ? 'pending_verification' : 'invalid_credentials' }, 401, cors);
        }
        if (user.status !== 'active') return json({ error: 'account_suspended' }, 403, cors);

        const token = randomId(48);
        const expiresAt = plusSec(60 * 60 * 24 * 30);
        await db.batch([
          db.prepare("INSERT INTO sessions (token, staff_id, expires_at) VALUES (?,?,?)")
            .bind(token, user.staff_id, expiresAt),
          db.prepare("UPDATE master_staff SET last_login_at = datetime('now') WHERE staff_id = ?")
            .bind(user.staff_id)
        ]);
        await audit(db, 'login', user.staff_id, user.login_id, null, request);
        return json({
          ok: true, token, expires_at: expiresAt,
          user: {
            staff_id: user.staff_id, login_id: user.login_id, name: user.name, email: user.email,
            role: user.role, master_company_id: user.master_company_id
          }
        }, 200, cors);
      }

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

      if (path === '/api/auth/me' && method === 'GET') {
        const r = await requireAuth(request, db);
        if (r.error) return json({ error: r.error }, r.status, cors);
        const company = await db.prepare("SELECT * FROM master_companies WHERE company_id = ?")
          .bind(r.user.master_company_id).first();
        return json({ user: r.user, company }, 200, cors);
      }

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

      // =============== モジュール連携 ===============

      if (path === '/api/apps/links' && method === 'GET') {
        const r = await requireAuth(request, db);
        if (r.error) return json({ error: r.error }, r.status, cors);
        const rs = await db.prepare(
          "SELECT * FROM app_links WHERE staff_id = ? AND status != 'revoked' ORDER BY linked_at DESC"
        ).bind(r.user.staff_id).all();
        return json({ links: rs.results || [] }, 200, cors);
      }

      if (path === '/api/apps/links' && method === 'POST') {
        const r = await requireAuth(request, db);
        if (r.error) return json({ error: r.error }, r.status, cors);
        const { app_name, child_login_id, child_password } = (await request.json()) || {};
        if (!app_name || !child_login_id || !child_password) return json({ error: 'missing_fields' }, 400, cors);
        if (!['onetouch', 'medadapt'].includes(app_name)) return json({ error: 'invalid_app' }, 400, cors);

        const apiBase = app_name === 'onetouch' ? env.ONETOUCH_API_BASE : env.MEDADAPT_API_BASE;
        const loginPath = app_name === 'onetouch' ? '/api/auth/login' : '/auth/login';
        let verified = false, childCompany = null, childRole = null;
        try {
          const resp = await fetch(apiBase + loginPath, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ login_id: child_login_id, password: child_password })
          });
          if (resp.ok) {
            const data = await resp.json().catch(() => ({}));
            verified = !!(data.token || data.user || data.ok || data.success);
            childCompany = data.user?.company_code || data.company_code || data.user?.org_id || null;
            childRole    = data.user?.role || data.role || null;
          }
        } catch (e) {}

        if (!verified) return json({ error: 'child_auth_failed' }, 401, cors);

        try {
          await db.prepare(
            "INSERT INTO app_links (staff_id, app_name, child_login_id, child_company_code, child_role, status) VALUES (?,?,?,?,?, 'linked')"
          ).bind(r.user.staff_id, app_name, child_login_id, childCompany, childRole).run();
        } catch (e) {
          if (String(e.message || '').includes('UNIQUE')) return json({ error: 'already_linked' }, 409, cors);
          throw e;
        }
        await audit(db, 'link', r.user.staff_id, r.user.login_id, { app_name, child_login_id }, request);
        return json({ ok: true }, 200, cors);
      }

      const unlinkMatch = path.match(/^\/api\/apps\/links\/(\d+)$/);
      if (unlinkMatch && method === 'DELETE') {
        const r = await requireAuth(request, db);
        if (r.error) return json({ error: r.error }, r.status, cors);
        const id = Number(unlinkMatch[1]);
        const row = await db.prepare("SELECT * FROM app_links WHERE id = ? AND staff_id = ?").bind(id, r.user.staff_id).first();
        if (!row) return json({ error: 'not_found' }, 404, cors);
        await db.prepare("UPDATE app_links SET status = 'revoked' WHERE id = ?").bind(id).run();
        await audit(db, 'unlink', r.user.staff_id, r.user.login_id, { app_name: row.app_name, child_login_id: row.child_login_id }, request);
        return json({ ok: true }, 200, cors);
      }

      // =============== SSO ===============

      if (path === '/api/apps/sso-ticket' && method === 'POST') {
        const r = await requireAuth(request, db);
        if (r.error) return json({ error: r.error }, r.status, cors);
        const { app_name } = (await request.json()) || {};
        if (!['onetouch', 'medadapt'].includes(app_name)) return json({ error: 'invalid_app' }, 400, cors);

        const link = await db.prepare(
          "SELECT * FROM app_links WHERE staff_id = ? AND app_name = ? AND status = 'linked' ORDER BY linked_at DESC LIMIT 1"
        ).bind(r.user.staff_id, app_name).first();
        if (!link) return json({ error: 'not_linked' }, 404, cors);

        const ticket = randomId(48);
        const exp = plusSec(60);
        await db.prepare(
          "INSERT INTO sso_tickets (ticket, staff_id, app_name, child_login_id, expires_at) VALUES (?,?,?,?,?)"
        ).bind(ticket, r.user.staff_id, app_name, link.child_login_id, exp).run();
        await db.prepare("UPDATE app_links SET last_sso_at = datetime('now') WHERE id = ?").bind(link.id).run();

        const redirectBase = app_name === 'onetouch' ? env.ONETOUCH_APP_URL : env.MEDADAPT_APP_URL;
        const landingPath = app_name === 'onetouch' ? '/login.html' : '/app.html';
        const redirect_url = `${redirectBase}${landingPath}?sso_ticket=${ticket}&from=adapt`;

        await audit(db, 'sso_issue', r.user.staff_id, r.user.login_id, { app_name, child_login_id: link.child_login_id }, request);
        return json({ ok: true, ticket, redirect_url, expires_at: exp }, 200, cors);
      }

      if (path === '/api/apps/sso-verify' && method === 'GET') {
        const ticket = url.searchParams.get('ticket');
        if (!ticket) return json({ error: 'missing_ticket' }, 400, cors);
        const row = await db.prepare("SELECT * FROM sso_tickets WHERE ticket = ?").bind(ticket).first();
        if (!row) return json({ error: 'invalid_ticket' }, 404, cors);
        if (row.consumed_at) return json({ error: 'already_used' }, 410, cors);
        if (new Date(row.expires_at) < new Date()) return json({ error: 'expired' }, 410, cors);

        await db.prepare("UPDATE sso_tickets SET consumed_at = datetime('now') WHERE ticket = ?").bind(ticket).run();
        const staff = await db.prepare(
          "SELECT staff_id, login_id, name, email FROM master_staff WHERE staff_id = ?"
        ).bind(row.staff_id).first();

        await audit(db, 'sso_consumed', row.staff_id, null, { app_name: row.app_name, child_login_id: row.child_login_id }, request);
        return json({ ok: true, app_name: row.app_name, child_login_id: row.child_login_id, master_staff: staff }, 200, cors);
      }

      return json({ error: 'not_found', path, method }, 404, cors);
    } catch (e) {
      return json({ error: 'server_error', message: String(e.message || e) }, 500, cors);
    }
  }
};

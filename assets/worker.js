/**
 * =========================================================
 * Adavoo API Worker v2.0  (email-verified register + SES)
 *  Cloudflare Workers + D1 (adapt-db)
 *
 *  追加で必要な環境変数（Plaintext / Secret）:
 *    AWS_ACCESS_KEY_ID       = 既存Medvoo/Touchvooと同じでOK (Plaintext)
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
    'Access-Control-Allow-Headers': 'Content-Type,Authorization,X-Partner-Authorization',
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
      <h1 style="font-size:22px; font-weight:900; margin:0 0 6px 0; letter-spacing:-0.01em;">Adavoo</h1>
      <p style="font-family:monospace; font-size:11px; color:#5a6070; letter-spacing:0.12em; text-transform:uppercase; margin:0 0 28px 0;">Email Verification</p>
      <h2 style="font-size:18px; font-weight:700; margin:0 0 14px 0;">メールアドレスを確認してください</h2>
      <p style="font-size:14px; line-height:1.8; color:#2a2f3d; margin:0 0 20px 0;">
        ${esc(name)} 様<br><br>
        Adavooへのご登録ありがとうございます。<br>
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

function passwordResetEmailHtml({ name, resetUrl, loginId }) {
  const esc = (s) => String(s || '').replace(/[<>&"']/g, c => ({'<':'&lt;','>':'&gt;','&':'&amp;','"':'&quot;',"'":'&#39;'}[c]));
  return `<!DOCTYPE html>
<html lang="ja"><head><meta charset="UTF-8"></head>
<body style="font-family: 'Helvetica Neue', 'Hiragino Kaku Gothic ProN', 'Noto Sans JP', sans-serif; background:#ffffff; color:#0a0e1a; margin:0; padding:0;">
  <table width="100%" cellpadding="0" cellspacing="0" style="max-width:560px; margin:0 auto; padding:32px 20px;">
    <tr><td>
      <h1 style="font-size:22px; font-weight:900; margin:0 0 6px 0; letter-spacing:-0.01em;">Adavoo</h1>
      <p style="font-family:monospace; font-size:11px; color:#5a6070; letter-spacing:0.12em; text-transform:uppercase; margin:0 0 28px 0;">Password Reset</p>
      <h2 style="font-size:18px; font-weight:700; margin:0 0 14px 0;">パスワード再設定のご案内</h2>
      <p style="font-size:14px; line-height:1.8; color:#2a2f3d; margin:0 0 20px 0;">
        ${esc(name)} 様<br><br>
        Adavooアカウントのパスワード再設定リクエストを受け付けました。<br>
        以下のボタンから新しいパスワードを設定してください。
      </p>
      <table cellpadding="0" cellspacing="0" style="margin:8px 0 28px 0;"><tr>
        <td style="background:#c4432b; border-radius:2px;">
          <a href="${resetUrl}" style="display:inline-block; padding:13px 28px; color:#ffffff; font-weight:700; font-size:13px; letter-spacing:0.06em; text-decoration:none;">パスワードを再設定する</a>
        </td>
      </tr></table>
      <p style="font-size:11px; color:#5a6070; line-height:1.8; margin:0 0 16px 0;">
        ボタンが押せない場合は以下のURLをブラウザに貼り付けてください：<br>
        <a href="${resetUrl}" style="color:#c4432b; word-break:break-all;">${esc(resetUrl)}</a>
      </p>
      <hr style="border:0; border-top:1px solid #e3e3e0; margin:24px 0;">
      <table style="font-size:11px; color:#5a6070; line-height:1.8;">
        <tr><td style="padding-right:16px;">ログインID</td><td style="color:#0a0e1a;" class="mono">${esc(loginId)}</td></tr>
        <tr><td style="padding-right:16px;">有効期限</td><td>発行から1時間</td></tr>
      </table>
      <p style="font-size:11px; color:#9aa0ac; margin:18px 0 0 0;">
        このリクエストに心当たりがない場合、このメールは無視してください。パスワードは変更されません。<br>
        なお、パスワードを変更した場合、全ての端末から自動的にログアウトされます。<br>
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

// =========================================================
//  代理店（partners）認証
//  - 独立ヘッダ X-Partner-Authorization: Bearer <token> を使用
//  - master_staff の sessions とは完全分離（partner_sessions）
// =========================================================
async function requirePartnerAuth(request, db) {
  const auth = request.headers.get('X-Partner-Authorization') || '';
  if (!auth.startsWith('Bearer ')) return { error: 'unauthorized', status: 401 };
  const token = auth.slice(7);
  const sess = await db.prepare(
    "SELECT ps.token, ps.partner_id, ps.expires_at, " +
    "       p.type, p.parent_partner_id, p.company_name, p.code, p.login_id, " +
    "       p.email, p.phone, p.contract_start_at, p.contract_end_at, p.status, p.revenue_share_pct " +
    "  FROM partner_sessions ps JOIN partners p ON ps.partner_id = p.partner_id " +
    " WHERE ps.token = ?"
  ).bind(token).first();
  if (!sess) return { error: 'invalid_token', status: 401 };
  if (new Date(sess.expires_at) < new Date()) {
    await db.prepare("DELETE FROM partner_sessions WHERE token = ?").bind(token).run();
    return { error: 'expired', status: 401 };
  }
  if (sess.status !== 'active') return { error: 'partner_suspended', status: 403 };
  return { partner: sess };
}

// タムジ管理者（master_staff.role='tamj_admin'）認証
// 通常の requireAuth に加えてロールチェックを行う
async function requireTamjAdmin(request, db) {
  const r = await requireAuth(request, db);
  if (r.error) return r;
  if (r.user.role !== 'tamj_admin') return { error: 'forbidden_admin_only', status: 403 };
  return r;
}

// 代理店コード形式チェック: SUP-XXXXXX (総代理店) / AGT-XXXXXX (代理店)
const PARTNER_CODE_RE = /^(SUP|AGT)-\d{6}$/;
function isValidPartnerCodeFormat(code) {
  return typeof code === 'string' && PARTNER_CODE_RE.test(code);
}

// 代理店コードの存在＋active確認
async function lookupActivePartnerByCode(db, code) {
  return await db.prepare(
    "SELECT partner_id, type, code, company_name, status FROM partners WHERE code = ?"
  ).bind(code).first();
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

// 代理店（AGT-XXXXXX）の次の連番 — 総代理店がパートナー代理店を登録する際に使用
const nextAgentId = async (db) => {
  const row = await db.prepare(
    "SELECT partner_id FROM partners WHERE type = 'agent' AND partner_id LIKE 'AGT-%' ORDER BY partner_id DESC LIMIT 1"
  ).first();
  const n = row ? parseInt(row.partner_id.replace('AGT-', ''), 10) + 1 : 1;
  return 'AGT-' + String(n).padStart(6, '0');
};

// 総代理店（SUP-XXXXXX）の次の連番 — タムジが総代理店を登録する際に使用
const nextSuperId = async (db) => {
  const row = await db.prepare(
    "SELECT partner_id FROM partners WHERE type = 'super' AND partner_id LIKE 'SUP-%' ORDER BY partner_id DESC LIMIT 1"
  ).first();
  const n = row ? parseInt(row.partner_id.replace('SUP-', ''), 10) + 1 : 1;
  return 'SUP-' + String(n).padStart(6, '0');
};

// =========================================================
//  Phase 4-3b ヘルパ
// =========================================================

// 国税庁法人番号API 連携
// env.NTA_API_ID が未設定の場合は mock モードで動作（dev/test 用）
async function verifyCorporateNumber(number, env) {
  if (!/^\d{13}$/.test(number)) {
    return { ok: false, error: 'invalid_format' };
  }
  const appId = env.NTA_API_ID;
  if (!appId) {
    // mock モード：13桁数字なら形式OK扱い（API未配備でも開発継続可能）
    return {
      ok: true,
      mocked: true,
      name: null,
      name_kana: null,
      prefecture: null,
      city: null,
      street: null,
      status: null,
      message: 'NTA_API_ID 未設定のため mock モードで動作しています（実データ未検証）'
    };
  }
  try {
    const url = `https://api.houjin-bangou.nta.go.jp/4/num?id=${encodeURIComponent(appId)}&number=${number}&type=12`;
    const resp = await fetch(url);
    if (!resp.ok) {
      return { ok: false, error: 'nta_api_error', status: resp.status };
    }
    const data = await resp.json();
    if (!data || data.count === 0 || !Array.isArray(data.corporations) || data.corporations.length === 0) {
      return { ok: false, error: 'not_found' };
    }
    const corp = data.corporations[0];
    return {
      ok: true,
      mocked: false,
      name: corp.name || null,
      name_kana: corp.furigana || null,
      prefecture: corp.prefectureName || null,
      city: corp.cityName || null,
      street: corp.streetNumber || null,
      status: corp.kind || null,
      raw: data
    };
  } catch (e) {
    return { ok: false, error: 'network_error', message: String(e.message || e) };
  }
}

// 法人番号 チェックデジット検証
// 先頭1桁のチェックデジットが 9 - (下12桁の桁ごとの重み付き和 mod 9) の仕様
function isValidCorporateNumber(num) {
  if (!/^\d{13}$/.test(num)) return false;
  const check = parseInt(num[0], 10);
  const base = num.slice(1);
  let sum = 0;
  for (let i = 0; i < 12; i++) {
    const digit = parseInt(base[i], 10);
    // 奇数位(右から1,3,5...)の重みは1, 偶数位は2（右からのインデックスが偶奇）
    const weightOdd = ((11 - i) % 2) === 1;
    sum += digit * (weightOdd ? 1 : 2);
  }
  const expected = 9 - (sum % 9);
  return expected === check;
}

// 郵便番号・電話等の単純バリデーション
const validatePostalCode = (s) => typeof s === 'string' && /^\d{7}$/.test(s);
const validateJPPhone = (s) => typeof s === 'string' && /^\d{10,11}$/.test(s.replace(/[-\s()]/g, ''));
const validateKana = (s) => typeof s === 'string' && s.length >= 1 && s.length <= 100 && /^[\u30A0-\u30FF\uFF65-\uFF9F（）()\-\s]+$/.test(s);

// =========================================================
//  Phase 4-3a 按分率履歴引き当てヘルパ
//  target_date（YYYY-MM-DD）時点で有効な履歴レコードを1件取得
//  scope='tamj_to_super' の場合 parent_partner_id は NULL
//  見つからない場合は null
// =========================================================
const resolveShareHistory = async (db, partnerId, targetDate, scope = 'tamj_to_super', parentPartnerId = null) => {
  let sql =
    "SELECT id, partner_id, scope, parent_partner_id, pct, effective_from, effective_to " +
    "  FROM partner_revenue_share_history " +
    " WHERE partner_id = ? AND scope = ? " +
    "   AND effective_from <= ? " +
    "   AND (effective_to IS NULL OR effective_to >= ?)";
  const binds = [partnerId, scope, targetDate, targetDate];
  if (scope === 'super_to_agent' && parentPartnerId) {
    sql += " AND parent_partner_id = ?";
    binds.push(parentPartnerId);
  }
  sql += " ORDER BY effective_from DESC LIMIT 1";
  return await db.prepare(sql).bind(...binds).first();
};

// pct バリデーション: 0 <= pct <= 100、小数点第一位まで
const validatePct = (val) => {
  if (val === null || val === undefined || val === '') return { ok: false, error: 'invalid_pct' };
  const n = Number(val);
  if (Number.isNaN(n) || n < 0 || n > 100) return { ok: false, error: 'invalid_pct' };
  // 小数点第二位以下切り捨て
  const rounded = Math.round(n * 10) / 10;
  return { ok: true, value: rounded };
};

// YYYY-MM-DD 形式バリデーション
const validateDateYMD = (s) => {
  if (typeof s !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(s)) return false;
  const d = new Date(s + 'T00:00:00Z');
  if (Number.isNaN(d.getTime())) return false;
  return s === d.toISOString().substring(0, 10);
};

// 今日の日付を YYYY-MM-DD (JST) で取得
const todayJSTDate = () => {
  const now = new Date();
  const jst = new Date(now.getTime() + 9 * 60 * 60 * 1000);
  return jst.toISOString().substring(0, 10);
};

// =========================================================
//  月次台帳（revenue_ledger）集計ロジック
//  Cron (ledger_monthly_close) と手動再集計APIから共通利用
//
//  設計書§12.5 の原則:
//   - タムジは総代理店にしか支払わない
//   - 代理店経由の売上は上位の総代理店コードで集約
//   - タムジ直販（partner_code=NULL）は台帳に入れない
// =========================================================
async function generateMonthlyLedger(db, yearMonth) {
  // 対象月の範囲
  const ymStart = `${yearMonth}-01 00:00:00`;
  const [y, m] = yearMonth.split('-').map(Number);
  const nextMonth = m === 12 ? `${y + 1}-01-01 00:00:00` : `${y}-${String(m + 1).padStart(2, '0')}-01 00:00:00`;
  // 履歴引き当て基準日：集計対象月の1日（YYYY-MM-DD）
  const targetDate = `${yearMonth}-01`;

  // 既存エントリ削除（冪等性確保 — 再集計を可能に）
  // status='pending' のみ削除。'paid' は Phase 4-3a ルール2により保護
  await db.prepare("DELETE FROM revenue_ledger WHERE year_month = ? AND status = 'pending'")
    .bind(yearMonth).run();

  // 当月稼働中だった subscriptions を取得
  // - status='active'
  // - started_at <= 月末  かつ  (ended_at IS NULL OR ended_at >= 月初)
  // - partner_code IS NOT NULL（直販は除外）
  const subs = await db.prepare(
    "SELECT s.subscription_id, s.master_company_id, s.app_name, s.partner_code, " +
    "       s.seat_count, s.unit_price, s.started_at, s.ended_at " +
    "  FROM subscriptions s " +
    " WHERE s.partner_code IS NOT NULL " +
    "   AND s.status IN ('active','expired') " +
    "   AND s.started_at <= ? " +
    "   AND (s.ended_at IS NULL OR s.ended_at >= ?)"
  ).bind(nextMonth, ymStart).all();

  // partner_code → 上位総代理店コード のマッピング
  // (agent の場合は parent_partner_id → partners.code を引く、superならそのまま)
  const allPartners = await db.prepare(
    "SELECT partner_id, code, type, parent_partner_id, revenue_share_pct FROM partners"
  ).all();
  const partnerByCode = {};
  const partnerById = {};
  for (const p of (allPartners.results || [])) {
    partnerByCode[p.code] = p;
    partnerById[p.partner_id] = p;
  }

  const resolvePayoutSuper = (code) => {
    const p = partnerByCode[code];
    if (!p) return null;
    if (p.type === 'super') return p;
    if (p.type === 'agent' && p.parent_partner_id) {
      return partnerById[p.parent_partner_id] || null;
    }
    return null;
  };

  // app_name × 支払先総代理店コード で集約
  // share_history_id は同一 partner では同じなので集約時に一つ記録
  const bucket = {};
  const shareHistoryCache = {}; // partner_id → history record
  for (const s of (subs.results || [])) {
    const sup = resolvePayoutSuper(s.partner_code);
    if (!sup || sup.type !== 'super') continue;
    const gross = (s.seat_count || 1) * (s.unit_price || 0);

    // ★ Phase 4-3a: 履歴から按分率を引き当て ★
    let sharePct;
    let shareHistoryId = null;
    if (shareHistoryCache[sup.partner_id] === undefined) {
      shareHistoryCache[sup.partner_id] = await resolveShareHistory(db, sup.partner_id, targetDate, 'tamj_to_super', null);
    }
    const history = shareHistoryCache[sup.partner_id];
    if (history) {
      sharePct = history.pct;
      shareHistoryId = history.id;
    } else {
      // フォールバック：既存 partners.revenue_share_pct を使用（履歴登録前の互換動作）
      sharePct = (sup.revenue_share_pct !== null && sup.revenue_share_pct !== undefined) ? sup.revenue_share_pct : 0;
    }

    const shareAmount = Math.floor(gross * sharePct / 100);
    const key = `${sup.code}|${s.app_name}`;
    if (!bucket[key]) {
      bucket[key] = {
        partner_code: sup.code,
        app_name: s.app_name,
        gross_amount: 0,
        share_pct: sharePct,
        share_amount: 0,
        share_history_id: shareHistoryId,
        subscription_ids: []
      };
    }
    bucket[key].gross_amount += gross;
    bucket[key].share_amount += shareAmount;
    bucket[key].subscription_ids.push(s.subscription_id);
  }

  // INSERT
  const inserts = [];
  for (const key in bucket) {
    const b = bucket[key];
    // 複数サブスクをまとめた場合は subscription_id には最初のを入れる（集計行のため代表値）
    inserts.push(
      db.prepare(
        "INSERT INTO revenue_ledger (year_month, partner_code, app_name, subscription_id, " +
        "  gross_amount, share_pct, share_amount, share_history_id, status) " +
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending')"
      ).bind(
        yearMonth, b.partner_code, b.app_name,
        b.subscription_ids[0] || null,
        b.gross_amount, b.share_pct, b.share_amount,
        b.share_history_id
      )
    );
  }
  if (inserts.length > 0) await db.batch(inserts);

  return {
    year_month: yearMonth,
    generated_entry_count: inserts.length,
    total_gross: Object.values(bucket).reduce((s, b) => s + b.gross_amount, 0),
    total_share: Object.values(bucket).reduce((s, b) => s + b.share_amount, 0)
  };
}

// =========================================================
//  契約ライフサイクル関連のCronロジック
// =========================================================

// 契約終了2ヶ月前通知
async function runContractNotify2Month(db, env) {
  const now = new Date();
  const sixtyDaysLater = new Date(now.getTime() + 60 * 24 * 60 * 60 * 1000).toISOString();
  const nowIso = now.toISOString();

  const targets = await db.prepare(
    "SELECT partner_id, type, company_name, code, email, contract_end_at " +
    "  FROM partners " +
    " WHERE status = 'active' " +
    "   AND auto_end_notified_at IS NULL " +
    "   AND contract_end_at IS NOT NULL " +
    "   AND contract_end_at <= ? " +
    "   AND contract_end_at > ?"
  ).bind(sixtyDaysLater, nowIso).all();

  let sent = 0, failed = 0;
  for (const p of (targets.results || [])) {
    if (!p.email) {
      // メール未登録はスキップ（通知日だけ更新してループ回避）
      await db.prepare("UPDATE partners SET auto_end_notified_at = datetime('now') WHERE partner_id = ?")
        .bind(p.partner_id).run();
      continue;
    }
    try {
      const endDate = new Date(p.contract_end_at).toLocaleDateString('ja-JP');
      const typeLabel = p.type === 'super' ? '総代理店' : '代理店';
      const baseUrl = (env.BASE_URL || 'https://adapt.tamjump.com').replace(/\/+$/, '');
      await sendEmail(env, {
        to: p.email,
        subject: `【Adavoo】契約終了のお知らせ（2ヶ月前）/ ${p.company_name} 様`,
        text:
`${p.company_name} 様

いつもAdavooをご利用いただきありがとうございます。
現在の${typeLabel}契約は ${endDate} に終了予定です。

▼ 継続をご希望の場合
代理店ダッシュボードにログインし、「アカウント設定」→「契約情報」
の「継続を申請する」ボタンから申請してください。
タムジ社の承認後、契約期間が +1年延長されます。

▼ 終了をご希望の場合
同じく「アカウント設定」→「契約情報」の「終了を申請する」ボタン
から申請してください。タムジ社の承認後、契約が終了します。

代理店ログイン: ${baseUrl}/partner-login.html
アカウント設定: ${baseUrl}/partner-account.html（ログイン後に開けます）

ご不明な点は no-reply@tamjump.com までお問い合わせください。
※ このアドレスには返信できません。`
      });
      await db.prepare(
        "UPDATE partners SET auto_end_notified_at = datetime('now'), updated_at = datetime('now') WHERE partner_id = ?"
      ).bind(p.partner_id).run();
      await audit(db, 'cron_contract_notify', null, null, { partner_id: p.partner_id, email: p.email }, new Request('https://cron'));
      sent++;
    } catch (e) {
      failed++;
    }
  }
  return { sent, failed, candidates: (targets.results || []).length };
}

// 契約自動失効
async function runContractAutoExpire(db) {
  const nowIso = new Date().toISOString();

  // 対象: active + contract_end_at < now
  const targets = await db.prepare(
    "SELECT partner_id FROM partners WHERE status = 'active' AND contract_end_at IS NOT NULL AND contract_end_at < ?"
  ).bind(nowIso).all();

  let expiredCount = 0;
  for (const p of (targets.results || [])) {
    await db.batch([
      db.prepare("UPDATE partners SET status = 'expired', updated_at = datetime('now') WHERE partner_id = ?")
        .bind(p.partner_id),
      db.prepare("DELETE FROM partner_sessions WHERE partner_id = ?").bind(p.partner_id)
    ]);
    await audit(db, 'cron_contract_expired', null, null, { partner_id: p.partner_id }, new Request('https://cron'));
    expiredCount++;
  }
  return { expired_count: expiredCount };
}

// 期限切れトークンのクリーンアップ
async function runCleanupExpiredTokens(db) {
  const nowIso = new Date().toISOString();
  const results = await db.batch([
    db.prepare("DELETE FROM sso_tickets WHERE expires_at < ?").bind(nowIso),
    db.prepare("DELETE FROM email_verifications WHERE expires_at < ? AND used_at IS NULL").bind(nowIso),
    db.prepare("DELETE FROM sessions WHERE expires_at < ?").bind(nowIso),
    db.prepare("DELETE FROM partner_sessions WHERE expires_at < ?").bind(nowIso),
    db.prepare("DELETE FROM password_reset_tokens WHERE expires_at < ?").bind(nowIso),
    db.prepare("DELETE FROM partner_password_reset_tokens WHERE expires_at < ?").bind(nowIso),
    db.prepare("UPDATE partner_invitations SET status='expired' WHERE status='issued' AND expires_at < ?").bind(nowIso)
  ]);
  return {
    sso_tickets_deleted: results[0].meta?.changes || 0,
    email_verifications_deleted: results[1].meta?.changes || 0,
    sessions_deleted: results[2].meta?.changes || 0,
    partner_sessions_deleted: results[3].meta?.changes || 0,
    password_reset_tokens_deleted: results[4].meta?.changes || 0,
    partner_password_reset_tokens_deleted: results[5].meta?.changes || 0,
    partner_invitations_expired: results[6].meta?.changes || 0
  };
}

// =========================================================
//  Phase 4-3a: 按分率の日次同期 Cron
//  partner_revenue_share_history から「今日発効する」レコードを検索し、
//  partners.revenue_share_pct に反映する（scope='tamj_to_super' のみ対象）
//  毎日 00:10 JST = UTC 15:10
// =========================================================
async function runSyncRevenueSharePct(db) {
  const today = todayJSTDate();

  // 今日時点で有効な tamj_to_super 履歴を partner ごとに最新1件取得
  const rows = await db.prepare(
    "SELECT h.partner_id, h.pct " +
    "  FROM partner_revenue_share_history h " +
    " WHERE h.scope = 'tamj_to_super' " +
    "   AND h.effective_from <= ? " +
    "   AND (h.effective_to IS NULL OR h.effective_to >= ?) " +
    "   AND h.id = ( " +
    "     SELECT MAX(h2.id) FROM partner_revenue_share_history h2 " +
    "      WHERE h2.partner_id = h.partner_id AND h2.scope = 'tamj_to_super' " +
    "        AND h2.effective_from <= ? " +
    "        AND (h2.effective_to IS NULL OR h2.effective_to >= ?) " +
    "   )"
  ).bind(today, today, today, today).all();

  const toSync = rows.results || [];
  const syncedIds = [];
  const batchUpdates = [];
  for (const r of toSync) {
    // 現在の partners.revenue_share_pct と比較して変わっている場合のみ UPDATE
    const cur = await db.prepare(
      "SELECT revenue_share_pct FROM partners WHERE partner_id = ?"
    ).bind(r.partner_id).first();
    if (!cur) continue;
    if (cur.revenue_share_pct === r.pct) continue;
    batchUpdates.push(
      db.prepare(
        "UPDATE partners SET revenue_share_pct = ?, updated_at = datetime('now') WHERE partner_id = ?"
      ).bind(r.pct, r.partner_id)
    );
    syncedIds.push(r.partner_id);
  }
  if (batchUpdates.length > 0) await db.batch(batchUpdates);

  // 監査ログ
  try {
    await db.prepare("INSERT INTO audit_logs (type, details) VALUES (?, ?)")
      .bind('cron_share_sync', JSON.stringify({
        date: today,
        synced_count: syncedIds.length,
        partner_ids: syncedIds
      })).run();
  } catch {}

  return { date: today, synced_count: syncedIds.length, partner_ids: syncedIds };
}

// =========================================================
//  Square 決済連携（Phase 3f）
//
//  必要な環境変数:
//    SQUARE_ACCESS_TOKEN          (Secret)   Square API呼び出し用
//    SQUARE_LOCATION_ID           (Plain)    拠点ID
//    SQUARE_WEBHOOK_SIGNATURE_KEY (Secret)   Webhook署名検証用
//    SQUARE_APPLICATION_ID        (Plain)    フロント Web Payments SDK用
//    SQUARE_ENV                   (Plain)    'sandbox' | 'production'
// =========================================================

// 利用可能なプラン一覧（Phase 3f初期版・ハードコード）
// 将来的にはD1のテーブル化も検討（設計書 Phase 4 の宿題）
const AVAILABLE_PLANS = [
  { id: 'onetouch_pro',   app_name: 'onetouch', plan: 'pro',  name: 'Touchvoo Pro',  unit_price: 3000, description: '施設設備管理・QR台帳（IDあたり月額）' },
  { id: 'medadapt_pro',   app_name: 'medadapt', plan: 'pro',  name: 'Medvoo Pro',       unit_price: 5000, description: '医療介護法人間連携OS（IDあたり月額）' }
];

// Square Webhook 署名検証
// Squareは「notification URL + request body」をHMAC-SHA256でハッシュしてBase64で送ってくる
// ヘッダ: x-square-hmacsha256-signature
async function verifySquareWebhookSignature(request, rawBody, signatureKey, notificationUrl) {
  const signature = request.headers.get('x-square-hmacsha256-signature');
  if (!signature || !signatureKey) return false;

  const payload = notificationUrl + rawBody;
  const keyBuf = new TextEncoder().encode(signatureKey);
  const key = await crypto.subtle.importKey('raw', keyBuf, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sigBuf = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(payload));
  // Base64エンコード
  const sigArr = new Uint8Array(sigBuf);
  let binary = '';
  for (let i = 0; i < sigArr.length; i++) binary += String.fromCharCode(sigArr[i]);
  const expected = btoa(binary);

  // 定数時間比較
  if (signature.length !== expected.length) return false;
  let diff = 0;
  for (let i = 0; i < signature.length; i++) diff |= signature.charCodeAt(i) ^ expected.charCodeAt(i);
  return diff === 0;
}

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
        const { company_name, login_id, name, email, password, phone, partner_code } = b || {};
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

        // 代理店コードが入力されている場合のバリデーション（任意項目）
        let normalizedPartnerCode = null;
        if (partner_code && String(partner_code).trim() !== '') {
          const code = String(partner_code).trim().toUpperCase();
          if (!isValidPartnerCodeFormat(code)) {
            return json({ error: 'invalid_partner_code_format' }, 400, cors);
          }
          const p = await lookupActivePartnerByCode(db, code);
          if (!p) return json({ error: 'partner_code_not_found' }, 404, cors);
          if (p.status !== 'active') return json({ error: 'partner_code_inactive' }, 409, cors);
          normalizedPartnerCode = code;
        }

        const exists = await db.prepare("SELECT 1 FROM master_staff WHERE login_id = ?").bind(login_id).first();
        if (exists) return json({ error: 'login_id_taken' }, 409, cors);

        // 同じメールで pending 中のやつがあれば置き換え
        await db.prepare("DELETE FROM email_verifications WHERE email = ? AND used_at IS NULL").bind(email).run();

        const token = randomId(48);
        const passwordHash = await sha256(password);
        const pending = {
          company_name, login_id, name, email,
          phone: phone || null, password_hash: passwordHash,
          partner_code: normalizedPartnerCode  // NULL = タムジ直販
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
            subject: '【Adavoo】メールアドレス確認のお願い',
            html: verifyEmailHtml({ name, verifyUrl, companyName: company_name }),
            text:
`${name} 様

Adavooへのご登録ありがとうございます。
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

        // 代理店コードが pending_data にあり、かつ現時点でもactiveであるか最終確認
        // （登録からverifyまでの間に代理店が終了する稀なケースを救済）
        let partnerCodeToPersist = null;
        if (p.partner_code) {
          const p2 = await lookupActivePartnerByCode(db, p.partner_code);
          if (p2 && p2.status === 'active') {
            partnerCodeToPersist = p.partner_code;
          }
          // もし期間中に失効していても登録自体は続行（partner_code は NULL 扱い＝タムジ直販に降格）
        }

        await db.batch([
          db.prepare(
            "INSERT INTO master_companies (company_id, name, email, phone, partner_code, partner_code_locked_at) " +
            "VALUES (?,?,?,?,?,?)"
          ).bind(
            companyId, p.company_name, p.email || null, p.phone || null,
            partnerCodeToPersist,
            partnerCodeToPersist ? nowISO() : null
          ),
          db.prepare(
            "INSERT INTO master_staff (staff_id, master_company_id, login_id, name, email, password_hash, role, last_login_at) " +
            "VALUES (?,?,?,?,?,?, 'master_admin', datetime('now'))"
          ).bind(staffId, companyId, p.login_id, p.name, p.email, p.password_hash),
          db.prepare("INSERT INTO sessions (token, staff_id, expires_at) VALUES (?,?,?)")
            .bind(sessionToken, staffId, expiresAt),
          db.prepare("UPDATE email_verifications SET used_at = datetime('now') WHERE token = ?")
            .bind(token)
        ]);

        await audit(db, 'register_verified', staffId, p.login_id, {
          company_id: companyId,
          partner_code: partnerCodeToPersist
        }, request);
        return json({
          ok: true,
          token: sessionToken,
          expires_at: expiresAt,
          user: {
            staff_id: staffId, login_id: p.login_id, name: p.name, email: p.email,
            role: 'master_admin', master_company_id: companyId
          },
          partner_code: partnerCodeToPersist
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

      // =============== Password Reset (Phase 4-1) ===============

      // パスワードリセットのリクエスト
      //  - email 存在不問で常に 200 OK を返す（アカウント列挙攻撃防止）
      //  - メール送信失敗は内部ログのみ記録、レスポンスには出さない
      if (path === '/api/auth/password-reset-request' && method === 'POST') {
        const b = await request.json();
        const { email } = b || {};
        if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
          return json({ error: 'invalid_email' }, 400, cors);
        }

        const user = await db.prepare(
          "SELECT staff_id, login_id, name, email, status FROM master_staff WHERE email = ? AND status = 'active'"
        ).bind(email).first();

        // ユーザーが存在しない場合も、存在する場合と同じレスポンスを返す
        if (!user) {
          await audit(db, 'password_reset_requested_unknown', null, null, { email: email.slice(0, 64) }, request);
          return json({ ok: true, message: 'if_exists_email_sent' }, 200, cors);
        }

        // 同一staffの未使用リセットトークンを先に削除（多重発行防止）
        await db.prepare(
          "DELETE FROM password_reset_tokens WHERE staff_id = ? AND used_at IS NULL"
        ).bind(user.staff_id).run();

        const token = randomId(48);
        const expiresAt = plusSec(60 * 60); // 1時間

        await db.prepare(
          "INSERT INTO password_reset_tokens (token, staff_id, email, expires_at) VALUES (?,?,?,?)"
        ).bind(token, user.staff_id, email, expiresAt).run();

        const baseUrl = (env.BASE_URL || 'https://adapt.tamjump.com').replace(/\/+$/, '');
        const resetUrl = `${baseUrl}/reset-password.html?token=${token}`;

        try {
          await sendEmail(env, {
            to: email,
            subject: '【Adavoo】パスワード再設定のご案内',
            html: passwordResetEmailHtml({ name: user.name, resetUrl, loginId: user.login_id }),
            text:
`${user.name} 様

Adavooアカウントのパスワード再設定リクエストを受け付けました。
以下のURLを開いて、新しいパスワードを設定してください。

${resetUrl}

有効期限: 1時間
ログインID: ${user.login_id}

このリクエストに心当たりがない場合、このメールは無視してください。
パスワードは変更されません。

※ パスワードを変更した場合、全ての端末から自動的にログアウトされます。`
          });
          await audit(db, 'password_reset_requested', user.staff_id, user.login_id, { email }, request);
        } catch (e) {
          // 送信失敗もログには残すが、レスポンスは成功扱い（攻撃者が成否を区別できないように）
          await audit(db, 'password_reset_mail_fail', user.staff_id, user.login_id,
            { error: String(e.message || e).slice(0, 200) }, request);
        }

        return json({ ok: true, message: 'if_exists_email_sent' }, 200, cors);
      }

      // リセットトークンの情報取得（reset-password.html 表示用）
      if (path === '/api/auth/password-reset-info' && method === 'GET') {
        const token = url.searchParams.get('token');
        if (!token) return json({ error: 'missing_token' }, 400, cors);
        const row = await db.prepare(
          "SELECT prt.token, prt.staff_id, prt.email, prt.expires_at, prt.used_at, " +
          "       u.login_id, u.name, u.status " +
          "  FROM password_reset_tokens prt " +
          "  JOIN master_staff u ON prt.staff_id = u.staff_id " +
          " WHERE prt.token = ?"
        ).bind(token).first();
        if (!row) return json({ error: 'invalid_token' }, 404, cors);
        if (row.used_at) return json({ error: 'already_used' }, 410, cors);
        if (new Date(row.expires_at) < new Date()) return json({ error: 'expired' }, 410, cors);
        if (row.status !== 'active') return json({ error: 'account_suspended' }, 403, cors);

        // 表示用にメールをマスク（p***@example.com）
        const maskEmail = (e) => {
          const m = String(e || '').match(/^([^@]+)@(.+)$/);
          if (!m) return '';
          const [, local, domain] = m;
          const masked = local.length <= 2 ? local[0] + '*' : local[0] + '***' + local[local.length - 1];
          return `${masked}@${domain}`;
        };

        return json({
          ok: true,
          login_id: row.login_id,
          name: row.name,
          email_masked: maskEmail(row.email),
          expires_at: row.expires_at
        }, 200, cors);
      }

      // リセット確定: 新パスワード設定 + 全セッション破棄 + 新セッション発行
      if (path === '/api/auth/password-reset-confirm' && method === 'POST') {
        const { token, new_password } = (await request.json()) || {};
        if (!token || !new_password) return json({ error: 'missing_fields' }, 400, cors);
        if (new_password.length < 8) return json({ error: 'password_too_short' }, 400, cors);

        const row = await db.prepare(
          "SELECT * FROM password_reset_tokens WHERE token = ?"
        ).bind(token).first();
        if (!row) return json({ error: 'invalid_token' }, 404, cors);
        if (row.used_at) return json({ error: 'already_used' }, 410, cors);
        if (new Date(row.expires_at) < new Date()) return json({ error: 'expired' }, 410, cors);

        const user = await db.prepare(
          "SELECT staff_id, login_id, name, email, role, master_company_id, status FROM master_staff WHERE staff_id = ?"
        ).bind(row.staff_id).first();
        if (!user) return json({ error: 'user_not_found' }, 404, cors);
        if (user.status !== 'active') return json({ error: 'account_suspended' }, 403, cors);

        const newHash = await sha256(new_password);
        const newSessionToken = randomId(48);
        const sessionExpires = plusSec(60 * 60 * 24 * 30);

        // 一括処理:
        // 1. パスワード更新
        // 2. 既存セッション全削除（セキュリティ: 全端末からログアウト）
        // 3. リセットトークンを used に
        // 4. 新セッション発行（自動ログイン用）
        await db.batch([
          db.prepare("UPDATE master_staff SET password_hash = ?, updated_at = datetime('now') WHERE staff_id = ?")
            .bind(newHash, user.staff_id),
          db.prepare("DELETE FROM sessions WHERE staff_id = ?").bind(user.staff_id),
          db.prepare("UPDATE password_reset_tokens SET used_at = datetime('now') WHERE token = ?").bind(token),
          db.prepare("INSERT INTO sessions (token, staff_id, expires_at) VALUES (?,?,?)")
            .bind(newSessionToken, user.staff_id, sessionExpires)
        ]);

        // 同時に古いパスワードリセットトークンもすべて無効化（別トークンを横流しで悪用されるのを防ぐ）
        await db.prepare(
          "UPDATE password_reset_tokens SET used_at = datetime('now') WHERE staff_id = ? AND used_at IS NULL AND token != ?"
        ).bind(user.staff_id, token).run();

        await audit(db, 'password_reset_completed', user.staff_id, user.login_id, null, request);

        return json({
          ok: true,
          token: newSessionToken,
          expires_at: sessionExpires,
          user: {
            staff_id: user.staff_id, login_id: user.login_id, name: user.name, email: user.email,
            role: user.role, master_company_id: user.master_company_id
          }
        }, 200, cors);
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

        // Service Binding経由で子Workerを呼び出す（Cloudflare Error 1042=同一ゾーンWorker間fetch制限の回避）
        // env.ONETOUCH_SVC / env.MEDADAPT_SVC はCloudflareダッシュボードのService Bindingsで設定
        const svc = app_name === 'onetouch' ? env.ONETOUCH_SVC : env.MEDADAPT_SVC;
        const loginPath = app_name === 'onetouch' ? '/api/auth/login' : '/auth/login';
        let verified = false, childCompany = null, childRole = null;
        let debugInfo = { url: loginPath, status: null, bodyPreview: null, verifiedBy: null, transport: 'service_binding' };
        try {
          if (!svc) {
            // Service Bindingが未設定の場合は旧来のfetchにフォールバック（ローカル/開発用途）
            const apiBase = app_name === 'onetouch' ? env.ONETOUCH_API_BASE : env.MEDADAPT_API_BASE;
            debugInfo.transport = 'fetch_fallback';
            debugInfo.url = apiBase + loginPath;
            var resp = await fetch(apiBase + loginPath, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ login_id: child_login_id, loginId: child_login_id, email: child_login_id, password: child_password })
            });
          } else {
            // Service Binding経由。ホスト名はダミー（Service Bindingが上書きする）
            // bodyは子API側のフィールド名差異を吸収するため3形式で送信
            // - Touchvoo: loginId (camelCase)
            // - Medvoo: email (ADM-/STF-プレフィックスのlogin_idもemailフィールドで受ける設計)
            // - 予備: login_id (snake_case)
            var resp = await svc.fetch('https://internal' + loginPath, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ login_id: child_login_id, loginId: child_login_id, email: child_login_id, password: child_password })
            });
          }
          debugInfo.status = resp.status;
          const rawText = await resp.text();
          debugInfo.bodyPreview = rawText.slice(0, 500);
          if (resp.ok) {
            let data = {};
            try { data = JSON.parse(rawText); } catch {}
            // より幅広くチェック：トークン系フィールド全般、user系、ok/success系
            if (data.token) { verified = true; debugInfo.verifiedBy = 'token'; }
            else if (data.access_token) { verified = true; debugInfo.verifiedBy = 'access_token'; }
            else if (data.session_token) { verified = true; debugInfo.verifiedBy = 'session_token'; }
            else if (data.user) { verified = true; debugInfo.verifiedBy = 'user'; }
            else if (data.ok === true) { verified = true; debugInfo.verifiedBy = 'ok'; }
            else if (data.success === true) { verified = true; debugInfo.verifiedBy = 'success'; }
            else if (data.staff_id || data.user_id || data.id) { verified = true; debugInfo.verifiedBy = 'id_field'; }
            childCompany = data.user?.company_code || data.company_code || data.user?.org_id || data.org_id || null;
            childRole    = data.user?.role || data.role || null;
          }
        } catch (e) {
          debugInfo.fetchError = String(e.message || e);
        }
        console.log('LINK_DEBUG:', JSON.stringify({ app_name, child_login_id, debugInfo }));

        if (!verified) return json({ error: 'child_auth_failed', debug: debugInfo }, 401, cors);

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

      // =============== 代理店コード（エンドユーザー側：後付け入力） ===============

      // エンドユーザーが後から代理店コードを紐付ける（1回のみ・以後変更不可）
      if (path === '/api/company/claim-partner-code' && method === 'POST') {
        const r = await requireAuth(request, db);
        if (r.error) return json({ error: r.error }, r.status, cors);

        const { partner_code } = (await request.json()) || {};
        if (!partner_code) return json({ error: 'missing_fields' }, 400, cors);

        const code = String(partner_code).trim().toUpperCase();
        if (!isValidPartnerCodeFormat(code)) {
          return json({ error: 'invalid_partner_code_format' }, 400, cors);
        }

        // 会社の現状確認: 既にロック済みなら変更不可
        const company = await db.prepare(
          "SELECT company_id, partner_code, partner_code_locked_at FROM master_companies WHERE company_id = ?"
        ).bind(r.user.master_company_id).first();
        if (!company) return json({ error: 'company_not_found' }, 404, cors);
        if (company.partner_code_locked_at) {
          return json({
            error: 'partner_code_already_locked',
            partner_code: company.partner_code
          }, 409, cors);
        }

        // コード存在＋active 確認
        const p = await lookupActivePartnerByCode(db, code);
        if (!p) return json({ error: 'partner_code_not_found' }, 404, cors);
        if (p.status !== 'active') return json({ error: 'partner_code_inactive' }, 409, cors);

        // 書き込み（partner_code + partner_code_locked_at を同時にセット）
        await db.prepare(
          "UPDATE master_companies SET partner_code = ?, partner_code_locked_at = datetime('now'), updated_at = datetime('now') WHERE company_id = ?"
        ).bind(code, r.user.master_company_id).run();

        await audit(db, 'claim_partner_code', r.user.staff_id, r.user.login_id, {
          company_id: r.user.master_company_id, partner_code: code
        }, request);

        return json({
          ok: true,
          partner_code: code,
          partner_code_locked_at: nowISO(),
          partner: { type: p.type, company_name: p.company_name }
        }, 200, cors);
      }

      // =============== 代理店（partner）認証系 ===============

      // 代理店ログイン
      if (path === '/api/partner/login' && method === 'POST') {
        const { login_id, password } = (await request.json()) || {};
        if (!login_id || !password) return json({ error: 'missing_fields' }, 400, cors);

        const hash = await sha256(password);
        const p = await db.prepare(
          "SELECT * FROM partners WHERE login_id = ? AND password_hash = ?"
        ).bind(login_id, hash).first();

        if (!p) {
          await audit(db, 'partner_login_failed', null, login_id, null, request);
          return json({ error: 'invalid_credentials' }, 401, cors);
        }
        if (p.status !== 'active') {
          await audit(db, 'partner_login_blocked', null, login_id, { status: p.status }, request);
          return json({ error: 'partner_suspended', status_detail: p.status }, 403, cors);
        }

        const token = randomId(48);
        const expiresAt = plusSec(60 * 60 * 24 * 30);
        await db.batch([
          db.prepare("INSERT INTO partner_sessions (token, partner_id, expires_at) VALUES (?,?,?)")
            .bind(token, p.partner_id, expiresAt),
          db.prepare("UPDATE partners SET updated_at = datetime('now') WHERE partner_id = ?")
            .bind(p.partner_id)
        ]);

        await audit(db, 'partner_login', null, login_id, { partner_id: p.partner_id, type: p.type }, request);
        return json({
          ok: true,
          token,
          expires_at: expiresAt,
          partner: {
            partner_id: p.partner_id,
            type: p.type,
            parent_partner_id: p.parent_partner_id,
            company_name: p.company_name,
            code: p.code,
            login_id: p.login_id,
            email: p.email,
            contract_start_at: p.contract_start_at,
            contract_end_at: p.contract_end_at,
            revenue_share_pct: p.revenue_share_pct
          }
        }, 200, cors);
      }

      // 代理店ログアウト
      if (path === '/api/partner/logout' && method === 'POST') {
        const auth = request.headers.get('X-Partner-Authorization') || '';
        if (auth.startsWith('Bearer ')) {
          const t = auth.slice(7);
          const s = await db.prepare("SELECT partner_id FROM partner_sessions WHERE token = ?").bind(t).first();
          await db.prepare("DELETE FROM partner_sessions WHERE token = ?").bind(t).run();
          if (s) await audit(db, 'partner_logout', null, null, { partner_id: s.partner_id }, request);
        }
        return json({ ok: true }, 200, cors);
      }

      // 代理店情報取得
      if (path === '/api/partner/me' && method === 'GET') {
        const r = await requirePartnerAuth(request, db);
        if (r.error) return json({ error: r.error }, r.status, cors);
        const p = r.partner;
        // 親総代理店情報（agentの場合のみ）
        let parent = null;
        if (p.type === 'agent' && p.parent_partner_id) {
          parent = await db.prepare(
            "SELECT partner_id, code, company_name FROM partners WHERE partner_id = ?"
          ).bind(p.parent_partner_id).first();
        }
        // bank_info_json の個別取得（requirePartnerAuth では引かない）
        const bankRow = await db.prepare(
          "SELECT bank_info_json, renewal_requested_at, renewal_note, terminate_requested_at, terminate_note, last_renewal_approved_at FROM partners WHERE partner_id = ?"
        ).bind(p.partner_id).first();
        let bankInfo = null;
        try { bankInfo = bankRow?.bank_info_json ? JSON.parse(bankRow.bank_info_json) : null; } catch {}
        return json({
          ok: true,
          partner: {
            partner_id: p.partner_id,
            type: p.type,
            parent_partner_id: p.parent_partner_id,
            parent: parent,
            company_name: p.company_name,
            code: p.code,
            login_id: p.login_id,
            email: p.email,
            phone: p.phone,
            contract_start_at: p.contract_start_at,
            contract_end_at: p.contract_end_at,
            revenue_share_pct: p.revenue_share_pct,
            status: p.status,
            bank_info: bankInfo,
            renewal_requested_at: bankRow?.renewal_requested_at || null,
            renewal_note: bankRow?.renewal_note || null,
            terminate_requested_at: bankRow?.terminate_requested_at || null,
            terminate_note: bankRow?.terminate_note || null,
            last_renewal_approved_at: bankRow?.last_renewal_approved_at || null
          }
        }, 200, cors);
      }

      // Phase 4-3c: 代理店自身による自己情報の更新（email / phone / bank_info）
      // 会社名・種別・契約期間・按分率・login_id は編集不可（タムジ管理者のみ）
      if (path === '/api/partner/me' && method === 'PUT') {
        const r = await requirePartnerAuth(request, db);
        if (r.error) return json({ error: r.error }, r.status, cors);
        const p = r.partner;

        const b = (await request.json()) || {};
        const { email, phone, bank_info } = b;

        // バリデーション
        if (email !== undefined && email !== null && email !== '') {
          if (typeof email !== 'string' || email.length > 200) return json({ error: 'invalid_email' }, 400, cors);
          if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return json({ error: 'invalid_email' }, 400, cors);
        }
        if (phone !== undefined && phone !== null && phone !== '') {
          if (typeof phone !== 'string' || phone.length > 40) return json({ error: 'invalid_phone' }, 400, cors);
          // 緩めのバリデーション：数字・ハイフン・プラス・括弧・スペース
          if (!/^[0-9+\-\s()]+$/.test(phone)) return json({ error: 'invalid_phone' }, 400, cors);
        }
        if (bank_info !== undefined && bank_info !== null) {
          if (typeof bank_info !== 'object') return json({ error: 'invalid_bank_info' }, 400, cors);
          // 許可フィールド限定（不要なキーは捨てる）
          const allowed = ['bank_name', 'branch_name', 'branch_code', 'account_type', 'account_number', 'account_holder'];
          const cleaned = {};
          for (const k of allowed) {
            if (bank_info[k] !== undefined && bank_info[k] !== null) {
              if (typeof bank_info[k] !== 'string' || bank_info[k].length > 100) {
                return json({ error: 'invalid_bank_info', field: k }, 400, cors);
              }
              cleaned[k] = bank_info[k];
            }
          }
          // account_type は 'ordinary' | 'checking' | '普通' | '当座' 受け入れ
          if (cleaned.account_type && !['ordinary', 'checking', '普通', '当座', ''].includes(cleaned.account_type)) {
            return json({ error: 'invalid_bank_info', field: 'account_type' }, 400, cors);
          }
          // account_number は数字のみ 4〜10桁（日本の一般的な口座番号）
          if (cleaned.account_number && !/^\d{4,10}$/.test(cleaned.account_number)) {
            return json({ error: 'invalid_bank_info', field: 'account_number' }, 400, cors);
          }
          b.bank_info_cleaned = cleaned;
        }

        // 変更された項目だけを UPDATE
        const sets = [];
        const binds = [];
        const changes = {};
        if (email !== undefined) {
          sets.push('email = ?');
          binds.push(email || null);
          if (email !== p.email) changes.email = { old: p.email, new: email || null };
        }
        if (phone !== undefined) {
          sets.push('phone = ?');
          binds.push(phone || null);
          if (phone !== p.phone) changes.phone = { old: p.phone, new: phone || null };
        }
        if (bank_info !== undefined) {
          const bankJson = b.bank_info_cleaned ? JSON.stringify(b.bank_info_cleaned) : null;
          sets.push('bank_info_json = ?');
          binds.push(bankJson);
          changes.bank_info = { new: b.bank_info_cleaned || null };
        }

        if (sets.length === 0) {
          return json({ error: 'no_changes' }, 400, cors);
        }

        sets.push("updated_at = datetime('now')");
        binds.push(p.partner_id);
        await db.prepare(
          `UPDATE partners SET ${sets.join(', ')} WHERE partner_id = ?`
        ).bind(...binds).run();

        await audit(db, 'partner_self_updated', null, p.login_id, {
          partner_id: p.partner_id,
          changes: changes
        }, request);

        // 更新後の partner を取得して返す
        const updated = await db.prepare(
          "SELECT email, phone, bank_info_json FROM partners WHERE partner_id = ?"
        ).bind(p.partner_id).first();
        let bankInfoUpdated = null;
        try { bankInfoUpdated = updated?.bank_info_json ? JSON.parse(updated.bank_info_json) : null; } catch {}

        return json({
          ok: true,
          updated_fields: Object.keys(changes),
          partner: {
            partner_id: p.partner_id,
            email: updated?.email || null,
            phone: updated?.phone || null,
            bank_info: bankInfoUpdated
          }
        }, 200, cors);
      }

      // =============== Phase 4-3d: 契約継続/終了の代理店申請 ===============

      // 継続申請
      if (path === '/api/partner/renewal-request' && method === 'POST') {
        const r = await requirePartnerAuth(request, db);
        if (r.error) return json({ error: r.error }, r.status, cors);
        const p = r.partner;

        if (p.status !== 'active') return json({ error: 'not_active', current_status: p.status }, 400, cors);
        if (!p.contract_end_at) return json({ error: 'no_contract_end' }, 400, cors);

        // 契約終了60日前以内のみ可能
        const endDate = new Date(p.contract_end_at);
        const now = new Date();
        const daysLeft = Math.ceil((endDate.getTime() - now.getTime()) / (24 * 60 * 60 * 1000));
        if (daysLeft > 60) return json({ error: 'too_early', days_left: daysLeft }, 400, cors);
        if (daysLeft < 0) return json({ error: 'contract_already_ended' }, 400, cors);

        // 既に申請中なら弾く
        const current = await db.prepare(
          "SELECT renewal_requested_at, terminate_requested_at FROM partners WHERE partner_id = ?"
        ).bind(p.partner_id).first();
        if (current?.renewal_requested_at) return json({ error: 'already_requested', since: current.renewal_requested_at }, 409, cors);
        if (current?.terminate_requested_at) return json({ error: 'terminate_pending' }, 409, cors);

        const b = (await request.json().catch(() => ({}))) || {};
        const note = (b.note || '').toString();
        if (note.length > 500) return json({ error: 'note_too_long' }, 400, cors);

        const nowIso = nowISO();
        await db.prepare(
          "UPDATE partners SET renewal_requested_at = ?, renewal_note = ?, updated_at = datetime('now') WHERE partner_id = ?"
        ).bind(nowIso, note || null, p.partner_id).run();

        await audit(db, 'partner_renewal_requested', null, p.login_id, {
          partner_id: p.partner_id,
          contract_end_at: p.contract_end_at,
          days_left: daysLeft,
          note: note || null
        }, request);

        return json({
          ok: true,
          requested_at: nowIso,
          contract_end_at: p.contract_end_at,
          days_left: daysLeft,
          note: note || null,
          message: '継続申請を受け付けました。タムジ社の承認をお待ちください。'
        }, 200, cors);
      }

      // 終了申請
      if (path === '/api/partner/terminate-request' && method === 'POST') {
        const r = await requirePartnerAuth(request, db);
        if (r.error) return json({ error: r.error }, r.status, cors);
        const p = r.partner;

        if (p.status !== 'active') return json({ error: 'not_active', current_status: p.status }, 400, cors);

        const current = await db.prepare(
          "SELECT renewal_requested_at, terminate_requested_at FROM partners WHERE partner_id = ?"
        ).bind(p.partner_id).first();
        if (current?.terminate_requested_at) return json({ error: 'already_requested', since: current.terminate_requested_at }, 409, cors);
        if (current?.renewal_requested_at) return json({ error: 'renewal_pending' }, 409, cors);

        const b = (await request.json().catch(() => ({}))) || {};
        const note = (b.note || '').toString();
        if (note.length > 500) return json({ error: 'note_too_long' }, 400, cors);

        const nowIso = nowISO();
        await db.prepare(
          "UPDATE partners SET terminate_requested_at = ?, terminate_note = ?, updated_at = datetime('now') WHERE partner_id = ?"
        ).bind(nowIso, note || null, p.partner_id).run();

        await audit(db, 'partner_terminate_requested', null, p.login_id, {
          partner_id: p.partner_id,
          contract_end_at: p.contract_end_at,
          note: note || null
        }, request);

        return json({
          ok: true,
          requested_at: nowIso,
          note: note || null,
          message: '終了申請を受け付けました。タムジ社の承認後、契約が終了します。'
        }, 200, cors);
      }

      // 申請取り消し（継続 or 終了）
      if (path === '/api/partner/cancel-request' && method === 'POST') {
        const r = await requirePartnerAuth(request, db);
        if (r.error) return json({ error: r.error }, r.status, cors);
        const p = r.partner;

        const b = (await request.json().catch(() => ({}))) || {};
        const type = b.type;
        if (type !== 'renewal' && type !== 'terminate') {
          return json({ error: 'invalid_type' }, 400, cors);
        }

        const current = await db.prepare(
          "SELECT renewal_requested_at, terminate_requested_at FROM partners WHERE partner_id = ?"
        ).bind(p.partner_id).first();

        if (type === 'renewal' && !current?.renewal_requested_at) {
          return json({ error: 'no_pending_renewal' }, 404, cors);
        }
        if (type === 'terminate' && !current?.terminate_requested_at) {
          return json({ error: 'no_pending_terminate' }, 404, cors);
        }

        if (type === 'renewal') {
          await db.prepare(
            "UPDATE partners SET renewal_requested_at = NULL, renewal_note = NULL, updated_at = datetime('now') WHERE partner_id = ?"
          ).bind(p.partner_id).run();
        } else {
          await db.prepare(
            "UPDATE partners SET terminate_requested_at = NULL, terminate_note = NULL, updated_at = datetime('now') WHERE partner_id = ?"
          ).bind(p.partner_id).run();
        }

        await audit(db, 'partner_request_cancelled', null, p.login_id, {
          partner_id: p.partner_id,
          type: type
        }, request);

        return json({ ok: true, type }, 200, cors);
      }

      // =============== 代理店パスワード変更・リセット（Phase 4-2） ===============

      // ログイン中の代理店によるパスワード変更
      //  - 現在のパスワード検証 + 新パスワードで上書き
      //  - 他セッションを全破棄（現在のセッションは維持）
      if (path === '/api/partner/change-password' && method === 'POST') {
        const r = await requirePartnerAuth(request, db);
        if (r.error) return json({ error: r.error }, r.status, cors);
        const { old_password, new_password } = (await request.json()) || {};
        if (!old_password || !new_password) return json({ error: 'missing_fields' }, 400, cors);
        if (new_password.length < 8) return json({ error: 'password_too_short' }, 400, cors);

        const oldHash = await sha256(old_password);
        const check = await db.prepare(
          "SELECT 1 FROM partners WHERE partner_id = ? AND password_hash = ?"
        ).bind(r.partner.partner_id, oldHash).first();
        if (!check) return json({ error: 'wrong_password' }, 401, cors);

        const newHash = await sha256(new_password);

        // 現在のトークン（変更後も維持）
        const currentAuth = request.headers.get('X-Partner-Authorization') || '';
        const currentToken = currentAuth.startsWith('Bearer ') ? currentAuth.slice(7) : null;

        await db.batch([
          db.prepare("UPDATE partners SET password_hash = ?, updated_at = datetime('now') WHERE partner_id = ?")
            .bind(newHash, r.partner.partner_id),
          // 他セッションを全削除（現セッションのみ残す）
          db.prepare("DELETE FROM partner_sessions WHERE partner_id = ? AND token != ?")
            .bind(r.partner.partner_id, currentToken || '')
        ]);

        await audit(db, 'partner_password_change', null, r.partner.login_id,
          { partner_id: r.partner.partner_id }, request);
        return json({ ok: true }, 200, cors);
      }

      // パスワードリセットのリクエスト（代理店）
      //  - email 存在不問で常に 200 OK（アカウント列挙攻撃対策）
      //  - partners.email に対して送信
      if (path === '/api/partner/password-reset-request' && method === 'POST') {
        const b = await request.json();
        const { email } = b || {};
        if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
          return json({ error: 'invalid_email' }, 400, cors);
        }

        const p = await db.prepare(
          "SELECT partner_id, login_id, company_name, email, status FROM partners WHERE email = ? AND status = 'active'"
        ).bind(email).first();

        // 存在しない場合も成功レスポンス（情報漏洩防止）
        if (!p) {
          await audit(db, 'partner_password_reset_requested_unknown', null, null,
            { email: email.slice(0, 64) }, request);
          return json({ ok: true, message: 'if_exists_email_sent' }, 200, cors);
        }

        // 同一partnerの未使用トークン削除（多重発行防止）
        await db.prepare(
          "DELETE FROM partner_password_reset_tokens WHERE partner_id = ? AND used_at IS NULL"
        ).bind(p.partner_id).run();

        const token = randomId(48);
        const expiresAt = plusSec(60 * 60); // 1時間

        await db.prepare(
          "INSERT INTO partner_password_reset_tokens (token, partner_id, email, expires_at) VALUES (?,?,?,?)"
        ).bind(token, p.partner_id, email, expiresAt).run();

        const baseUrl = (env.BASE_URL || 'https://adapt.tamjump.com').replace(/\/+$/, '');
        const resetUrl = `${baseUrl}/partner-reset-password.html?token=${token}`;

        try {
          await sendEmail(env, {
            to: email,
            subject: '【Adavoo Partner Portal】パスワード再設定のご案内',
            html: passwordResetEmailHtml({ name: p.company_name, resetUrl, loginId: p.login_id }),
            text:
`${p.company_name} 御中

Adavoo 代理店アカウントのパスワード再設定リクエストを受け付けました。
以下のURLを開いて、新しいパスワードを設定してください。

${resetUrl}

有効期限: 1時間
ログインID: ${p.login_id}

このリクエストに心当たりがない場合、このメールは無視してください。
パスワードは変更されません。

※ パスワードを変更した場合、全ての端末から自動的にログアウトされます。`
          });
          await audit(db, 'partner_password_reset_requested', null, p.login_id,
            { partner_id: p.partner_id, email }, request);
        } catch (e) {
          await audit(db, 'partner_password_reset_mail_fail', null, p.login_id,
            { partner_id: p.partner_id, error: String(e.message || e).slice(0, 200) }, request);
        }

        return json({ ok: true, message: 'if_exists_email_sent' }, 200, cors);
      }

      // リセットトークン情報取得（partner-reset-password.html 表示用）
      if (path === '/api/partner/password-reset-info' && method === 'GET') {
        const token = url.searchParams.get('token');
        if (!token) return json({ error: 'missing_token' }, 400, cors);
        const row = await db.prepare(
          "SELECT prt.token, prt.partner_id, prt.email, prt.expires_at, prt.used_at, " +
          "       p.login_id, p.company_name, p.type, p.status " +
          "  FROM partner_password_reset_tokens prt " +
          "  JOIN partners p ON prt.partner_id = p.partner_id " +
          " WHERE prt.token = ?"
        ).bind(token).first();
        if (!row) return json({ error: 'invalid_token' }, 404, cors);
        if (row.used_at) return json({ error: 'already_used' }, 410, cors);
        if (new Date(row.expires_at) < new Date()) return json({ error: 'expired' }, 410, cors);
        if (row.status !== 'active') return json({ error: 'partner_suspended' }, 403, cors);

        const maskEmail = (e) => {
          const m = String(e || '').match(/^([^@]+)@(.+)$/);
          if (!m) return '';
          const [, local, domain] = m;
          const masked = local.length <= 2 ? local[0] + '*' : local[0] + '***' + local[local.length - 1];
          return `${masked}@${domain}`;
        };

        return json({
          ok: true,
          login_id: row.login_id,
          company_name: row.company_name,
          partner_type: row.type,
          email_masked: maskEmail(row.email),
          expires_at: row.expires_at
        }, 200, cors);
      }

      // リセット確定: 新パスワード設定 + 全セッション破棄 + 新セッション発行（自動ログイン）
      if (path === '/api/partner/password-reset-confirm' && method === 'POST') {
        const { token, new_password } = (await request.json()) || {};
        if (!token || !new_password) return json({ error: 'missing_fields' }, 400, cors);
        if (new_password.length < 8) return json({ error: 'password_too_short' }, 400, cors);

        const row = await db.prepare(
          "SELECT * FROM partner_password_reset_tokens WHERE token = ?"
        ).bind(token).first();
        if (!row) return json({ error: 'invalid_token' }, 404, cors);
        if (row.used_at) return json({ error: 'already_used' }, 410, cors);
        if (new Date(row.expires_at) < new Date()) return json({ error: 'expired' }, 410, cors);

        const p = await db.prepare(
          "SELECT * FROM partners WHERE partner_id = ?"
        ).bind(row.partner_id).first();
        if (!p) return json({ error: 'partner_not_found' }, 404, cors);
        if (p.status !== 'active') return json({ error: 'partner_suspended' }, 403, cors);

        const newHash = await sha256(new_password);
        const newSessionToken = randomId(48);
        const sessionExpires = plusSec(60 * 60 * 24 * 30);

        // 一括処理:
        // 1. パスワード更新
        // 2. 既存セッション全削除（全端末ログアウト）
        // 3. リセットトークンを used に
        // 4. 新セッション発行（自動ログイン用）
        await db.batch([
          db.prepare("UPDATE partners SET password_hash = ?, updated_at = datetime('now') WHERE partner_id = ?")
            .bind(newHash, p.partner_id),
          db.prepare("DELETE FROM partner_sessions WHERE partner_id = ?").bind(p.partner_id),
          db.prepare("UPDATE partner_password_reset_tokens SET used_at = datetime('now') WHERE token = ?").bind(token),
          db.prepare("INSERT INTO partner_sessions (token, partner_id, expires_at) VALUES (?,?,?)")
            .bind(newSessionToken, p.partner_id, sessionExpires)
        ]);

        // 他の未使用トークンも無効化（横流し対策）
        await db.prepare(
          "UPDATE partner_password_reset_tokens SET used_at = datetime('now') WHERE partner_id = ? AND used_at IS NULL AND token != ?"
        ).bind(p.partner_id, token).run();

        await audit(db, 'partner_password_reset_completed', null, p.login_id,
          { partner_id: p.partner_id }, request);

        return json({
          ok: true,
          token: newSessionToken,
          expires_at: sessionExpires,
          partner: {
            partner_id: p.partner_id,
            type: p.type,
            parent_partner_id: p.parent_partner_id,
            company_name: p.company_name,
            code: p.code,
            login_id: p.login_id,
            email: p.email,
            contract_start_at: p.contract_start_at,
            contract_end_at: p.contract_end_at,
            revenue_share_pct: p.revenue_share_pct
          }
        }, 200, cors);
      }

      // =============== 代理店ダッシュボード ===============

      // ダッシュボード用サマリー集計
      //   総代理店: 自分のコード + パートナー代理店コード に紐づくエンドユーザー/売上
      //   代理店  : 自分のコードのみに紐づくエンドユーザー/売上
      if (path === '/api/partner/dashboard' && method === 'GET') {
        const r = await requirePartnerAuth(request, db);
        if (r.error) return json({ error: r.error }, r.status, cors);
        const p = r.partner;

        // 集計対象のコード一覧
        let codes = [p.code];
        let subAgentCount = 0;
        if (p.type === 'super') {
          const subs = await db.prepare(
            "SELECT code FROM partners WHERE parent_partner_id = ? AND status != 'terminated'"
          ).bind(p.partner_id).all();
          const subCodes = (subs.results || []).map(x => x.code);
          codes = codes.concat(subCodes);
          // active のパートナー代理店のみカウント
          const activeSubs = await db.prepare(
            "SELECT COUNT(*) AS cnt FROM partners WHERE parent_partner_id = ? AND status = 'active'"
          ).bind(p.partner_id).first();
          subAgentCount = activeSubs?.cnt || 0;
        }

        // ご紹介先企業数（企業数）
        const placeholders = codes.map(() => '?').join(',');
        const customerCountRow = await db.prepare(
          `SELECT COUNT(*) AS cnt FROM master_companies WHERE partner_code IN (${placeholders})`
        ).bind(...codes).first();
        const customerCount = customerCountRow?.cnt || 0;

        // ご紹介先企業の有料契約数（subscriptions.status='active'）
        const activeSubsCountRow = await db.prepare(
          `SELECT COUNT(*) AS cnt FROM subscriptions WHERE partner_code IN (${placeholders}) AND status = 'active'`
        ).bind(...codes).first();
        const activeSubscriptionCount = activeSubsCountRow?.cnt || 0;

        // 当月の売上台帳（revenue_ledger）— 総代理店の場合は自分のコードで集計（代理店経由分も集約されている）
        const ym = new Date().toISOString().slice(0, 7); // YYYY-MM
        let ledgerSummary = null;
        if (p.type === 'super') {
          const row = await db.prepare(
            "SELECT COUNT(*) AS count, COALESCE(SUM(gross_amount),0) AS gross, COALESCE(SUM(share_amount),0) AS share " +
            "FROM revenue_ledger WHERE partner_code = ? AND year_month = ?"
          ).bind(p.code, ym).first();
          ledgerSummary = {
            year_month: ym,
            entry_count: row?.count || 0,
            gross_amount: row?.gross || 0,
            share_amount: row?.share || 0
          };
        }

        return json({
          ok: true,
          partner: {
            partner_id: p.partner_id,
            type: p.type,
            company_name: p.company_name,
            code: p.code,
            contract_start_at: p.contract_start_at,
            contract_end_at: p.contract_end_at
          },
          summary: {
            customer_count: customerCount,
            active_subscription_count: activeSubscriptionCount,
            sub_agent_count: p.type === 'super' ? subAgentCount : null,
            current_month_ledger: ledgerSummary  // 代理店はnull（タムジは総代理店にしか支払わないため）
          }
        }, 200, cors);
      }

      // ご紹介先企業一覧
      //   総代理店: 自コード + パートナー代理店コード に紐づく master_companies
      //   代理店  : 自コードに紐づく master_companies
      if (path === '/api/partner/customers' && method === 'GET') {
        const r = await requirePartnerAuth(request, db);
        if (r.error) return json({ error: r.error }, r.status, cors);
        const p = r.partner;

        let codes = [p.code];
        let subAgentCodes = [];
        if (p.type === 'super') {
          const subs = await db.prepare(
            "SELECT partner_id, code, company_name FROM partners WHERE parent_partner_id = ? AND status != 'terminated'"
          ).bind(p.partner_id).all();
          const subList = subs.results || [];
          subAgentCodes = subList.map(x => ({ code: x.code, company_name: x.company_name, partner_id: x.partner_id }));
          codes = codes.concat(subList.map(x => x.code));
        }

        const placeholders = codes.map(() => '?').join(',');
        const rows = await db.prepare(
          `SELECT c.company_id, c.name, c.email, c.phone, c.partner_code, c.partner_code_locked_at, c.created_at,
                  (SELECT COUNT(*) FROM master_staff WHERE master_company_id = c.company_id) AS staff_count,
                  (SELECT COUNT(*) FROM subscriptions WHERE master_company_id = c.company_id AND status = 'active') AS active_subs
             FROM master_companies c
            WHERE c.partner_code IN (${placeholders})
            ORDER BY c.created_at DESC`
        ).bind(...codes).all();

        return json({
          ok: true,
          customers: rows.results || [],
          my_code: p.code,
          is_super: p.type === 'super',
          sub_agent_codes: subAgentCodes  // Phase 4-3e: UI フィルタ用
        }, 200, cors);
      }

      // パートナー代理店一覧（総代理店のみ）
      if (path === '/api/partner/sub-agents' && method === 'GET') {
        const r = await requirePartnerAuth(request, db);
        if (r.error) return json({ error: r.error }, r.status, cors);
        const p = r.partner;
        if (p.type !== 'super') return json({ error: 'forbidden_super_only' }, 403, cors);

        // 各代理店のご紹介先企業数と現行按分率（super→agent scope）をまとめて返す
        const today = todayJSTDate();
        const rows = await db.prepare(
          "SELECT a.partner_id, a.code, a.company_name, a.login_id, a.email, a.phone, " +
          "       a.contract_start_at, a.contract_end_at, a.status, a.created_at, " +
          "       (SELECT COUNT(*) FROM master_companies mc WHERE mc.partner_code = a.code) AS customer_count, " +
          "       (SELECT h.pct FROM partner_revenue_share_history h " +
          "          WHERE h.partner_id = a.partner_id AND h.scope = 'super_to_agent' " +
          "            AND h.parent_partner_id = ? " +
          "            AND h.effective_from <= ? " +
          "            AND (h.effective_to IS NULL OR h.effective_to >= ?) " +
          "          ORDER BY h.effective_from DESC LIMIT 1) AS share_pct " +
          "  FROM partners a " +
          " WHERE a.parent_partner_id = ? " +
          " ORDER BY a.created_at DESC"
        ).bind(p.partner_id, today, today, p.partner_id).all();

        return json({ ok: true, sub_agents: rows.results || [] }, 200, cors);
      }

      // パートナー代理店を新規登録（総代理店のみ）
      if (path === '/api/partner/sub-agents' && method === 'POST') {
        const r = await requirePartnerAuth(request, db);
        if (r.error) return json({ error: r.error }, r.status, cors);
        const p = r.partner;
        if (p.type !== 'super') return json({ error: 'forbidden_super_only' }, 403, cors);

        const b = (await request.json()) || {};
        const { company_name, login_id, password, email, phone } = b;
        if (!company_name || !login_id || !password) {
          return json({ error: 'missing_fields', fields: ['company_name','login_id','password'].filter(k => !b?.[k]) }, 400, cors);
        }
        if (password.length < 8) return json({ error: 'password_too_short' }, 400, cors);
        if (!/^[a-zA-Z0-9_-]{3,40}$/.test(login_id)) {
          return json({ error: 'invalid_login_id' }, 400, cors);
        }
        if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
          return json({ error: 'invalid_email' }, 400, cors);
        }

        // login_id 重複チェック（partners 全体でユニーク）
        const exists = await db.prepare("SELECT 1 FROM partners WHERE login_id = ?").bind(login_id).first();
        if (exists) return json({ error: 'login_id_taken' }, 409, cors);

        const agentId = await nextAgentId(db);
        const passwordHash = await sha256(password);
        const now = nowISO();
        // 代理店の契約期間は登録日から1年（総代理店の残り期間に合わせるロジックはPhase 3c以降で検討）
        const oneYearLater = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString();

        await db.prepare(
          "INSERT INTO partners (partner_id, type, parent_partner_id, company_name, code, login_id, password_hash, " +
          "  email, phone, contract_start_at, contract_end_at, status) " +
          "VALUES (?, 'agent', ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active')"
        ).bind(
          agentId, p.partner_id, company_name, agentId, login_id, passwordHash,
          email || null, phone || null, now, oneYearLater
        ).run();

        await audit(db, 'sub_agent_created', null, p.login_id, {
          parent_partner_id: p.partner_id, new_agent_id: agentId, login_id
        }, request);

        return json({
          ok: true,
          sub_agent: {
            partner_id: agentId,
            code: agentId,
            company_name,
            login_id,
            email: email || null,
            contract_start_at: now,
            contract_end_at: oneYearLater,
            status: 'active'
          }
        }, 200, cors);
      }

      // =============== Phase 4-3a: super→agent 按分率管理 ===============

      // Phase 4-3e: 特定パートナー代理店のご紹介先企業一覧（super のみ）
      const partnerSubCustomersMatch = path.match(/^\/api\/partner\/sub-agents\/([A-Z]{3}-\d{6})\/customers$/);
      if (partnerSubCustomersMatch && method === 'GET') {
        const r = await requirePartnerAuth(request, db);
        if (r.error) return json({ error: r.error }, r.status, cors);
        if (r.partner.type !== 'super') return json({ error: 'forbidden_super_only' }, 403, cors);
        const agentId = partnerSubCustomersMatch[1];

        const agent = await db.prepare(
          "SELECT partner_id, code, company_name, parent_partner_id FROM partners WHERE partner_id = ?"
        ).bind(agentId).first();
        if (!agent) return json({ error: 'partner_not_found' }, 404, cors);
        if (agent.parent_partner_id !== r.partner.partner_id) {
          return json({ error: 'not_your_sub_agent' }, 403, cors);
        }

        const rows = await db.prepare(
          `SELECT c.company_id, c.name, c.email, c.phone, c.partner_code, c.partner_code_locked_at, c.created_at,
                  (SELECT COUNT(*) FROM master_staff WHERE master_company_id = c.company_id) AS staff_count,
                  (SELECT COUNT(*) FROM subscriptions WHERE master_company_id = c.company_id AND status = 'active') AS active_subs
             FROM master_companies c
            WHERE c.partner_code = ?
            ORDER BY c.created_at DESC`
        ).bind(agent.code).all();

        return json({
          ok: true,
          sub_agent: {
            partner_id: agent.partner_id,
            code: agent.code,
            company_name: agent.company_name
          },
          customers: rows.results || []
        }, 200, cors);
      }

      // パートナー代理店の按分率履歴を取得（super のみ）
      const partnerSubShareHistoryMatch = path.match(/^\/api\/partner\/sub-agents\/([A-Z]{3}-\d{6})\/share-history$/);
      if (partnerSubShareHistoryMatch && method === 'GET') {
        const r = await requirePartnerAuth(request, db);
        if (r.error) return json({ error: r.error }, r.status, cors);
        if (r.partner.type !== 'super') return json({ error: 'forbidden_super_only' }, 403, cors);
        const agentId = partnerSubShareHistoryMatch[1];

        const agent = await db.prepare(
          "SELECT partner_id, parent_partner_id, company_name, code FROM partners WHERE partner_id = ?"
        ).bind(agentId).first();
        if (!agent) return json({ error: 'partner_not_found' }, 404, cors);
        if (agent.parent_partner_id !== r.partner.partner_id) {
          return json({ error: 'not_your_sub_agent' }, 403, cors);
        }

        const rows = await db.prepare(
          "SELECT h.id, h.pct, h.effective_from, h.effective_to, h.note, h.created_at, " +
          "       h.set_by_staff_id, h.set_by_partner_id, " +
          "       ms.login_id AS set_by_staff_login, " +
          "       sp.login_id AS set_by_partner_login " +
          "  FROM partner_revenue_share_history h " +
          "  LEFT JOIN master_staff ms ON ms.staff_id = h.set_by_staff_id " +
          "  LEFT JOIN partners sp ON sp.partner_id = h.set_by_partner_id " +
          " WHERE h.partner_id = ? AND h.scope = 'super_to_agent' AND h.parent_partner_id = ? " +
          " ORDER BY h.effective_from DESC, h.id DESC"
        ).bind(agentId, r.partner.partner_id).all();

        const today = todayJSTDate();
        const current = (rows.results || []).find(h =>
          h.effective_from <= today && (!h.effective_to || h.effective_to >= today)
        );

        return json({
          ok: true,
          partner_id: agentId,
          parent_partner_id: r.partner.partner_id,
          scope: 'super_to_agent',
          current_pct: current ? current.pct : null,
          history: (rows.results || []).map(h => ({
            id: h.id,
            pct: h.pct,
            effective_from: h.effective_from,
            effective_to: h.effective_to,
            note: h.note,
            created_at: h.created_at,
            set_by: h.set_by_staff_login || h.set_by_partner_login || null,
            set_by_type: h.set_by_staff_id ? 'staff' : (h.set_by_partner_id ? 'partner' : null)
          }))
        }, 200, cors);
      }

      // パートナー代理店の按分率を変更（super のみ）
      const partnerSubShareSetMatch = path.match(/^\/api\/partner\/sub-agents\/([A-Z]{3}-\d{6})\/share$/);
      if (partnerSubShareSetMatch && method === 'POST') {
        const r = await requirePartnerAuth(request, db);
        if (r.error) return json({ error: r.error }, r.status, cors);
        if (r.partner.type !== 'super') return json({ error: 'forbidden_super_only' }, 403, cors);
        const agentId = partnerSubShareSetMatch[1];

        const agent = await db.prepare(
          "SELECT partner_id, parent_partner_id, company_name, contract_start_at FROM partners WHERE partner_id = ?"
        ).bind(agentId).first();
        if (!agent) return json({ error: 'partner_not_found' }, 404, cors);
        if (agent.parent_partner_id !== r.partner.partner_id) {
          return json({ error: 'not_your_sub_agent' }, 403, cors);
        }

        const b = (await request.json()) || {};
        const pctV = validatePct(b.pct);
        if (!pctV.ok) return json({ error: pctV.error }, 400, cors);
        if (!validateDateYMD(b.effective_from || '')) return json({ error: 'invalid_date' }, 400, cors);
        const note = (b.note || '').toString();
        if (note.length > 500) return json({ error: 'note_too_long' }, 400, cors);

        const newPct = pctV.value;
        const effectiveFrom = b.effective_from;

        // 契約開始日より前の発効不可
        if (agent.contract_start_at) {
          const contractStart = agent.contract_start_at.substring(0, 10);
          if (effectiveFrom < contractStart) {
            return json({ error: 'effective_before_contract', contract_start_at: contractStart }, 400, cors);
          }
        }

        // ★ pct_exceeds_parent_share バリデーション
        // super→agent の pct は、super の tamj_to_super 有効値を超えてはいけない
        const parentShare = await resolveShareHistory(db, r.partner.partner_id, effectiveFrom, 'tamj_to_super', null);
        const parentPct = parentShare ? parentShare.pct : r.partner.revenue_share_pct;
        if (parentPct === null || parentPct === undefined) {
          return json({ error: 'parent_share_not_set' }, 400, cors);
        }
        if (newPct > parentPct) {
          return json({
            error: 'pct_exceeds_parent_share',
            parent_pct: parentPct,
            message: `パートナー代理店への按分率は、自社の取得率（${parentPct}%）を超えて設定できません`
          }, 400, cors);
        }

        // effective_from - 1日 を計算
        const effDate = new Date(effectiveFrom + 'T00:00:00Z');
        const prevDay = new Date(effDate.getTime() - 24 * 60 * 60 * 1000);
        const effectiveToOfOld = prevDay.toISOString().substring(0, 10);

        // 既存レコードで effective_to IS NULL（=現在有効）のものを closing
        const oldRec = await db.prepare(
          "SELECT id, pct FROM partner_revenue_share_history " +
          " WHERE partner_id = ? AND scope = 'super_to_agent' AND parent_partner_id = ? AND effective_to IS NULL " +
          " ORDER BY effective_from DESC LIMIT 1"
        ).bind(agentId, r.partner.partner_id).first();

        const stmts = [];
        if (oldRec) {
          stmts.push(db.prepare(
            "UPDATE partner_revenue_share_history SET effective_to = ? WHERE id = ?"
          ).bind(effectiveToOfOld, oldRec.id));
        }
        stmts.push(db.prepare(
          "INSERT INTO partner_revenue_share_history " +
          "  (partner_id, scope, parent_partner_id, pct, effective_from, effective_to, set_by_partner_id, note) " +
          "VALUES (?, 'super_to_agent', ?, ?, ?, NULL, ?, ?)"
        ).bind(agentId, r.partner.partner_id, newPct, effectiveFrom, r.partner.partner_id, note || null));

        await db.batch(stmts);

        // 新レコードの id を取得
        const inserted = await db.prepare(
          "SELECT id FROM partner_revenue_share_history " +
          " WHERE partner_id = ? AND scope = 'super_to_agent' AND parent_partner_id = ? " +
          "   AND effective_from = ? AND pct = ? " +
          " ORDER BY id DESC LIMIT 1"
        ).bind(agentId, r.partner.partner_id, effectiveFrom, newPct).first();

        await audit(db, 'partner_sub_agent_share_changed', null, r.partner.login_id, {
          partner_id: agentId,
          parent_partner_id: r.partner.partner_id,
          scope: 'super_to_agent',
          old_pct: oldRec ? oldRec.pct : null,
          new_pct: newPct,
          effective_from: effectiveFrom,
          note: note || null
        }, request);

        return json({
          ok: true,
          history_id: inserted?.id || null,
          partner_id: agentId,
          pct: newPct,
          effective_from: effectiveFrom,
          note: note || null
        }, 200, cors);
      }

      // =============== タムジ管理画面（master_staff.role='tamj_admin' 専用） ===============

      // 管理画面サマリー（全体俯瞰）
      if (path === '/api/admin/summary' && method === 'GET') {
        const r = await requireTamjAdmin(request, db);
        if (r.error) return json({ error: r.error }, r.status, cors);

        const rows = await db.batch([
          db.prepare("SELECT COUNT(*) AS cnt FROM partners WHERE type = 'super'"),
          db.prepare("SELECT COUNT(*) AS cnt FROM partners WHERE type = 'super' AND status = 'active'"),
          db.prepare("SELECT COUNT(*) AS cnt FROM partners WHERE type = 'super' AND status = 'pending'"),
          db.prepare("SELECT COUNT(*) AS cnt FROM partners WHERE type = 'agent'"),
          db.prepare("SELECT COUNT(*) AS cnt FROM partners WHERE type = 'agent' AND status = 'active'"),
          db.prepare("SELECT COUNT(*) AS cnt FROM master_companies"),
          db.prepare("SELECT COUNT(*) AS cnt FROM master_companies WHERE partner_code IS NULL"),
          db.prepare("SELECT COUNT(*) AS cnt FROM subscriptions WHERE status = 'active'"),
        ]);
        const [
          supTotal, supActive, supPending,
          agtTotal, agtActive,
          compTotal, compDirect, subsActive
        ] = rows.map(x => x.results?.[0]?.cnt || 0);

        const ym = new Date().toISOString().slice(0, 7);
        const ledger = await db.prepare(
          "SELECT COUNT(*) AS cnt, COALESCE(SUM(gross_amount),0) AS gross, COALESCE(SUM(share_amount),0) AS share, " +
          "       SUM(CASE WHEN status='pending' THEN share_amount ELSE 0 END) AS pending_pay, " +
          "       SUM(CASE WHEN status='paid'    THEN share_amount ELSE 0 END) AS paid " +
          "  FROM revenue_ledger WHERE year_month = ?"
        ).bind(ym).first();

        return json({
          ok: true,
          summary: {
            super_total: supTotal, super_active: supActive, super_pending: supPending,
            agent_total: agtTotal, agent_active: agtActive,
            company_total: compTotal, company_direct: compDirect,
            active_subscription_count: subsActive
          },
          current_month_ledger: {
            year_month: ym,
            entry_count: ledger?.cnt || 0,
            gross_amount: ledger?.gross || 0,
            share_amount: ledger?.share || 0,
            pending_payout: ledger?.pending_pay || 0,
            paid_payout: ledger?.paid || 0
          }
        }, 200, cors);
      }

      // 全代理店（総代理店＋代理店）一覧
      if (path === '/api/admin/partners' && method === 'GET') {
        const r = await requireTamjAdmin(request, db);
        if (r.error) return json({ error: r.error }, r.status, cors);

        const rows = await db.prepare(
          "SELECT p.partner_id, p.type, p.parent_partner_id, p.company_name, p.code, p.login_id, " +
          "       p.email, p.phone, p.contract_start_at, p.contract_end_at, p.status, p.revenue_share_pct, " +
          "       p.created_at, p.auto_end_notified_at, " +
          "       (SELECT COUNT(*) FROM master_companies mc WHERE mc.partner_code = p.code) AS direct_customer_count, " +
          "       (SELECT COUNT(*) FROM partners ap WHERE ap.parent_partner_id = p.partner_id) AS child_agent_count " +
          "  FROM partners p " +
          " ORDER BY p.type ASC, p.created_at DESC"
        ).all();
        return json({ ok: true, partners: rows.results || [] }, 200, cors);
      }

      // =============== Phase 4-3b: 代理店セルフ登録（招待フロー） ===============

      // [admin] 招待作成（admin→super）
      if (path === '/api/admin/partner-invitations' && method === 'POST') {
        const r = await requireTamjAdmin(request, db);
        if (r.error) return json({ error: r.error }, r.status, cors);

        const b = (await request.json()) || {};
        const { invited_email, initial_revenue_share_pct, initial_contract_months, note } = b;
        if (!invited_email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(invited_email)) {
          return json({ error: 'invalid_email' }, 400, cors);
        }
        const pct = initial_revenue_share_pct != null ? Number(initial_revenue_share_pct) : null;
        if (pct != null && (Number.isNaN(pct) || pct < 0 || pct > 100)) {
          return json({ error: 'invalid_pct' }, 400, cors);
        }
        const months = initial_contract_months != null ? Number(initial_contract_months) : 12;
        if (!Number.isInteger(months) || months < 1 || months > 60) {
          return json({ error: 'invalid_months' }, 400, cors);
        }

        const token = randomId(48);
        const expiresAt = new Date(Date.now() + 14 * 24 * 60 * 60 * 1000).toISOString();

        await db.prepare(
          "INSERT INTO partner_invitations " +
          "(token, invited_email, invited_role, initial_revenue_share_pct, initial_contract_months, note, created_by_staff_id, status, expires_at) " +
          "VALUES (?, ?, 'super', ?, ?, ?, ?, 'issued', ?)"
        ).bind(token, invited_email, pct, months, note || null, r.user.staff_id, expiresAt).run();

        const baseUrl = (env.BASE_URL || 'https://adapt.tamjump.com').replace(/\/+$/, '');
        const registerUrl = `${baseUrl}/partner-register.html?token=${token}`;
        try {
          await sendEmail(env, {
            to: invited_email,
            subject: '【Adavoo】総代理店ご登録のご案内 / TAmJ.Corp',
            text:
`この度は Adavoo 総代理店契約にご関心をお寄せいただきありがとうございます。

以下のURLから登録手続きへお進みください。

${registerUrl}

・有効期限: ${new Date(expiresAt).toLocaleString('ja-JP')}（14日間）
・所要時間: 約10〜15分
・ご用意いただくもの: 法人番号・代表者氏名・振込先口座情報

ご不明な点はこのメールにご返信ください。

--
TAmJ.Corp
https://tamjump.com/`
          });
        } catch {}

        await audit(db, 'partner_invitation_created', r.user.staff_id, r.user.login_id, {
          invited_email, invited_role: 'super', pct, months
        }, request);

        return json({ ok: true, token, expires_at: expiresAt, register_url: registerUrl }, 200, cors);
      }

      // [partner/super] 招待作成（super→agent）
      if (path === '/api/partner/invitations' && method === 'POST') {
        const r = await requirePartnerAuth(request, db);
        if (r.error) return json({ error: r.error }, r.status, cors);
        if (r.partner.type !== 'super') return json({ error: 'forbidden_super_only' }, 403, cors);
        if (r.partner.status !== 'active') return json({ error: 'not_active' }, 400, cors);

        const b = (await request.json()) || {};
        const { invited_email, initial_revenue_share_pct, initial_contract_months, note } = b;
        if (!invited_email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(invited_email)) {
          return json({ error: 'invalid_email' }, 400, cors);
        }
        const pct = initial_revenue_share_pct != null ? Number(initial_revenue_share_pct) : null;
        // agentへの按分率は自社取得率を超えられない（super_to_agent scope 前提）
        if (pct != null) {
          if (Number.isNaN(pct) || pct < 0 || pct > 100) return json({ error: 'invalid_pct' }, 400, cors);
          if (r.partner.revenue_share_pct != null && pct > r.partner.revenue_share_pct) {
            return json({ error: 'pct_exceeds_parent_share', parent_pct: r.partner.revenue_share_pct }, 400, cors);
          }
        }
        const months = initial_contract_months != null ? Number(initial_contract_months) : 12;
        if (!Number.isInteger(months) || months < 1 || months > 60) {
          return json({ error: 'invalid_months' }, 400, cors);
        }

        const token = randomId(48);
        const expiresAt = new Date(Date.now() + 14 * 24 * 60 * 60 * 1000).toISOString();

        await db.prepare(
          "INSERT INTO partner_invitations " +
          "(token, invited_email, invited_role, parent_partner_id, initial_revenue_share_pct, initial_contract_months, note, created_by_partner_id, status, expires_at) " +
          "VALUES (?, ?, 'agent', ?, ?, ?, ?, ?, 'issued', ?)"
        ).bind(token, invited_email, r.partner.partner_id, pct, months, note || null, r.partner.partner_id, expiresAt).run();

        const baseUrl = (env.BASE_URL || 'https://adapt.tamjump.com').replace(/\/+$/, '');
        const registerUrl = `${baseUrl}/partner-register.html?token=${token}`;
        try {
          await sendEmail(env, {
            to: invited_email,
            subject: `【Adavoo】代理店ご登録のご案内 / ${r.partner.company_name}`,
            text:
`この度は ${r.partner.company_name} 様経由で Adavoo 代理店契約にご関心をお寄せいただきありがとうございます。

以下のURLから登録手続きへお進みください。

${registerUrl}

・招待元: ${r.partner.company_name}（${r.partner.code}）
・有効期限: ${new Date(expiresAt).toLocaleString('ja-JP')}（14日間）
・所要時間: 約10〜15分

--
TAmJ.Corp`
          });
        } catch {}

        await audit(db, 'partner_invitation_created', null, r.partner.login_id, {
          invited_email, invited_role: 'agent', parent_partner_id: r.partner.partner_id, pct, months
        }, request);

        return json({ ok: true, token, expires_at: expiresAt, register_url: registerUrl }, 200, cors);
      }

      // [admin] 招待一覧
      if (path === '/api/admin/partner-invitations' && method === 'GET') {
        const r = await requireTamjAdmin(request, db);
        if (r.error) return json({ error: r.error }, r.status, cors);

        const rows = await db.prepare(
          "SELECT i.id, i.invited_email, i.invited_role, i.parent_partner_id, " +
          "       i.initial_revenue_share_pct, i.initial_contract_months, i.note, " +
          "       i.status, i.expires_at, i.used_at, i.resulted_partner_id, i.resend_count, " +
          "       i.last_resent_at, i.created_at, " +
          "       s.login_id AS created_by_staff_login, " +
          "       p.company_name AS parent_company_name, " +
          "       rp.company_name AS resulted_company_name " +
          "  FROM partner_invitations i " +
          "  LEFT JOIN master_staff s ON i.created_by_staff_id = s.staff_id " +
          "  LEFT JOIN partners p ON i.parent_partner_id = p.partner_id " +
          "  LEFT JOIN partners rp ON i.resulted_partner_id = rp.partner_id " +
          " ORDER BY i.created_at DESC"
        ).all();
        return json({ ok: true, invitations: rows.results || [] }, 200, cors);
      }

      // [admin] 招待再送（5回まで）
      const resendMatch = path.match(/^\/api\/admin\/partner-invitations\/(\d+)\/resend$/);
      if (resendMatch && method === 'POST') {
        const r = await requireTamjAdmin(request, db);
        if (r.error) return json({ error: r.error }, r.status, cors);
        const id = parseInt(resendMatch[1], 10);

        const inv = await db.prepare(
          "SELECT * FROM partner_invitations WHERE id = ?"
        ).bind(id).first();
        if (!inv) return json({ error: 'invitation_not_found' }, 404, cors);
        if (inv.status !== 'issued') return json({ error: 'invalid_status', current: inv.status }, 400, cors);
        if ((inv.resend_count || 0) >= 5) return json({ error: 'resend_limit_reached' }, 400, cors);

        const baseUrl = (env.BASE_URL || 'https://adapt.tamjump.com').replace(/\/+$/, '');
        const registerUrl = `${baseUrl}/partner-register.html?token=${inv.token}`;
        try {
          await sendEmail(env, {
            to: inv.invited_email,
            subject: '【Adavoo・再送】ご登録のご案内',
            text:
`先日お送りしました登録のご案内を再送いたします。

${registerUrl}

・有効期限: ${new Date(inv.expires_at).toLocaleString('ja-JP')}

--
TAmJ.Corp`
          });
        } catch {}

        await db.prepare(
          "UPDATE partner_invitations SET resend_count = resend_count + 1, last_resent_at = datetime('now') WHERE id = ?"
        ).bind(id).run();

        await audit(db, 'partner_invitation_resent', r.user.staff_id, r.user.login_id, { invitation_id: id }, request);
        return json({ ok: true, resend_count: (inv.resend_count || 0) + 1 }, 200, cors);
      }

      // [admin] 招待失効
      const revokeMatch = path.match(/^\/api\/admin\/partner-invitations\/(\d+)$/);
      if (revokeMatch && method === 'DELETE') {
        const r = await requireTamjAdmin(request, db);
        if (r.error) return json({ error: r.error }, r.status, cors);
        const id = parseInt(revokeMatch[1], 10);

        const inv = await db.prepare("SELECT status FROM partner_invitations WHERE id = ?").bind(id).first();
        if (!inv) return json({ error: 'invitation_not_found' }, 404, cors);
        if (inv.status !== 'issued') return json({ error: 'invalid_status', current: inv.status }, 400, cors);

        await db.prepare(
          "UPDATE partner_invitations SET status = 'revoked' WHERE id = ?"
        ).bind(id).run();

        await audit(db, 'partner_invitation_revoked', r.user.staff_id, r.user.login_id, { invitation_id: id }, request);
        return json({ ok: true }, 200, cors);
      }

      // [public] 招待情報取得（トークンで照会・登録フォーム冒頭）
      if (path === '/api/partner-invitations/info' && method === 'GET') {
        const token = url.searchParams.get('token');
        if (!token) return json({ error: 'missing_token' }, 400, cors);

        const inv = await db.prepare(
          "SELECT i.token, i.invited_email, i.invited_role, i.parent_partner_id, i.initial_contract_months, " +
          "       i.status, i.expires_at, p.company_name AS parent_company_name " +
          "  FROM partner_invitations i " +
          "  LEFT JOIN partners p ON i.parent_partner_id = p.partner_id " +
          " WHERE i.token = ?"
        ).bind(token).first();
        if (!inv) return json({ error: 'invalid_token' }, 404, cors);

        if (inv.status === 'accepted') return json({ error: 'already_accepted' }, 409, cors);
        if (inv.status === 'revoked') return json({ error: 'revoked' }, 410, cors);
        if (inv.status === 'expired' || new Date(inv.expires_at) < new Date()) {
          // 自動で expired に遷移（Cron と同等処理）
          if (inv.status === 'issued') {
            await db.prepare("UPDATE partner_invitations SET status = 'expired' WHERE token = ?").bind(token).run();
          }
          return json({ error: 'expired', expires_at: inv.expires_at }, 410, cors);
        }

        return json({
          ok: true,
          invitation: {
            invited_email: inv.invited_email,
            invited_role: inv.invited_role,
            parent_partner_id: inv.parent_partner_id,
            parent_company_name: inv.parent_company_name,
            initial_contract_months: inv.initial_contract_months,
            expires_at: inv.expires_at
          }
        }, 200, cors);
      }

      // [public] 法人番号 国税庁API 照会
      if (path === '/api/partner-invitations/verify-corporate-number' && method === 'POST') {
        const b = (await request.json()) || {};
        const { token, corporate_number } = b;
        if (!token) return json({ error: 'missing_token' }, 400, cors);
        if (!corporate_number) return json({ error: 'missing_corporate_number' }, 400, cors);

        // トークン最小検証（DoS対策）
        const inv = await db.prepare(
          "SELECT status, expires_at FROM partner_invitations WHERE token = ?"
        ).bind(token).first();
        if (!inv) return json({ error: 'invalid_token' }, 404, cors);
        if (inv.status !== 'issued') return json({ error: 'invalid_status', current: inv.status }, 400, cors);
        if (new Date(inv.expires_at) < new Date()) return json({ error: 'expired' }, 410, cors);

        // チェックデジット検証
        if (!isValidCorporateNumber(corporate_number)) {
          return json({ ok: false, error: 'invalid_check_digit' }, 400, cors);
        }

        const result = await verifyCorporateNumber(corporate_number, env);
        return json(result, result.ok ? 200 : 400, cors);
      }

      // [public] 登録完了（全情報 POST → partners に pending で INSERT）
      if (path === '/api/partner-invitations/accept' && method === 'POST') {
        const b = (await request.json()) || {};
        const {
          token, corporate_number,
          company_name, company_name_kana,
          representative_name, representative_name_kana,
          hq_postal_code, hq_prefecture, hq_city, hq_street, hq_phone,
          industry_code, founded_on, capital,
          contact_name, contact_name_kana, contact_email, contact_phone,
          bank_info,
          login_id, password,
          consents // { terms, antisocial, privacy, agreement } 全て true 必須
        } = b;

        if (!token) return json({ error: 'missing_token' }, 400, cors);

        // トークン検証
        const inv = await db.prepare(
          "SELECT * FROM partner_invitations WHERE token = ?"
        ).bind(token).first();
        if (!inv) return json({ error: 'invalid_token' }, 404, cors);
        if (inv.status !== 'issued') return json({ error: 'invalid_status', current: inv.status }, 400, cors);
        if (new Date(inv.expires_at) < new Date()) return json({ error: 'expired' }, 410, cors);

        // 必須チェック
        const missing = [];
        const req = {
          company_name, company_name_kana,
          representative_name, representative_name_kana,
          hq_postal_code, hq_prefecture, hq_city, hq_street, hq_phone,
          industry_code, founded_on, capital,
          contact_name, contact_name_kana, contact_email, contact_phone,
          bank_info, login_id, password, corporate_number
        };
        for (const [k, v] of Object.entries(req)) {
          if (v === undefined || v === null || v === '') missing.push(k);
        }
        if (missing.length > 0) return json({ error: 'missing_fields', fields: missing }, 400, cors);

        // 各種バリデーション
        if (!isValidCorporateNumber(corporate_number)) return json({ error: 'invalid_corporate_number' }, 400, cors);
        if (typeof company_name !== 'string' || company_name.length < 1 || company_name.length > 100) return json({ error: 'invalid_company_name' }, 400, cors);
        if (!validateKana(company_name_kana)) return json({ error: 'invalid_company_name_kana' }, 400, cors);
        if (!validateKana(representative_name_kana)) return json({ error: 'invalid_representative_name_kana' }, 400, cors);
        if (!validatePostalCode(hq_postal_code)) return json({ error: 'invalid_postal_code' }, 400, cors);
        if (!validateJPPhone(hq_phone)) return json({ error: 'invalid_hq_phone' }, 400, cors);
        if (!validateJPPhone(contact_phone)) return json({ error: 'invalid_contact_phone' }, 400, cors);
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(contact_email)) return json({ error: 'invalid_contact_email' }, 400, cors);
        if (!/^\d{4}-(0[1-9]|1[0-2])$/.test(founded_on)) return json({ error: 'invalid_founded_on' }, 400, cors);
        const cap = Number(capital);
        if (!Number.isInteger(cap) || cap < 1 || cap > 10_000_000_000) return json({ error: 'invalid_capital' }, 400, cors);
        if (!/^[A-Za-z0-9_-]{3,40}$/.test(login_id)) return json({ error: 'invalid_login_id' }, 400, cors);
        if (typeof password !== 'string' || password.length < 8) return json({ error: 'password_too_short' }, 400, cors);

        // 銀行情報
        if (typeof bank_info !== 'object' || !bank_info) return json({ error: 'invalid_bank_info' }, 400, cors);
        const bi = bank_info;
        if (!bi.bank_name || !bi.branch_name || !bi.account_type || !bi.account_number || !bi.account_holder) {
          return json({ error: 'invalid_bank_info', missing: ['bank_name','branch_name','account_type','account_number','account_holder'].filter(k => !bi[k]) }, 400, cors);
        }
        if (!['普通','当座','貯蓄','ordinary','checking'].includes(bi.account_type)) return json({ error: 'invalid_account_type' }, 400, cors);
        if (!/^\d{4,10}$/.test(bi.account_number)) return json({ error: 'invalid_account_number' }, 400, cors);

        // 同意
        if (!consents || !consents.terms || !consents.antisocial || !consents.privacy || !consents.agreement) {
          return json({ error: 'consent_required' }, 400, cors);
        }

        // ログインID重複チェック
        const dup = await db.prepare("SELECT partner_id FROM partners WHERE login_id = ?").bind(login_id).first();
        if (dup) return json({ error: 'login_id_taken' }, 409, cors);

        // 法人番号の再確認（国税庁API・mock でも可）
        const ntaResult = await verifyCorporateNumber(corporate_number, env);
        if (!ntaResult.ok && ntaResult.error !== 'api_not_configured') {
          return json({ error: 'nta_verification_failed', detail: ntaResult.error }, 400, cors);
        }

        // partner_id 生成
        let partnerId;
        if (inv.invited_role === 'super') {
          partnerId = await nextSuperId(db);
        } else {
          // AGT-XXXXXX
          const row = await db.prepare(
            "SELECT partner_id FROM partners WHERE type='agent' AND partner_id LIKE 'AGT-%' ORDER BY partner_id DESC LIMIT 1"
          ).first();
          const n = row ? parseInt(row.partner_id.replace('AGT-', ''), 10) + 1 : 1;
          partnerId = 'AGT-' + String(n).padStart(6, '0');
        }
        // コード生成（admin 登録と同じロジック）
        const codePrefix = inv.invited_role === 'super' ? 'SUP' : 'AGT';
        const codeSuffix = randomId(6).toUpperCase();
        const code = `${codePrefix}-${codeSuffix}`;

        // パスワードハッシュ
        const pwHash = await sha256(password);

        // 契約期間
        const nowIso = nowISO();
        const contractEnd = new Date(Date.now() + (inv.initial_contract_months || 12) * 30 * 24 * 60 * 60 * 1000).toISOString();

        // 振込先JSON正規化
        const cleanedBank = {
          bank_name: bi.bank_name,
          bank_code: bi.bank_code || null,
          branch_name: bi.branch_name,
          branch_code: bi.branch_code || null,
          account_type: bi.account_type,
          account_number: bi.account_number,
          account_holder: bi.account_holder,
          memo: bi.memo || null
        };

        // INSERT
        await db.prepare(
          "INSERT INTO partners " +
          "(partner_id, type, parent_partner_id, company_name, company_name_kana, corporate_number, " +
          " representative_name, representative_name_kana, " +
          " hq_postal_code, hq_prefecture, hq_city, hq_street, hq_phone, " +
          " industry_code, founded_on, capital, " +
          " contact_name, contact_name_kana, contact_email, contact_phone, " +
          " bank_info_json, corporate_number_verified_at, corporate_number_api_result, " +
          " code, login_id, password_hash, email, phone, " +
          " contract_start_at, contract_end_at, revenue_share_pct, status, created_at, updated_at) " +
          "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', datetime('now'), datetime('now'))"
        ).bind(
          partnerId,
          inv.invited_role,
          inv.parent_partner_id || null,
          company_name,
          company_name_kana,
          corporate_number,
          representative_name,
          representative_name_kana,
          hq_postal_code,
          hq_prefecture,
          hq_city,
          hq_street,
          hq_phone,
          industry_code,
          founded_on,
          cap,
          contact_name,
          contact_name_kana,
          contact_email,
          contact_phone,
          JSON.stringify(cleanedBank),
          ntaResult.ok ? nowIso : null,
          ntaResult.ok ? JSON.stringify(ntaResult) : null,
          code,
          login_id,
          pwHash,
          contact_email,
          contact_phone,
          nowIso,
          contractEnd,
          inv.initial_revenue_share_pct
        ).run();

        // 招待を accepted に遷移
        await db.prepare(
          "UPDATE partner_invitations SET status='accepted', used_at=datetime('now'), resulted_partner_id=? WHERE id=?"
        ).bind(partnerId, inv.id).run();

        // 同意記録を保存（4種）
        const ip = request.headers.get('cf-connecting-ip') || request.headers.get('x-forwarded-for') || null;
        const ua = request.headers.get('user-agent') || null;
        for (const [dt, v] of Object.entries({
          terms: 'v1.0',
          antisocial: 'v1.0',
          privacy: 'v1.0',
          agreement: 'v1.0'
        })) {
          await db.prepare(
            "INSERT INTO consent_records (partner_id, invitation_token, document_type, document_version, ip_address, user_agent) " +
            "VALUES (?, ?, ?, ?, ?, ?)"
          ).bind(partnerId, token, dt, v, ip, ua).run();
        }

        await audit(db, 'partner_self_registered', null, login_id, {
          partner_id: partnerId,
          invitation_id: inv.id,
          invited_role: inv.invited_role,
          parent_partner_id: inv.parent_partner_id
        }, request);

        // 承認依頼通知（admin または親 super に）
        try {
          if (inv.invited_role === 'super') {
            // タムジ社（ADMIN_NOTIFY_EMAIL）に通知
            const adminEmail = env.ADMIN_NOTIFY_EMAIL || 'info@tamjump.com';
            await sendEmail(env, {
              to: adminEmail,
              subject: `【Adavoo】総代理店の新規登録申請: ${company_name}`,
              text:
`総代理店の新規登録申請が届きました。

会社名: ${company_name}
法人番号: ${corporate_number}
代表者: ${representative_name}
担当者: ${contact_name} <${contact_email}>
partner_id: ${partnerId}

管理画面で承認/却下の処理をお願いします。
${(env.BASE_URL || 'https://adapt.tamjump.com').replace(/\/+$/, '')}/admin-dashboard.html`
            });
          } else if (inv.parent_partner_id) {
            // 親 super に通知
            const parent = await db.prepare(
              "SELECT email, company_name FROM partners WHERE partner_id = ?"
            ).bind(inv.parent_partner_id).first();
            if (parent?.email) {
              await sendEmail(env, {
                to: parent.email,
                subject: `【Adavoo】代理店の新規登録申請: ${company_name}`,
                text:
`${parent.company_name} 様

貴社経由の代理店登録申請が届きました。

会社名: ${company_name}
法人番号: ${corporate_number}
担当者: ${contact_name} <${contact_email}>

タムジ社による承認をお待ちください。

--
TAmJ.Corp`
              });
            }
          }
        } catch {}

        return json({
          ok: true,
          partner_id: partnerId,
          status: 'pending',
          message: 'ご登録ありがとうございました。弊社にて内容確認の上、3営業日以内に ' + contact_email + ' 宛に承認可否をご連絡します。'
        }, 200, cors);
      }

      // [admin] 却下（既存 /approve エンドポイントで承認は代替可能だが、却下は新規）
      const rejectPendingMatch = path.match(/^\/api\/admin\/partners\/([A-Z]{3}-\d{6})\/reject$/);
      if (rejectPendingMatch && method === 'POST') {
        const r = await requireTamjAdmin(request, db);
        if (r.error) return json({ error: r.error }, r.status, cors);
        const partnerId = rejectPendingMatch[1];

        const p = await db.prepare(
          "SELECT partner_id, status, contact_email, company_name FROM partners WHERE partner_id = ?"
        ).bind(partnerId).first();
        if (!p) return json({ error: 'partner_not_found' }, 404, cors);
        if (p.status !== 'pending') return json({ error: 'not_pending', current: p.status }, 400, cors);

        const b = (await request.json().catch(() => ({}))) || {};
        const reason = (b.reason || '').toString().slice(0, 500);

        await db.prepare(
          "UPDATE partners SET status='rejected', rejected_at=datetime('now'), rejection_reason=?, updated_at=datetime('now') WHERE partner_id=?"
        ).bind(reason || null, partnerId).run();

        await audit(db, 'admin_partner_rejected', r.user.staff_id, r.user.login_id, {
          partner_id: partnerId, reason: reason || null
        }, request);

        try {
          if (p.contact_email) {
            await sendEmail(env, {
              to: p.contact_email,
              subject: `【Adavoo】ご登録申請について / ${p.company_name}`,
              text:
`${p.company_name} 様

ご登録申請につきまして、誠に申し訳ございませんが今回はご見送りとさせていただきます。
${reason ? '\n理由:\n' + reason + '\n' : ''}
ご不明な点はタムジ社（info@tamjump.com）までお問合せください。

--
TAmJ.Corp`
            });
          }
        } catch {}

        return json({ ok: true, partner_id: partnerId }, 200, cors);
      }

      // 総代理店を新規登録（status='pending' で登録、後で承認）
      if (path === '/api/admin/partners' && method === 'POST') {
        const r = await requireTamjAdmin(request, db);
        if (r.error) return json({ error: r.error }, r.status, cors);

        const b = (await request.json()) || {};
        const { company_name, login_id, password, email, phone, revenue_share_pct, bank_info } = b;
        if (!company_name || !login_id || !password) {
          return json({ error: 'missing_fields', fields: ['company_name','login_id','password'].filter(k => !b?.[k]) }, 400, cors);
        }
        if (password.length < 8) return json({ error: 'password_too_short' }, 400, cors);
        if (!/^[a-zA-Z0-9_-]{3,40}$/.test(login_id)) return json({ error: 'invalid_login_id' }, 400, cors);
        if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return json({ error: 'invalid_email' }, 400, cors);

        const sharePct = (revenue_share_pct === null || revenue_share_pct === undefined || revenue_share_pct === '')
          ? null
          : Number(revenue_share_pct);
        if (sharePct !== null && (Number.isNaN(sharePct) || sharePct < 0 || sharePct > 100)) {
          return json({ error: 'invalid_share_pct' }, 400, cors);
        }

        const exists = await db.prepare("SELECT 1 FROM partners WHERE login_id = ?").bind(login_id).first();
        if (exists) return json({ error: 'login_id_taken' }, 409, cors);

        const supId = await nextSuperId(db);
        const passwordHash = await sha256(password);
        const bankJson = bank_info ? JSON.stringify(bank_info) : null;

        // 登録時は status='pending' (契約日はまだセットしない=承認時に確定)
        await db.prepare(
          "INSERT INTO partners (partner_id, type, parent_partner_id, company_name, code, login_id, password_hash, " +
          "  email, phone, status, revenue_share_pct, bank_info_json) " +
          "VALUES (?, 'super', NULL, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)"
        ).bind(
          supId, company_name, supId, login_id, passwordHash,
          email || null, phone || null, sharePct, bankJson
        ).run();

        await audit(db, 'admin_super_created', r.user.staff_id, r.user.login_id, {
          new_partner_id: supId, login_id
        }, request);

        return json({
          ok: true,
          super_partner: {
            partner_id: supId, code: supId, company_name, login_id,
            email: email || null, status: 'pending',
            revenue_share_pct: sharePct
          }
        }, 200, cors);
      }

      // 総代理店を承認（status: 'pending' → 'active'、契約期間確定）
      const approveMatch = path.match(/^\/api\/admin\/partners\/([A-Z]{3}-\d{6})\/approve$/);
      if (approveMatch && method === 'POST') {
        const r = await requireTamjAdmin(request, db);
        if (r.error) return json({ error: r.error }, r.status, cors);
        const partnerId = approveMatch[1];

        const p = await db.prepare("SELECT * FROM partners WHERE partner_id = ?").bind(partnerId).first();
        if (!p) return json({ error: 'partner_not_found' }, 404, cors);
        if (p.status !== 'pending') return json({ error: 'not_pending', current_status: p.status }, 409, cors);

        const now = nowISO();
        const oneYearLater = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString();
        await db.prepare(
          "UPDATE partners SET status = 'active', contract_start_at = ?, contract_end_at = ?, " +
          "  auto_end_notified_at = NULL, updated_at = datetime('now') WHERE partner_id = ?"
        ).bind(now, oneYearLater, partnerId).run();

        await audit(db, 'admin_partner_approved', r.user.staff_id, r.user.login_id, {
          partner_id: partnerId, contract_start_at: now, contract_end_at: oneYearLater
        }, request);

        return json({
          ok: true,
          partner: { partner_id: partnerId, status: 'active', contract_start_at: now, contract_end_at: oneYearLater }
        }, 200, cors);
      }

      // =============== Phase 4-3d: タムジ側 契約申請の承認 ===============

      // 保留中申請一覧
      if (path === '/api/admin/renewal-requests' && method === 'GET') {
        const r = await requireTamjAdmin(request, db);
        if (r.error) return json({ error: r.error }, r.status, cors);

        const rows = await db.prepare(
          "SELECT partner_id, type, company_name, code, email, contract_start_at, contract_end_at, " +
          "       status, renewal_requested_at, renewal_note, terminate_requested_at, terminate_note, " +
          "       last_renewal_approved_at " +
          "  FROM partners " +
          " WHERE renewal_requested_at IS NOT NULL OR terminate_requested_at IS NOT NULL " +
          " ORDER BY COALESCE(renewal_requested_at, terminate_requested_at) ASC"
        ).all();

        return json({ ok: true, requests: rows.results || [] }, 200, cors);
      }

      // 継続申請の承認（契約期間を +1年）
      const adminApproveRenewalMatch = path.match(/^\/api\/admin\/partners\/([A-Z]{3}-\d{6})\/approve-renewal$/);
      if (adminApproveRenewalMatch && method === 'POST') {
        const r = await requireTamjAdmin(request, db);
        if (r.error) return json({ error: r.error }, r.status, cors);
        const partnerId = adminApproveRenewalMatch[1];

        const p = await db.prepare(
          "SELECT partner_id, contract_end_at, renewal_requested_at FROM partners WHERE partner_id = ?"
        ).bind(partnerId).first();
        if (!p) return json({ error: 'partner_not_found' }, 404, cors);
        if (!p.renewal_requested_at) return json({ error: 'no_pending_renewal' }, 400, cors);

        // 現在の契約終了日 or 今日の遅い方から +1年
        const now = new Date();
        const currentEnd = p.contract_end_at ? new Date(p.contract_end_at) : now;
        const base = currentEnd > now ? currentEnd : now;
        const newEnd = new Date(base.getTime() + 365 * 24 * 60 * 60 * 1000).toISOString();

        await db.prepare(
          "UPDATE partners SET " +
          "  contract_end_at = ?, " +
          "  renewal_requested_at = NULL, " +
          "  renewal_note = NULL, " +
          "  last_renewal_approved_at = datetime('now'), " +
          "  auto_end_notified_at = NULL, " + // 新契約期間で通知をリセット
          "  status = 'active', " +
          "  updated_at = datetime('now') " +
          "WHERE partner_id = ?"
        ).bind(newEnd, partnerId).run();

        await audit(db, 'admin_renewal_approved', r.user.staff_id, r.user.login_id, {
          partner_id: partnerId,
          old_contract_end_at: p.contract_end_at,
          new_contract_end_at: newEnd
        }, request);

        // 承認通知メール送信
        try {
          const pInfo = await db.prepare(
            "SELECT company_name, email, type FROM partners WHERE partner_id = ?"
          ).bind(partnerId).first();
          if (pInfo?.email) {
            const typeLabel = pInfo.type === 'super' ? '総代理店' : '代理店';
            const endDate = new Date(newEnd).toLocaleDateString('ja-JP');
            await sendEmail(env, {
              to: pInfo.email,
              subject: `【Adavoo】契約継続のご承認 / ${pInfo.company_name} 様`,
              text:
`${pInfo.company_name} 様

${typeLabel}契約の継続申請をご承認いたしました。
新しい契約終了予定日: ${endDate}

引き続き Adavoo をよろしくお願いいたします。

--
TAmJ.Corp
https://tamjump.com/`
            });
          }
        } catch {}

        return json({
          ok: true,
          partner_id: partnerId,
          new_contract_end_at: newEnd,
          message: '継続を承認しました。契約期間を1年延長しました。'
        }, 200, cors);
      }

      // 継続申請の却下
      const adminRejectRenewalMatch = path.match(/^\/api\/admin\/partners\/([A-Z]{3}-\d{6})\/reject-renewal$/);
      if (adminRejectRenewalMatch && method === 'POST') {
        const r = await requireTamjAdmin(request, db);
        if (r.error) return json({ error: r.error }, r.status, cors);
        const partnerId = adminRejectRenewalMatch[1];

        const p = await db.prepare(
          "SELECT partner_id, company_name, email, type, renewal_requested_at FROM partners WHERE partner_id = ?"
        ).bind(partnerId).first();
        if (!p) return json({ error: 'partner_not_found' }, 404, cors);
        if (!p.renewal_requested_at) return json({ error: 'no_pending_renewal' }, 400, cors);

        const b = (await request.json().catch(() => ({}))) || {};
        const reason = (b.reason || '').toString().slice(0, 500);

        await db.prepare(
          "UPDATE partners SET renewal_requested_at = NULL, renewal_note = NULL, updated_at = datetime('now') WHERE partner_id = ?"
        ).bind(partnerId).run();

        await audit(db, 'admin_renewal_rejected', r.user.staff_id, r.user.login_id, {
          partner_id: partnerId,
          reason: reason || null
        }, request);

        try {
          if (p.email) {
            const typeLabel = p.type === 'super' ? '総代理店' : '代理店';
            await sendEmail(env, {
              to: p.email,
              subject: `【Adavoo】継続申請について / ${p.company_name} 様`,
              text:
`${p.company_name} 様

${typeLabel}契約の継続申請につきまして、誠に申し訳ございませんが今回はご見送りとさせていただきます。
${reason ? '\n理由:\n' + reason + '\n' : ''}
詳細につきましてはタムジ社（info@tamjump.com）までお問合せください。

--
TAmJ.Corp`
            });
          }
        } catch {}

        return json({ ok: true, partner_id: partnerId }, 200, cors);
      }

      // 終了申請の承認（契約終了）
      const adminApproveTerminateMatch = path.match(/^\/api\/admin\/partners\/([A-Z]{3}-\d{6})\/approve-terminate$/);
      if (adminApproveTerminateMatch && method === 'POST') {
        const r = await requireTamjAdmin(request, db);
        if (r.error) return json({ error: r.error }, r.status, cors);
        const partnerId = adminApproveTerminateMatch[1];

        const p = await db.prepare(
          "SELECT partner_id, company_name, email, type, terminate_requested_at FROM partners WHERE partner_id = ?"
        ).bind(partnerId).first();
        if (!p) return json({ error: 'partner_not_found' }, 404, cors);
        if (!p.terminate_requested_at) return json({ error: 'no_pending_terminate' }, 400, cors);

        const nowIso = nowISO();
        await db.batch([
          db.prepare(
            "UPDATE partners SET " +
            "  status = 'terminated', " +
            "  contract_end_at = ?, " +
            "  terminate_requested_at = NULL, " +
            "  terminate_note = NULL, " +
            "  updated_at = datetime('now') " +
            "WHERE partner_id = ?"
          ).bind(nowIso, partnerId),
          // 既存セッション全消し（即ログアウト）
          db.prepare("DELETE FROM partner_sessions WHERE partner_id = ?").bind(partnerId)
        ]);

        await audit(db, 'admin_terminate_approved', r.user.staff_id, r.user.login_id, {
          partner_id: partnerId,
          terminated_at: nowIso
        }, request);

        try {
          if (p.email) {
            const typeLabel = p.type === 'super' ? '総代理店' : '代理店';
            await sendEmail(env, {
              to: p.email,
              subject: `【Adavoo】契約終了のご連絡 / ${p.company_name} 様`,
              text:
`${p.company_name} 様

${typeLabel}契約を終了いたしました。
これまでのご利用、誠にありがとうございました。

--
TAmJ.Corp`
            });
          }
        } catch {}

        return json({ ok: true, partner_id: partnerId, terminated_at: nowIso }, 200, cors);
      }

      // 終了申請の却下
      const adminRejectTerminateMatch = path.match(/^\/api\/admin\/partners\/([A-Z]{3}-\d{6})\/reject-terminate$/);
      if (adminRejectTerminateMatch && method === 'POST') {
        const r = await requireTamjAdmin(request, db);
        if (r.error) return json({ error: r.error }, r.status, cors);
        const partnerId = adminRejectTerminateMatch[1];

        const p = await db.prepare(
          "SELECT partner_id, company_name, email, type, terminate_requested_at FROM partners WHERE partner_id = ?"
        ).bind(partnerId).first();
        if (!p) return json({ error: 'partner_not_found' }, 404, cors);
        if (!p.terminate_requested_at) return json({ error: 'no_pending_terminate' }, 400, cors);

        const b = (await request.json().catch(() => ({}))) || {};
        const reason = (b.reason || '').toString().slice(0, 500);

        await db.prepare(
          "UPDATE partners SET terminate_requested_at = NULL, terminate_note = NULL, updated_at = datetime('now') WHERE partner_id = ?"
        ).bind(partnerId).run();

        await audit(db, 'admin_terminate_rejected', r.user.staff_id, r.user.login_id, {
          partner_id: partnerId,
          reason: reason || null
        }, request);

        try {
          if (p.email) {
            const typeLabel = p.type === 'super' ? '総代理店' : '代理店';
            await sendEmail(env, {
              to: p.email,
              subject: `【Adavoo】契約終了申請について / ${p.company_name} 様`,
              text:
`${p.company_name} 様

${typeLabel}契約の終了申請につきまして、以下の理由により保留とさせていただきます。
${reason ? '\n理由:\n' + reason + '\n' : ''}
ご不明な点はタムジ社（info@tamjump.com）までご連絡ください。

--
TAmJ.Corp`
            });
          }
        } catch {}

        return json({ ok: true, partner_id: partnerId }, 200, cors);
      }

      // =============== Phase 4-3a: タムジ→総代理店 按分率管理 ===============

      // 総代理店詳細ドリルダウン（Phase 4-3e）
      const adminPartnerDetailMatch = path.match(/^\/api\/admin\/partners\/([A-Z]{3}-\d{6})\/detail$/);
      if (adminPartnerDetailMatch && method === 'GET') {
        const r = await requireTamjAdmin(request, db);
        if (r.error) return json({ error: r.error }, r.status, cors);
        const partnerId = adminPartnerDetailMatch[1];

        // 基本情報
        const partner = await db.prepare(
          "SELECT p.partner_id, p.type, p.parent_partner_id, p.company_name, p.code, p.login_id, " +
          "       p.email, p.phone, p.contract_start_at, p.contract_end_at, p.status, p.revenue_share_pct, " +
          "       p.bank_info_json, p.created_at, p.updated_at " +
          "  FROM partners p WHERE p.partner_id = ?"
        ).bind(partnerId).first();
        if (!partner) return json({ error: 'partner_not_found' }, 404, cors);

        let bankInfo = null;
        try { bankInfo = partner.bank_info_json ? JSON.parse(partner.bank_info_json) : null; } catch {}

        // 対象 partner_code 群を決める（super の場合は自 + パートナー代理店）
        const isSuper = partner.type === 'super';
        let ownerCodes = [partner.code];
        let subAgents = [];

        if (isSuper) {
          const subRows = await db.prepare(
            "SELECT a.partner_id, a.code, a.company_name, a.login_id, a.email, " +
            "       a.contract_start_at, a.contract_end_at, a.status, " +
            "       (SELECT COUNT(*) FROM master_companies mc WHERE mc.partner_code = a.code) AS customer_count " +
            "  FROM partners a WHERE a.parent_partner_id = ? ORDER BY a.created_at DESC"
          ).bind(partnerId).all();
          subAgents = subRows.results || [];
          for (const sa of subAgents) ownerCodes.push(sa.code);
        }

        // ご紹介先企業一覧（partner_code で紐付く master_companies）
        const placeholders = ownerCodes.map(() => '?').join(',');
        const customersRes = await db.prepare(
          "SELECT mc.company_id, mc.name, mc.email, mc.phone, mc.status, " +
          "       mc.partner_code, mc.created_at, " +
          "       (SELECT COUNT(*) FROM users u WHERE u.org_id = mc.company_id) AS staff_count, " +
          "       (SELECT COUNT(*) FROM subscriptions s " +
          "         WHERE s.master_company_id = mc.company_id AND s.status = 'active') AS active_subs " +
          "  FROM master_companies mc " +
          " WHERE mc.partner_code IN (" + placeholders + ") " +
          " ORDER BY mc.created_at DESC"
        ).bind(...ownerCodes).all();

        // 月別売上推移（直近12ヶ月・partner_code = partner.code の分のみ=タムジ視点）
        const monthlyRevenue = isSuper ? await db.prepare(
          "SELECT year_month, " +
          "       COALESCE(SUM(gross_amount),0) AS gross_amount, " +
          "       COALESCE(SUM(share_amount),0) AS share_amount, " +
          "       SUM(CASE WHEN status='paid' THEN share_amount ELSE 0 END) AS paid_amount, " +
          "       SUM(CASE WHEN status='pending' THEN share_amount ELSE 0 END) AS pending_amount, " +
          "       COUNT(*) AS entry_count " +
          "  FROM revenue_ledger WHERE partner_code = ? " +
          " GROUP BY year_month ORDER BY year_month DESC LIMIT 12"
        ).bind(partner.code).all() : { results: [] };

        // 台帳サマリー（総額）
        const ledgerSummary = isSuper ? await db.prepare(
          "SELECT " +
          "  COUNT(*) AS total_entries, " +
          "  COALESCE(SUM(share_amount),0) AS total_share, " +
          "  SUM(CASE WHEN status='paid'    THEN share_amount ELSE 0 END) AS paid_total, " +
          "  SUM(CASE WHEN status='pending' THEN share_amount ELSE 0 END) AS pending_total " +
          "  FROM revenue_ledger WHERE partner_code = ?"
        ).bind(partner.code).first() : null;

        return json({
          ok: true,
          partner: {
            partner_id: partner.partner_id,
            type: partner.type,
            parent_partner_id: partner.parent_partner_id,
            company_name: partner.company_name,
            code: partner.code,
            login_id: partner.login_id,
            email: partner.email,
            phone: partner.phone,
            contract_start_at: partner.contract_start_at,
            contract_end_at: partner.contract_end_at,
            status: partner.status,
            revenue_share_pct: partner.revenue_share_pct,
            bank_info: bankInfo,
            created_at: partner.created_at,
            updated_at: partner.updated_at
          },
          sub_agents: subAgents,
          customers: customersRes.results || [],
          monthly_revenue: (monthlyRevenue.results || []).reverse(), // 古→新
          ledger_summary: ledgerSummary || null
        }, 200, cors);
      }

      // 総代理店の按分率履歴を取得
      const adminShareHistoryMatch = path.match(/^\/api\/admin\/partners\/([A-Z]{3}-\d{6})\/share-history$/);
      if (adminShareHistoryMatch && method === 'GET') {
        const r = await requireTamjAdmin(request, db);
        if (r.error) return json({ error: r.error }, r.status, cors);
        const partnerId = adminShareHistoryMatch[1];

        const p = await db.prepare(
          "SELECT partner_id, type, company_name, code, revenue_share_pct FROM partners WHERE partner_id = ?"
        ).bind(partnerId).first();
        if (!p) return json({ error: 'partner_not_found' }, 404, cors);
        if (p.type !== 'super') return json({ error: 'not_super' }, 400, cors);

        const rows = await db.prepare(
          "SELECT h.id, h.pct, h.effective_from, h.effective_to, h.note, h.created_at, " +
          "       h.set_by_staff_id, h.set_by_partner_id, " +
          "       ms.login_id AS set_by_staff_login, " +
          "       sp.login_id AS set_by_partner_login " +
          "  FROM partner_revenue_share_history h " +
          "  LEFT JOIN master_staff ms ON ms.staff_id = h.set_by_staff_id " +
          "  LEFT JOIN partners sp ON sp.partner_id = h.set_by_partner_id " +
          " WHERE h.partner_id = ? AND h.scope = 'tamj_to_super' " +
          " ORDER BY h.effective_from DESC, h.id DESC"
        ).bind(partnerId).all();

        return json({
          ok: true,
          partner_id: partnerId,
          scope: 'tamj_to_super',
          current_pct: p.revenue_share_pct,
          history: (rows.results || []).map(h => ({
            id: h.id,
            pct: h.pct,
            effective_from: h.effective_from,
            effective_to: h.effective_to,
            note: h.note,
            created_at: h.created_at,
            set_by: h.set_by_staff_login || h.set_by_partner_login || null,
            set_by_type: h.set_by_staff_id ? 'staff' : (h.set_by_partner_id ? 'partner' : null)
          }))
        }, 200, cors);
      }

      // 総代理店の按分率を変更
      const adminShareSetMatch = path.match(/^\/api\/admin\/partners\/([A-Z]{3}-\d{6})\/share$/);
      if (adminShareSetMatch && method === 'POST') {
        const r = await requireTamjAdmin(request, db);
        if (r.error) return json({ error: r.error }, r.status, cors);
        const partnerId = adminShareSetMatch[1];

        const p = await db.prepare(
          "SELECT partner_id, type, contract_start_at FROM partners WHERE partner_id = ?"
        ).bind(partnerId).first();
        if (!p) return json({ error: 'partner_not_found' }, 404, cors);
        if (p.type !== 'super') return json({ error: 'not_super' }, 400, cors);

        const b = (await request.json()) || {};
        const pctV = validatePct(b.pct);
        if (!pctV.ok) return json({ error: pctV.error }, 400, cors);
        if (!validateDateYMD(b.effective_from || '')) return json({ error: 'invalid_date' }, 400, cors);
        const note = (b.note || '').toString();
        if (note.length > 500) return json({ error: 'note_too_long' }, 400, cors);

        const newPct = pctV.value;
        const effectiveFrom = b.effective_from;
        const today = todayJSTDate();

        // 契約開始日より前の発効不可
        if (p.contract_start_at) {
          const contractStart = p.contract_start_at.substring(0, 10);
          if (effectiveFrom < contractStart) {
            return json({ error: 'effective_before_contract', contract_start_at: contractStart }, 400, cors);
          }
        }

        // effective_from - 1日
        const effDate = new Date(effectiveFrom + 'T00:00:00Z');
        const prevDay = new Date(effDate.getTime() - 24 * 60 * 60 * 1000);
        const effectiveToOfOld = prevDay.toISOString().substring(0, 10);

        // 既存の effective_to IS NULL（現在有効）レコードを取得
        const oldRec = await db.prepare(
          "SELECT id, pct FROM partner_revenue_share_history " +
          " WHERE partner_id = ? AND scope = 'tamj_to_super' AND effective_to IS NULL " +
          " ORDER BY effective_from DESC LIMIT 1"
        ).bind(partnerId).first();

        const stmts = [];
        if (oldRec) {
          stmts.push(db.prepare(
            "UPDATE partner_revenue_share_history SET effective_to = ? WHERE id = ?"
          ).bind(effectiveToOfOld, oldRec.id));
        }
        stmts.push(db.prepare(
          "INSERT INTO partner_revenue_share_history " +
          "  (partner_id, scope, parent_partner_id, pct, effective_from, effective_to, set_by_staff_id, note) " +
          "VALUES (?, 'tamj_to_super', NULL, ?, ?, NULL, ?, ?)"
        ).bind(partnerId, newPct, effectiveFrom, r.user.staff_id, note || null));

        // 発効日が今日以下の場合は partners.revenue_share_pct も即 UPDATE
        if (effectiveFrom <= today) {
          stmts.push(db.prepare(
            "UPDATE partners SET revenue_share_pct = ?, updated_at = datetime('now') WHERE partner_id = ?"
          ).bind(newPct, partnerId));
        }

        await db.batch(stmts);

        // 新レコードの id を取得
        const inserted = await db.prepare(
          "SELECT id FROM partner_revenue_share_history " +
          " WHERE partner_id = ? AND scope = 'tamj_to_super' " +
          "   AND effective_from = ? AND pct = ? " +
          " ORDER BY id DESC LIMIT 1"
        ).bind(partnerId, effectiveFrom, newPct).first();

        // 遡及影響チェック：effective_from より後の pending ledger を再計算
        const retroactiveAdjustments = [];
        // effective_from が今日以前かつ過去月に効果のある設定の場合に遡及チェック
        const effYearMonth = effectiveFrom.substring(0, 7);
        const pendingMonths = await db.prepare(
          "SELECT DISTINCT year_month FROM revenue_ledger " +
          " WHERE partner_code = ? AND status = 'pending' AND year_month >= ? " +
          " ORDER BY year_month ASC"
        ).bind(partnerId, effYearMonth).all();

        for (const m of (pendingMonths.results || [])) {
          // generateMonthlyLedger が pending のみ DELETE → 新率で INSERT してくれる
          const recalc = await generateMonthlyLedger(db, m.year_month);
          retroactiveAdjustments.push({
            year_month: m.year_month,
            recalculated_entries: recalc.generated_entry_count,
            total_share: recalc.total_share
          });
          try {
            await db.prepare("INSERT INTO audit_logs (type, details) VALUES (?, ?)")
              .bind('ledger_recalculated', JSON.stringify({
                year_month: m.year_month,
                partner_id: partnerId,
                new_pct: newPct,
                effective_from: effectiveFrom
              })).run();
          } catch {}
        }

        // paid ledger の保護通知（監査のみ）
        const paidAffected = await db.prepare(
          "SELECT COUNT(*) AS cnt, COALESCE(SUM(share_amount),0) AS total_share " +
          "  FROM revenue_ledger " +
          " WHERE partner_code = ? AND status = 'paid' AND year_month >= ?"
        ).bind(partnerId, effYearMonth).first();
        if (paidAffected && paidAffected.cnt > 0) {
          try {
            await db.prepare("INSERT INTO audit_logs (type, details) VALUES (?, ?)")
              .bind('ledger_retroactive_adjustment_skipped', JSON.stringify({
                partner_id: partnerId,
                since_year_month: effYearMonth,
                skipped_count: paidAffected.cnt,
                total_share_at_paid_time: paidAffected.total_share
              })).run();
          } catch {}
        }

        await audit(db, 'partner_share_changed', r.user.staff_id, r.user.login_id, {
          partner_id: partnerId,
          scope: 'tamj_to_super',
          old_pct: oldRec ? oldRec.pct : null,
          new_pct: newPct,
          effective_from: effectiveFrom,
          effective_to_of_old: oldRec ? effectiveToOfOld : null,
          note: note || null
        }, request);

        return json({
          ok: true,
          history_id: inserted?.id || null,
          partner_id: partnerId,
          pct: newPct,
          effective_from: effectiveFrom,
          note: note || null,
          retroactive_adjustments: retroactiveAdjustments,
          paid_entries_protected: paidAffected?.cnt || 0
        }, 200, cors);
      }

      // 月次売上台帳の取得
      const ledgerMatch = path.match(/^\/api\/admin\/ledger\/(\d{4}-\d{2})$/);
      if (ledgerMatch && method === 'GET') {
        const r = await requireTamjAdmin(request, db);
        if (r.error) return json({ error: r.error }, r.status, cors);
        const ym = ledgerMatch[1];

        const rows = await db.prepare(
          "SELECT rl.id, rl.year_month, rl.partner_code, rl.app_name, rl.subscription_id, " +
          "       rl.gross_amount, rl.share_pct, rl.share_amount, rl.status, rl.paid_at, rl.created_at, " +
          "       p.company_name AS partner_company_name " +
          "  FROM revenue_ledger rl " +
          "  LEFT JOIN partners p ON p.code = rl.partner_code " +
          " WHERE rl.year_month = ? " +
          " ORDER BY rl.partner_code ASC, rl.app_name ASC"
        ).bind(ym).all();

        const summary = await db.prepare(
          "SELECT COUNT(*) AS cnt, COALESCE(SUM(gross_amount),0) AS gross, COALESCE(SUM(share_amount),0) AS share, " +
          "       SUM(CASE WHEN status='pending' THEN share_amount ELSE 0 END) AS pending_pay, " +
          "       SUM(CASE WHEN status='paid'    THEN share_amount ELSE 0 END) AS paid " +
          "  FROM revenue_ledger WHERE year_month = ?"
        ).bind(ym).first();

        return json({
          ok: true,
          year_month: ym,
          entries: rows.results || [],
          summary: {
            entry_count: summary?.cnt || 0,
            gross_amount: summary?.gross || 0,
            share_amount: summary?.share || 0,
            pending_payout: summary?.pending_pay || 0,
            paid_payout: summary?.paid || 0
          }
        }, 200, cors);
      }

      // 台帳エントリに「支払い完了」マーク
      const markPaidMatch = path.match(/^\/api\/admin\/ledger\/(\d+)\/mark-paid$/);
      if (markPaidMatch && method === 'POST') {
        const r = await requireTamjAdmin(request, db);
        if (r.error) return json({ error: r.error }, r.status, cors);
        const id = Number(markPaidMatch[1]);

        const row = await db.prepare("SELECT * FROM revenue_ledger WHERE id = ?").bind(id).first();
        if (!row) return json({ error: 'ledger_not_found' }, 404, cors);
        if (row.status !== 'pending') return json({ error: 'not_pending', current_status: row.status }, 409, cors);

        await db.prepare(
          "UPDATE revenue_ledger SET status = 'paid', paid_at = datetime('now') WHERE id = ?"
        ).bind(id).run();

        await audit(db, 'admin_ledger_paid', r.user.staff_id, r.user.login_id, {
          ledger_id: id, year_month: row.year_month, partner_code: row.partner_code, amount: row.share_amount
        }, request);

        return json({ ok: true, id, status: 'paid', paid_at: nowISO() }, 200, cors);
      }

      // 売上俯瞰（全月・月別集計）
      if (path === '/api/admin/revenue' && method === 'GET') {
        const r = await requireTamjAdmin(request, db);
        if (r.error) return json({ error: r.error }, r.status, cors);

        const byMonth = await db.prepare(
          "SELECT year_month, COUNT(*) AS entry_count, SUM(gross_amount) AS gross, SUM(share_amount) AS share, " +
          "       SUM(CASE WHEN status='pending' THEN share_amount ELSE 0 END) AS pending_pay, " +
          "       SUM(CASE WHEN status='paid'    THEN share_amount ELSE 0 END) AS paid " +
          "  FROM revenue_ledger GROUP BY year_month ORDER BY year_month DESC LIMIT 12"
        ).all();

        return json({
          ok: true,
          months: byMonth.results || []
        }, 200, cors);
      }

      // 月次台帳を手動再生成（Cron と同じ処理を on-demand で実行・保険用）
      const regenMatch = path.match(/^\/api\/admin\/ledger\/(\d{4}-\d{2})\/regenerate$/);
      if (regenMatch && method === 'POST') {
        const r = await requireTamjAdmin(request, db);
        if (r.error) return json({ error: r.error }, r.status, cors);
        const ym = regenMatch[1];
        try {
          const result = await generateMonthlyLedger(db, ym);
          await audit(db, 'admin_ledger_regenerated', r.user.staff_id, r.user.login_id, result, request);
          return json({ ok: true, ...result }, 200, cors);
        } catch (e) {
          return json({ error: 'regeneration_failed', message: String(e.message || e) }, 500, cors);
        }
      }

      // =============== Subscriptions (Phase 3d: モック版) ===============
      //  Phase 3f で Square Web Payments SDK に統合される予定。
      //  現状は直接作成・状態管理のみ。

      // 自分の会社のsubscription一覧
      if (path === '/api/subscriptions/mine' && method === 'GET') {
        const r = await requireAuth(request, db);
        if (r.error) return json({ error: r.error }, r.status, cors);
        const rs = await db.prepare(
          "SELECT subscription_id, app_name, plan, seat_count, unit_price, partner_code, " +
          "       started_at, ended_at, next_billing_at, status, created_at " +
          "  FROM subscriptions WHERE master_company_id = ? ORDER BY created_at DESC"
        ).bind(r.user.master_company_id).all();
        return json({ ok: true, subscriptions: rs.results || [] }, 200, cors);
      }

      // subscription 作成（Phase 3d: モック・Phase 3fでSquare連携に置換予定）
      if (path === '/api/subscriptions/create' && method === 'POST') {
        const r = await requireAuth(request, db);
        if (r.error) return json({ error: r.error }, r.status, cors);

        const b = (await request.json()) || {};
        const { app_name, plan, seat_count, unit_price } = b;
        if (!app_name || !plan || !seat_count || !unit_price) {
          return json({ error: 'missing_fields', fields: ['app_name','plan','seat_count','unit_price'].filter(k => !b?.[k]) }, 400, cors);
        }
        if (!['onetouch', 'medadapt'].includes(app_name)) return json({ error: 'invalid_app' }, 400, cors);
        if (seat_count < 1 || unit_price < 0) return json({ error: 'invalid_values' }, 400, cors);

        // 会社のpartner_code (NULL=直販) を継承（契約期間中は固定）
        const company = await db.prepare(
          "SELECT partner_code FROM master_companies WHERE company_id = ?"
        ).bind(r.user.master_company_id).first();

        const subId = 'SUB-' + randomId(12);
        const now = nowISO();
        const nextBilling = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();

        await db.prepare(
          "INSERT INTO subscriptions (subscription_id, master_company_id, app_name, plan, seat_count, unit_price, " +
          "  partner_code, started_at, next_billing_at, status) " +
          "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'active')"
        ).bind(
          subId, r.user.master_company_id, app_name, plan, seat_count, unit_price,
          company?.partner_code || null, now, nextBilling
        ).run();

        await audit(db, 'subscription_created', r.user.staff_id, r.user.login_id, {
          subscription_id: subId, app_name, plan, seat_count, unit_price,
          partner_code: company?.partner_code || null
        }, request);

        return json({
          ok: true,
          subscription: {
            subscription_id: subId, app_name, plan, seat_count, unit_price,
            partner_code: company?.partner_code || null,
            started_at: now, next_billing_at: nextBilling, status: 'active'
          }
        }, 200, cors);
      }

      // subscription 解約
      const cancelSubMatch = path.match(/^\/api\/subscriptions\/([A-Z0-9-]+)\/cancel$/);
      if (cancelSubMatch && method === 'POST') {
        const r = await requireAuth(request, db);
        if (r.error) return json({ error: r.error }, r.status, cors);
        const subId = cancelSubMatch[1];

        const sub = await db.prepare(
          "SELECT * FROM subscriptions WHERE subscription_id = ? AND master_company_id = ?"
        ).bind(subId, r.user.master_company_id).first();
        if (!sub) return json({ error: 'not_found' }, 404, cors);
        if (sub.status !== 'active') return json({ error: 'not_active', current_status: sub.status }, 409, cors);

        await db.prepare(
          "UPDATE subscriptions SET status = 'expired', ended_at = datetime('now'), updated_at = datetime('now') WHERE subscription_id = ?"
        ).bind(subId).run();

        await audit(db, 'subscription_canceled', r.user.staff_id, r.user.login_id, { subscription_id: subId }, request);
        return json({ ok: true, subscription_id: subId, status: 'expired' }, 200, cors);
      }

      // 内部API：モジュールが利用可否判定に使う（§12.8 論点2-A対応の下地）
      // Service Binding経由で子Workerから呼ばれる前提（認証は内部前提）
      if (path === '/api/internal/check-subscription' && method === 'GET') {
        const companyId = url.searchParams.get('company');
        const appName = url.searchParams.get('app');
        if (!companyId || !appName) return json({ error: 'missing_params' }, 400, cors);
        const sub = await db.prepare(
          "SELECT subscription_id, status, plan, seat_count, started_at, ended_at, next_billing_at " +
          "  FROM subscriptions " +
          " WHERE master_company_id = ? AND app_name = ? AND status = 'active' " +
          " ORDER BY created_at DESC LIMIT 1"
        ).bind(companyId, appName).first();
        return json({
          ok: true,
          active: !!sub,
          subscription: sub || null
        }, 200, cors);
      }

      // =============== Square 決済連携（Phase 3f） ===============

      // 購入可能なプラン一覧
      if (path === '/api/subscriptions/plans' && method === 'GET') {
        return json({ ok: true, plans: AVAILABLE_PLANS }, 200, cors);
      }

      // フロント用設定値（Web Payments SDK 初期化に必要）
      // 認証不要（Square Application ID とロケーションIDは公開情報扱い）
      if (path === '/api/subscriptions/config' && method === 'GET') {
        return json({
          ok: true,
          square: {
            application_id: env.SQUARE_APPLICATION_ID || null,
            location_id:    env.SQUARE_LOCATION_ID    || null,
            env:            env.SQUARE_ENV || 'sandbox'
          },
          configured: !!(env.SQUARE_APPLICATION_ID && env.SQUARE_LOCATION_ID)
        }, 200, cors);
      }

      // Square Webhook受信エンドポイント
      //
      //  Squareから送信される主要イベント:
      //    - subscription.created
      //    - subscription.updated
      //    - invoice.payment_made
      //    - invoice.published
      //    - invoice.scheduled_charge_failed
      //
      //  認証: x-square-hmacsha256-signature ヘッダで署名検証
      if (path === '/api/subscriptions/webhook' && method === 'POST') {
        const rawBody = await request.text();
        const notificationUrl = env.SQUARE_WEBHOOK_NOTIFICATION_URL ||
          `${new URL(request.url).origin}/api/subscriptions/webhook`;

        // 署名検証
        const sigKey = env.SQUARE_WEBHOOK_SIGNATURE_KEY;
        if (!sigKey) {
          // 未設定時は安全側で拒否（ただしログは残す）
          await audit(db, 'square_webhook_no_key', null, null, { notification_url: notificationUrl }, request);
          return json({ error: 'webhook_not_configured' }, 500, cors);
        }
        const valid = await verifySquareWebhookSignature(request, rawBody, sigKey, notificationUrl);
        if (!valid) {
          await audit(db, 'square_webhook_invalid_sig', null, null, { bodyPreview: rawBody.slice(0, 200) }, request);
          return json({ error: 'invalid_signature' }, 401, cors);
        }

        let event;
        try { event = JSON.parse(rawBody); } catch {
          return json({ error: 'invalid_json' }, 400, cors);
        }

        const eventType = event.type;
        const data = event.data?.object;

        try {
          // subscription.created / updated → subscriptions テーブルの status 反映
          if ((eventType === 'subscription.created' || eventType === 'subscription.updated') && data?.subscription) {
            const sq = data.subscription;
            const squareStatus = sq.status; // 'PENDING' | 'ACTIVE' | 'CANCELED' | 'DEACTIVATED'
            const mapStatus = squareStatus === 'ACTIVE' ? 'active'
                          : squareStatus === 'CANCELED' ? 'expired'
                          : squareStatus === 'DEACTIVATED' ? 'expired'
                          : 'pending';
            // square_subscription_id で検索して更新
            const existing = await db.prepare(
              "SELECT subscription_id FROM subscriptions WHERE square_subscription_id = ?"
            ).bind(sq.id).first();
            if (existing) {
              await db.prepare(
                "UPDATE subscriptions SET status = ?, updated_at = datetime('now') WHERE subscription_id = ?"
              ).bind(mapStatus, existing.subscription_id).run();
            }
          }

          // invoice.payment_made → next_billing_at 更新（Adavoo側では決済完了の記録まで）
          if (eventType === 'invoice.payment_made' && data?.invoice) {
            const inv = data.invoice;
            const subId = inv.subscription_id;
            if (subId) {
              await db.prepare(
                "UPDATE subscriptions SET status = 'active', updated_at = datetime('now') WHERE square_subscription_id = ?"
              ).bind(subId).run();
            }
          }

          await audit(db, 'square_webhook', null, null, {
            event_id: event.event_id,
            type: eventType,
            object_id: data?.subscription?.id || data?.invoice?.id || null
          }, request);
        } catch (e) {
          await audit(db, 'square_webhook_error', null, null, {
            event_id: event.event_id, type: eventType, error: String(e.message || e)
          }, request);
        }

        // Square の仕様上、2xx返せば再送されない
        return json({ ok: true, received: eventType }, 200, cors);
      }

      return json({ error: 'not_found', path, method }, 404, cors);
    } catch (e) {
      return json({ error: 'server_error', message: String(e.message || e) }, 500, cors);
    }
  },

  // =========================================================
  //  Cron Triggers（scheduled ハンドラ）
  //
  //  Cloudflare Cron は "L"（月末）非対応のため、月次集計は「翌月1日 00:05 JST」に移動。
  //  実質的な動作は設計書§12.7と同等。
  //
  //  wrangler.toml の crons 設定に対応:
  //   - "0 0 * * *"      → 09:00 JST (contract_notify_2month)
  //   - "5 15 * * *"     → 00:05 JST 翌日 (contract_auto_expire)
  //   - "5 15 1 * *"     → 毎月1日 00:05 JST (ledger_monthly_close — 前月分集計)
  //   - "0 18 * * *"     → 03:00 JST 翌日 (cleanup_expired_tokens)
  //
  //  ※ JST時刻はUTCに変換してcron式を書く（UTC = JST - 9h）
  // =========================================================
  async scheduled(event, env, ctx) {
    const db = env.DB;
    const started = new Date().toISOString();
    const cron = event.cron;
    let result = { cron, started, task: null, result: null, error: null };

    try {
      if (cron === '0 0 * * *') {
        result.task = 'contract_notify_2month';
        result.result = await runContractNotify2Month(db, env);
      } else if (cron === '5 15 * * *') {
        result.task = 'contract_auto_expire';
        result.result = await runContractAutoExpire(db);
      } else if (cron === '5 15 1 * *') {
        result.task = 'ledger_monthly_close';
        // 実行時刻: 毎月1日 00:05 JST (= 前月末日 15:05 UTC)
        // 集計対象は「前月」
        const now = new Date();
        const jst = new Date(now.getTime() + 9 * 60 * 60 * 1000);
        const prevMonth = new Date(Date.UTC(jst.getUTCFullYear(), jst.getUTCMonth() - 1, 1));
        const ym = `${prevMonth.getUTCFullYear()}-${String(prevMonth.getUTCMonth() + 1).padStart(2, '0')}`;
        result.result = await generateMonthlyLedger(db, ym);
      } else if (cron === '0 18 * * *') {
        result.task = 'cleanup_expired_tokens';
        result.result = await runCleanupExpiredTokens(db);
      } else if (cron === '10 15 * * *') {
        // Phase 4-3a 追加: 按分率履歴の日次同期 Cron
        // UTC 15:10 = JST 00:10（翌日 AM 0:10）
        result.task = 'sync_revenue_share_pct';
        result.result = await runSyncRevenueSharePct(db);
      } else {
        result.task = 'unknown_cron';
        result.error = `No handler for cron: ${cron}`;
      }
    } catch (e) {
      result.error = String(e.message || e);
    }

    // 実行結果を audit_logs に記録（監査用）
    try {
      await db.prepare(
        "INSERT INTO audit_logs (type, details) VALUES (?, ?)"
      ).bind('cron_run', JSON.stringify(result)).run();
    } catch {}

    return result;
  }
};

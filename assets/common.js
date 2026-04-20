/* =========================================================
   Adapt - Shared client utilities (v2)
   ========================================================= */

window.ADAPT_CONFIG = {
  API_BASE: 'https://adapt-api.animalb001.workers.dev',
  APPS: {
    onetouch: {
      name: 'OneTouchAdapt',
      kana: 'ワンタッチアダプト',
      desc: '施設設備の通報・管理会社連携・QR台帳。',
      accent: '#d4380d',
      url: 'https://tamjump.github.io/onetouch_app/login.html',
      lp:  'https://one-touch.tamjump.com',
      tags: '施設設備管理'
    },
    medadapt: {
      name: 'MedAdapt',
      kana: 'メドアダプト',
      desc: '医療・介護の法人間連携OS。NDA・退院通知・面談。',
      accent: '#0891b2',
      url: 'https://medadapt.scsgo.co.jp/app.html',
      lp:  'https://medadapt.scsgo.co.jp',
      tags: '医療介護連携'
    }
  }
};

const AdaptAPI = {
  base: () => window.ADAPT_CONFIG.API_BASE,
  token: () => localStorage.getItem('adapt_token'),
  setToken: (t, exp) => {
    localStorage.setItem('adapt_token', t);
    if (exp) localStorage.setItem('adapt_token_exp', exp);
  },
  clear: () => {
    localStorage.removeItem('adapt_token');
    localStorage.removeItem('adapt_token_exp');
    localStorage.removeItem('adapt_user');
  },
  setUser: (u) => localStorage.setItem('adapt_user', JSON.stringify(u)),
  getUser: () => {
    try { return JSON.parse(localStorage.getItem('adapt_user') || 'null'); }
    catch { return null; }
  },
  async call(path, opts = {}) {
    const headers = Object.assign({ 'Content-Type': 'application/json' }, opts.headers || {});
    const t = AdaptAPI.token();
    if (t) headers['Authorization'] = 'Bearer ' + t;
    const res = await fetch(AdaptAPI.base() + path, {
      method: opts.method || 'GET', headers,
      body: opts.body ? JSON.stringify(opts.body) : undefined
    });
    const text = await res.text();
    let data; try { data = text ? JSON.parse(text) : {}; } catch { data = { raw: text }; }
    if (!res.ok) {
      const err = new Error(data.error || ('HTTP ' + res.status));
      err.status = res.status;
      err.data = data;
      throw err;
    }
    return data;
  }
};

async function requireLogin(redirectTo = 'login.html') {
  const t = AdaptAPI.token();
  if (!t) { location.href = redirectTo; return null; }
  try {
    const r = await AdaptAPI.call('/api/auth/me');
    AdaptAPI.setUser(r.user);
    return r;
  } catch (e) {
    AdaptAPI.clear();
    location.href = redirectTo;
    return null;
  }
}

function renderHeader({ loggedIn = false, active = '' } = {}) {
  const user = AdaptAPI.getUser();
  const nav = loggedIn
    ? `
      <a href="index.html"  class="${active === 'home'    ? 'active' : ''}">ホーム</a>
      <a href="account.html" class="${active === 'account' ? 'active' : ''}">アカウント</a>
      <span class="hdr__who">${user ? escapeHTML(user.login_id) : ''}</span>
      <button id="adaptLogoutBtn" type="button">ログアウト</button>
    `
    : `
      <a href="login.html">ログイン</a>
      <a href="register.html">新規登録</a>
    `;
  const html = `
    <header class="hdr">
      <a href="index.html" class="hdr__brand">
        Adapt
        <span class="hdr__brand-sub">Platform Portal</span>
      </a>
      <nav class="hdr__nav">${nav}</nav>
    </header>
  `;
  const holder = document.getElementById('adapt-header') || (() => {
    const d = document.createElement('div');
    d.id = 'adapt-header';
    document.body.prepend(d);
    return d;
  })();
  holder.outerHTML = html;

  const btn = document.getElementById('adaptLogoutBtn');
  if (btn) btn.addEventListener('click', async () => {
    try { await AdaptAPI.call('/api/auth/logout', { method: 'POST' }); } catch {}
    AdaptAPI.clear();
    location.href = 'login.html';
  });
}

// パスワード表示トグル
function bindPasswordToggles(root = document) {
  root.querySelectorAll('.pw-toggle').forEach(btn => {
    if (btn.dataset.bound) return;
    btn.dataset.bound = '1';
    btn.addEventListener('click', () => {
      const target = document.getElementById(btn.dataset.pw);
      if (!target) return;
      const show = target.type === 'password';
      target.type = show ? 'text' : 'password';
      btn.textContent = show ? '非表示' : '表示';
    });
  });
}

function escapeHTML(s) {
  return String(s ?? '').replace(/[&<>"']/g, c => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
  ));
}

function toast(msg, kind = 'info', ms = 3500) {
  const el = document.createElement('div');
  el.className = 'msg msg--' + (kind === 'error' ? 'err' : kind === 'success' ? 'ok' : 'info');
  el.textContent = msg;
  el.style.position = 'fixed';
  el.style.top = '80px';
  el.style.right = '24px';
  el.style.zIndex = '9999';
  el.style.boxShadow = 'var(--shadow-lg)';
  el.style.maxWidth = '360px';
  el.style.background = '#fff';
  document.body.appendChild(el);
  setTimeout(() => el.remove(), ms);
}

window.AdaptAPI = AdaptAPI;
window.Adapt = { requireLogin, renderHeader, escapeHTML, toast, bindPasswordToggles };

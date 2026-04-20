# Adapt

**Adaptファミリー親アプリ** — OneTouchAdapt・MedAdapt 等の子アプリを統一ID/SSOで束ねるランチャー。

- **URL**: https://tamjump.github.io/adapt/ （Pages有効化後）
- **API**: https://adapt-api.animalb001.workers.dev （Worker作成後）
- **DB**: `adapt-db` (Cloudflare D1)

---

## 1. 構成

```
親: Adapt (このリポジトリ)
├── OneTouchAdapt  (TAmJump/onetouch_app)   施設設備管理
└── MedAdapt       (TAmJump/medadapt)       医療介護連携
```

- 親アプリは**無料**。Proプランは従来通り各子アプリで個別契約。
- 親 `login_id` が正本。`app_links` テーブルで子アプリID（`TEST1-admin` や `ADM-TIGER`）にマッピング。
- SSO: 親が60秒の短命チケットを発行 → 子アプリURLに `?sso_ticket=XXX` で渡す → 子が親API `/api/apps/sso-verify` で引き換え。

## 2. ファイル

| ファイル | 役割 |
|---|---|
| `index.html` | ランチャー（ログイン必須。子アプリカード＋SSO起動＋連携モーダル） |
| `login.html` | ログイン |
| `register.html` | 会社+初期管理者登録 |
| `account.html` | プロフィール / 連携一覧 / PW変更 |
| `assets/style.css` | 共通CSS |
| `assets/common.js` | API/認証ヘルパー |
| `assets/worker.js` | **Cloudflare Worker 全コード（Edit code に貼り付ける）** |
| `schema.sql` | D1スキーマ |
| `manifest.json` | PWA |

## 3. セットアップ手順

### 3-1. D1 データベース作成

1. Cloudflare ダッシュボード → Workers & Pages → D1 → **Create database**
2. Name: `adapt-db` / Location: 任意
3. 作成後 → **Console** タブ → `schema.sql` の中身を全貼り付け → **Execute**

### 3-2. Worker 作成

1. Workers & Pages → **Create** → **Create Worker** → Name: `adapt-api` → Deploy
2. 作成後 → **Settings** → **Bindings** → **Add binding** → **D1 database**
   - Variable name: `DB`
   - Database: `adapt-db`
3. **Settings** → **Variables and Secrets** → Plaintext で以下を追加
   ```
   ALLOWED_ORIGINS    = https://tamjump.github.io,https://adapt.tamjump.com,http://localhost:5500
   ONETOUCH_API_BASE  = https://onetouch-api.animalb001.workers.dev
   MEDADAPT_API_BASE  = https://medadapt-api-v2.animalb001.workers.dev
   ONETOUCH_APP_URL   = https://tamjump.github.io/onetouch_app
   MEDADAPT_APP_URL   = https://medadapt.scsgo.co.jp
   ```
4. **Edit code** → 既存コード全削除 → `assets/worker.js` を全貼り付け → **Deploy**
5. 動作確認: `curl https://adapt-api.animalb001.workers.dev/api/health` → `{ "ok": true, ... }`

### 3-3. GitHub Pages 有効化

1. GitHub → TAmJump/adapt → **Settings** → **Pages**
2. Source: **Deploy from a branch** / Branch: `main` / Folder: `/ (root)` → Save
3. 数分後 https://tamjump.github.io/adapt/ で公開

### 3-4. カスタムドメイン（任意・あとで）

1. Cloudflare DNS → tamjump.com → CNAME `adapt` → `tamjump.github.io` / Proxy ON
2. リポジトリ直下に `CNAME` ファイル作成（中身: `adapt.tamjump.com`）
3. GitHub → Settings → Pages → Custom domain: `adapt.tamjump.com`
4. Worker環境変数 `ALLOWED_ORIGINS` に `https://adapt.tamjump.com` を追加

### 3-5. 動作確認

1. https://tamjump.github.io/adapt/login.html にアクセス
2. **新規登録** → 会社名・ログインID（例: `tamjump-admin`）・パスワード（8文字以上）
3. 自動ログイン → ランチャー画面
4. OneTouchAdaptカード「連携する」→ 子ログインID `TEST1-admin` + PW `19800101a` で連携確認
5. 連携済みになったら「開く」→ 新タブで子アプリが開く（`?sso_ticket=XXX` 付き）

## 4. 子アプリ側のSSO受け口（Phase 2・未実装）

現状、子アプリは `?sso_ticket` を受け取っても無視して通常のログインを求めます。**完全SSOには子アプリ側の対応が必要**です。

### 子アプリ側で追加すべきもの

**子アプリ Worker (新エンドポイント):**
```js
// POST /api/auth/sso-login
if (path === '/api/auth/sso-login' && method === 'POST') {
  const { sso_ticket } = await request.json();
  // 親APIに照会
  const v = await fetch(`https://adapt-api.animalb001.workers.dev/api/apps/sso-verify?ticket=${sso_ticket}`);
  if (!v.ok) return json({ error: 'sso_invalid' }, 401, cors);
  const vd = await v.json();
  // vd.child_login_id のユーザーでセッション発行
  const user = await db.prepare("SELECT * FROM users WHERE login_id = ?").bind(vd.child_login_id).first();
  if (!user) return json({ error: 'user_not_found' }, 404, cors);
  // ... 通常のログイン成功レスポンスと同じ形で返す
}
```

**子アプリ login.html 冒頭:**
```js
const sso = new URLSearchParams(location.search).get('sso_ticket');
if (sso) {
  fetch(API_BASE + '/api/auth/sso-login', {
    method: 'POST', headers: {'Content-Type':'application/json'},
    body: JSON.stringify({ sso_ticket: sso })
  }).then(r => r.json()).then(d => {
    if (d.token) {
      localStorage.setItem('token', d.token);
      location.href = 'master-top.html'; // or app.html
    }
  });
}
```

## 5. D1 スキーマ概要

| テーブル | 内容 |
|---|---|
| `master_companies` | 親会社（ADP-000001 形式）|
| `master_staff` | 親スタッフ（ADP-STF-000001 形式・login_idユニーク）|
| `sessions` | Bearerトークン（30日有効）|
| `app_links` | 親↔子アプリ紐付け（UNIQUE: staff_id+app_name+child_login_id）|
| `sso_tickets` | 60秒ワンタイムチケット |
| `audit_logs` | 操作ログ |

## 6. API一覧

| メソッド | パス | 権限 | 用途 |
|---|---|---|---|
| GET  | `/api/health` | - | ヘルスチェック |
| POST | `/api/auth/register` | - | 会社+初期管理者登録 |
| POST | `/api/auth/login` | - | ログイン |
| POST | `/api/auth/logout` | Bearer | ログアウト |
| GET  | `/api/auth/me` | Bearer | 自分 |
| POST | `/api/auth/change-password` | Bearer | PW変更 |
| GET  | `/api/apps/links` | Bearer | 紐付け一覧 |
| POST | `/api/apps/links` | Bearer | 既存子アカウントを紐付け（子APIで実認証） |
| DELETE | `/api/apps/links/:id` | Bearer | 紐付け解除 |
| POST | `/api/apps/sso-ticket` | Bearer | 60秒チケット発行 |
| GET  | `/api/apps/sso-verify` | - | チケット検証（子Workerから呼ぶ） |

## 7. セキュリティメモ

- パスワード: SHA-256（子アプリと同方式）
- Bearerトークン: 48文字ランダム・30日
- SSOチケット: 48文字ランダム・60秒・**使い捨て**（consumed_at チェック）
- CORS: `ALLOWED_ORIGINS` で明示
- 子アプリ認証はパスワードを**保存しない**（連携時の1回だけ子APIに投げる）

## 8. 今後の拡張

- [ ] 子アプリ側 `/api/auth/sso-login` 実装（Phase 2）
- [ ] メール認証（新規登録時）
- [ ] パスワードリセット（メール経由）
- [ ] 親スタッフ複数人対応（master_admin がスタッフ招待）
- [ ] アイコン画像（manifest `icons[]` 埋め）
- [ ] Android TWA（子アプリと同じ方式）
- [ ] sso_tickets の定期クリーンアップ（Cron Triggers）

## 9. 認証情報

- **GitHub PAT**: 別途管理（Repo へ push する際のみ使用。コミット禁止）
- **Cloudflare**: `animalb001@gmail.com`

---
最終更新: 2026-04-20 (v1.0・箱のみ・SSO発行側は実装済／子受側は Phase 2)

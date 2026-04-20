-- =========================================================
--  Adapt (親アプリ) D1 Schema v1.0
--  DB名: adapt-db
--  Cloudflare D1 → Console にそのまま貼り付けて実行
-- =========================================================

-- 1. 親会社マスタ
CREATE TABLE IF NOT EXISTS master_companies (
  company_id    TEXT PRIMARY KEY,                 -- 'ADP-000001'
  name          TEXT NOT NULL,
  email         TEXT,
  phone         TEXT,
  status        TEXT NOT NULL DEFAULT 'active',   -- active / suspended
  created_at    TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

-- 2. 親スタッフ（マスタユーザー）
CREATE TABLE IF NOT EXISTS master_staff (
  staff_id          TEXT PRIMARY KEY,             -- 'ADP-STF-000001'
  master_company_id TEXT NOT NULL,
  login_id          TEXT UNIQUE NOT NULL,         -- ユーザーが設定する一意ID
  name              TEXT NOT NULL,
  email             TEXT,
  password_hash     TEXT NOT NULL,                -- SHA-256 hex
  role              TEXT NOT NULL DEFAULT 'master_admin', -- master_admin / master_staff
  status            TEXT NOT NULL DEFAULT 'active',
  last_login_at     TEXT,
  created_at        TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at        TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (master_company_id) REFERENCES master_companies(company_id)
);

CREATE INDEX IF NOT EXISTS idx_master_staff_company ON master_staff(master_company_id);

-- 3. 親セッション（Bearerトークン）
CREATE TABLE IF NOT EXISTS sessions (
  token       TEXT PRIMARY KEY,
  staff_id    TEXT NOT NULL,
  expires_at  TEXT NOT NULL,                      -- ISO8601
  created_at  TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (staff_id) REFERENCES master_staff(staff_id)
);

CREATE INDEX IF NOT EXISTS idx_sessions_staff ON sessions(staff_id);

-- 4. 子アプリ紐付け（既存アカウントのリンク）
CREATE TABLE IF NOT EXISTS app_links (
  id                 INTEGER PRIMARY KEY AUTOINCREMENT,
  staff_id           TEXT NOT NULL,
  app_name           TEXT NOT NULL,               -- 'medadapt' | 'onetouch'
  child_login_id     TEXT NOT NULL,
  child_company_code TEXT,                        -- 子アプリ側会社コード（任意）
  child_role         TEXT,                        -- 子アプリ側の役割（任意）
  status             TEXT NOT NULL DEFAULT 'linked', -- linked / pending / revoked
  linked_at          TEXT NOT NULL DEFAULT (datetime('now')),
  last_sso_at        TEXT,
  UNIQUE (staff_id, app_name, child_login_id),
  FOREIGN KEY (staff_id) REFERENCES master_staff(staff_id)
);

CREATE INDEX IF NOT EXISTS idx_app_links_staff ON app_links(staff_id);

-- 5. SSO短命チケット（60秒・一回きり）
CREATE TABLE IF NOT EXISTS sso_tickets (
  ticket          TEXT PRIMARY KEY,               -- ランダム32文字
  staff_id        TEXT NOT NULL,
  app_name        TEXT NOT NULL,
  child_login_id  TEXT NOT NULL,
  expires_at      TEXT NOT NULL,
  consumed_at     TEXT,
  created_at      TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (staff_id) REFERENCES master_staff(staff_id)
);

-- 6. 監査ログ（親アプリ内の操作記録）
CREATE TABLE IF NOT EXISTS audit_logs (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  timestamp   TEXT NOT NULL DEFAULT (datetime('now')),
  type        TEXT NOT NULL,                      -- login / logout / register / link / unlink / sso / password_change
  staff_id    TEXT,
  login_id    TEXT,
  details     TEXT,                               -- JSON文字列
  ip          TEXT,
  user_agent  TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_staff ON audit_logs(staff_id);
CREATE INDEX IF NOT EXISTS idx_audit_type  ON audit_logs(type);

-- =========================================================
--  初期データ（system_admin ダミー）※本番前に必ず削除可能
--  パスワードは後で /api/auth/change-password か D1直叩きで変更
-- =========================================================
-- system_adminは初期化時に手動で挿入する運用（README参照）

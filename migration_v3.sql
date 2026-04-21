-- =========================================================
--  Adapt D1 Schema Migration v2 → v3 (Phase 3a: 代理店制度)
--
--  追加点:
--   - master_companies に partner_code / partner_code_locked_at カラム追加
--   - partners / partner_sessions / subscriptions / revenue_ledger テーブル新設
--   - tamj-admin の role を 'tamj_admin' に更新（タムジ管理画面アクセス権）
--
--  実行方法（Cloudflare Dashboard / D1 / Console で一括実行）:
--   ※ ALTER TABLE は既存カラムがあると失敗する → 初回のみ実行
-- =========================================================

-- ---------------------------------------------------------
--  master_companies 拡張: 代理店コードの紐付け情報
-- ---------------------------------------------------------
ALTER TABLE master_companies ADD COLUMN partner_code TEXT;
ALTER TABLE master_companies ADD COLUMN partner_code_locked_at TEXT;
CREATE INDEX IF NOT EXISTS idx_companies_partner_code ON master_companies(partner_code);

-- ---------------------------------------------------------
--  partners: 総代理店・代理店マスタ
--   - type='super': 総代理店（タムジ直属・parent_partner_id=NULL）
--   - type='agent': 代理店（必ず総代理店に所属・parent_partner_id必須）
--   - code は partner_id と同一値（SUP-XXXXXX / AGT-XXXXXX）
--   - revenue_share_pct: 総代理店のみ意味を持つ（代理店はNULL）
-- ---------------------------------------------------------
CREATE TABLE IF NOT EXISTS partners (
  partner_id              TEXT PRIMARY KEY,
  type                    TEXT NOT NULL CHECK(type IN ('super','agent')),
  parent_partner_id       TEXT,
  company_name            TEXT NOT NULL,
  code                    TEXT UNIQUE NOT NULL,
  login_id                TEXT UNIQUE NOT NULL,
  password_hash           TEXT NOT NULL,
  email                   TEXT,
  phone                   TEXT,
  contract_start_at       TEXT,
  contract_end_at         TEXT,
  auto_end_notified_at    TEXT,
  status                  TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','pending','expired','terminated')),
  bank_info_json          TEXT,
  revenue_share_pct       REAL,
  created_at              TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at              TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (parent_partner_id) REFERENCES partners(partner_id)
);
CREATE INDEX IF NOT EXISTS idx_partners_parent  ON partners(parent_partner_id);
CREATE INDEX IF NOT EXISTS idx_partners_code    ON partners(code);
CREATE INDEX IF NOT EXISTS idx_partners_status  ON partners(status);

-- ---------------------------------------------------------
--  partner_sessions: 代理店ログイン用セッション
--   master_staff の sessions とは完全分離
-- ---------------------------------------------------------
CREATE TABLE IF NOT EXISTS partner_sessions (
  token       TEXT PRIMARY KEY,
  partner_id  TEXT NOT NULL,
  expires_at  TEXT NOT NULL,
  created_at  TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (partner_id) REFERENCES partners(partner_id)
);
CREATE INDEX IF NOT EXISTS idx_partner_sessions_partner ON partner_sessions(partner_id);

-- ---------------------------------------------------------
--  subscriptions: モジュール契約
--   Phase 3d で CRUD 実装・Phase 3f で Square 連携
-- ---------------------------------------------------------
CREATE TABLE IF NOT EXISTS subscriptions (
  subscription_id         TEXT PRIMARY KEY,
  master_company_id       TEXT NOT NULL,
  app_name                TEXT NOT NULL,
  plan                    TEXT NOT NULL,
  seat_count              INTEGER NOT NULL DEFAULT 1,
  unit_price              INTEGER NOT NULL,
  partner_code            TEXT,
  started_at              TEXT,
  ended_at                TEXT,
  next_billing_at         TEXT,
  status                  TEXT NOT NULL DEFAULT 'trial',
  square_subscription_id  TEXT,
  created_at              TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at              TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (master_company_id) REFERENCES master_companies(company_id)
);
CREATE INDEX IF NOT EXISTS idx_subs_company      ON subscriptions(master_company_id);
CREATE INDEX IF NOT EXISTS idx_subs_partner_code ON subscriptions(partner_code);
CREATE INDEX IF NOT EXISTS idx_subs_status       ON subscriptions(status);

-- ---------------------------------------------------------
--  revenue_ledger: 月次売上台帳
--   月末Cronで INSERT、タムジが手動で支払い完了マーク
--   タムジは総代理店にしか支払わないため、partner_code は常に SUP-XXXXXX
-- ---------------------------------------------------------
CREATE TABLE IF NOT EXISTS revenue_ledger (
  id               INTEGER PRIMARY KEY AUTOINCREMENT,
  year_month       TEXT NOT NULL,
  partner_code     TEXT NOT NULL,
  app_name         TEXT NOT NULL,
  subscription_id  TEXT,
  gross_amount     INTEGER NOT NULL,
  share_pct        REAL NOT NULL,
  share_amount     INTEGER NOT NULL,
  status           TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','paid','canceled')),
  paid_at          TEXT,
  created_at       TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (subscription_id) REFERENCES subscriptions(subscription_id)
);
CREATE INDEX IF NOT EXISTS idx_ledger_ym       ON revenue_ledger(year_month);
CREATE INDEX IF NOT EXISTS idx_ledger_partner  ON revenue_ledger(partner_code);
CREATE INDEX IF NOT EXISTS idx_ledger_status   ON revenue_ledger(status);

-- ---------------------------------------------------------
--  tamj-admin アカウントに tamj_admin ロール付与
--   タムジ管理画面（Phase 3c）のアクセス権
-- ---------------------------------------------------------
UPDATE master_staff
   SET role = 'tamj_admin', updated_at = datetime('now')
 WHERE login_id = 'tamj-admin';

-- migration_v8.sql: Phase 4-3b 代理店セルフ登録
-- 実行方法: Cloudflare D1 Console（adapt-db）に貼り付けて実行
--
-- 注: bank_info_json は migration_v3.sql で既に追加済みのため、ここでは追加しない

-- 1. 招待テーブル作成
CREATE TABLE IF NOT EXISTS partner_invitations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  token TEXT UNIQUE NOT NULL,
  invited_email TEXT NOT NULL,
  invited_role TEXT NOT NULL,
  parent_partner_id TEXT,
  initial_revenue_share_pct REAL,
  initial_contract_months INTEGER NOT NULL DEFAULT 12,
  note TEXT,
  created_by_staff_id TEXT,
  created_by_partner_id TEXT,
  status TEXT NOT NULL DEFAULT 'issued',
  expires_at TEXT NOT NULL,
  used_at TEXT,
  resulted_partner_id TEXT,
  resend_count INTEGER NOT NULL DEFAULT 0,
  last_resent_at TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (parent_partner_id) REFERENCES partners(partner_id),
  FOREIGN KEY (created_by_staff_id) REFERENCES master_staff(staff_id),
  FOREIGN KEY (created_by_partner_id) REFERENCES partners(partner_id),
  FOREIGN KEY (resulted_partner_id) REFERENCES partners(partner_id)
);
CREATE INDEX IF NOT EXISTS idx_pi_token ON partner_invitations(token);
CREATE INDEX IF NOT EXISTS idx_pi_status ON partner_invitations(status);
CREATE INDEX IF NOT EXISTS idx_pi_email ON partner_invitations(invited_email);
CREATE INDEX IF NOT EXISTS idx_pi_parent ON partner_invitations(parent_partner_id);
CREATE INDEX IF NOT EXISTS idx_pi_expires ON partner_invitations(expires_at);

-- 2. partners テーブル拡張（全て NULLABLE）
ALTER TABLE partners ADD COLUMN company_name_kana TEXT;
ALTER TABLE partners ADD COLUMN corporate_number TEXT;
ALTER TABLE partners ADD COLUMN representative_name TEXT;
ALTER TABLE partners ADD COLUMN representative_name_kana TEXT;
ALTER TABLE partners ADD COLUMN hq_postal_code TEXT;
ALTER TABLE partners ADD COLUMN hq_prefecture TEXT;
ALTER TABLE partners ADD COLUMN hq_city TEXT;
ALTER TABLE partners ADD COLUMN hq_street TEXT;
ALTER TABLE partners ADD COLUMN hq_phone TEXT;
ALTER TABLE partners ADD COLUMN industry_code TEXT;
ALTER TABLE partners ADD COLUMN founded_on TEXT;
ALTER TABLE partners ADD COLUMN capital INTEGER;
ALTER TABLE partners ADD COLUMN contact_name TEXT;
ALTER TABLE partners ADD COLUMN contact_name_kana TEXT;
ALTER TABLE partners ADD COLUMN contact_email TEXT;
ALTER TABLE partners ADD COLUMN contact_phone TEXT;
ALTER TABLE partners ADD COLUMN corporate_number_verified_at TEXT;
ALTER TABLE partners ADD COLUMN corporate_number_api_result TEXT;
ALTER TABLE partners ADD COLUMN approved_at TEXT;
ALTER TABLE partners ADD COLUMN approved_by_staff_id TEXT;
ALTER TABLE partners ADD COLUMN approved_by_partner_id TEXT;
ALTER TABLE partners ADD COLUMN rejected_at TEXT;
ALTER TABLE partners ADD COLUMN rejection_reason TEXT;

CREATE INDEX IF NOT EXISTS idx_partners_corporate_number ON partners(corporate_number);

-- 3. 同意記録テーブル（Phase 4-3b / §23 反社チェック運用）
-- 利用規約 / 反社条項 / プライバシーポリシー / 代理店契約書 各種同意を保存
CREATE TABLE IF NOT EXISTS consent_records (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  partner_id TEXT,
  invitation_token TEXT,
  document_type TEXT NOT NULL,
  document_version TEXT NOT NULL,
  consented_at TEXT NOT NULL DEFAULT (datetime('now')),
  ip_address TEXT,
  user_agent TEXT,
  FOREIGN KEY (partner_id) REFERENCES partners(partner_id)
);
CREATE INDEX IF NOT EXISTS idx_cr_partner ON consent_records(partner_id);
CREATE INDEX IF NOT EXISTS idx_cr_doc ON consent_records(document_type, document_version);

-- 4. 確認用SELECT（実行時はコメント外す）
-- SELECT COUNT(*) FROM partner_invitations;
-- SELECT COUNT(*) FROM consent_records;
-- SELECT name FROM pragma_table_info('partners') ORDER BY cid;

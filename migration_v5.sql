-- =========================================================
--  Adavoo D1 Schema Migration v4 → v5 (Phase 4-2: 代理店パスワード変更・リセット)
--
--  追加点:
--   - partner_password_reset_tokens テーブル新設
--     * password_reset_tokens（master_staff用）と完全対称
--     * master_staff と partners の分離原則（sessions / partner_sessions 同様）を踏襲
--
--  実行方法:
--   Cloudflare Dashboard → D1 → adapt-db → Console で全文実行
-- =========================================================

CREATE TABLE IF NOT EXISTS partner_password_reset_tokens (
  token       TEXT PRIMARY KEY,
  partner_id  TEXT NOT NULL,
  email       TEXT NOT NULL,
  expires_at  TEXT NOT NULL,
  used_at     TEXT,
  created_at  TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (partner_id) REFERENCES partners(partner_id)
);
CREATE INDEX IF NOT EXISTS idx_ppw_reset_partner ON partner_password_reset_tokens(partner_id);
CREATE INDEX IF NOT EXISTS idx_ppw_reset_expires ON partner_password_reset_tokens(expires_at);
CREATE INDEX IF NOT EXISTS idx_ppw_reset_email   ON partner_password_reset_tokens(email);

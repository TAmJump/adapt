-- =========================================================
--  Adavoo D1 Schema Migration v3 → v4 (Phase 4-1: パスワードリセット)
--
--  追加点:
--   - password_reset_tokens テーブル新設
--     * email_verifications と類似構造だが用途分離
--     * リセットトークンの漏洩時影響範囲を局所化
--
--  実行方法:
--   Cloudflare Dashboard → D1 → adapt-db → Console で全文実行
-- =========================================================

CREATE TABLE IF NOT EXISTS password_reset_tokens (
  token       TEXT PRIMARY KEY,
  staff_id    TEXT NOT NULL,
  email       TEXT NOT NULL,
  expires_at  TEXT NOT NULL,
  used_at     TEXT,
  created_at  TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (staff_id) REFERENCES master_staff(staff_id)
);
CREATE INDEX IF NOT EXISTS idx_pw_reset_staff   ON password_reset_tokens(staff_id);
CREATE INDEX IF NOT EXISTS idx_pw_reset_expires ON password_reset_tokens(expires_at);
CREATE INDEX IF NOT EXISTS idx_pw_reset_email   ON password_reset_tokens(email);

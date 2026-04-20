-- =========================================================
--  Adapt D1 Schema Migration v1 → v2
--  追加点: email_verifications テーブル（登録時のメール確認フロー用）
--  既存のDBに対して Console で実行してください
-- =========================================================

CREATE TABLE IF NOT EXISTS email_verifications (
  token         TEXT PRIMARY KEY,
  email         TEXT NOT NULL,
  pending_data  TEXT NOT NULL,
  expires_at    TEXT NOT NULL,
  used_at       TEXT,
  created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_email_ver_email   ON email_verifications(email);
CREATE INDEX IF NOT EXISTS idx_email_ver_expires ON email_verifications(expires_at);

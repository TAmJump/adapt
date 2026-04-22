-- migration_v7.sql: Phase 4-3d 契約継続/終了の代理店申請機能
-- 実行方法: Cloudflare D1 Console（adapt-db）に貼り付けて実行

-- 1. partners テーブルに申請関連カラム追加
-- renewal_requested_at: 継続申請日時（NULL = 未申請 or 処理済み）
-- renewal_note: 申請時の備考
-- terminate_requested_at: 終了申請日時
-- terminate_note: 終了申請時の備考
-- last_renewal_approved_at: 最後の承認日（監査用）

ALTER TABLE partners ADD COLUMN renewal_requested_at TEXT;
ALTER TABLE partners ADD COLUMN renewal_note TEXT;
ALTER TABLE partners ADD COLUMN terminate_requested_at TEXT;
ALTER TABLE partners ADD COLUMN terminate_note TEXT;
ALTER TABLE partners ADD COLUMN last_renewal_approved_at TEXT;

-- 2. 検索用インデックス
CREATE INDEX IF NOT EXISTS idx_partners_renewal_req ON partners(renewal_requested_at);
CREATE INDEX IF NOT EXISTS idx_partners_terminate_req ON partners(terminate_requested_at);

-- 3. 確認SELECT（実行時はコメント外す）
-- SELECT partner_id, type, status, contract_end_at, renewal_requested_at, terminate_requested_at FROM partners;
